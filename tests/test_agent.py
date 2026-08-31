from pathlib import Path

import pytest

from react_recon.agent import ReconAgent
from react_recon.models import Decision, RunConfig, ToolResult
from react_recon.storage import Store


class FixturePlanner:
    def __init__(self):
        self.decisions = [Decision("discover_subdomains", {"root_fqdn": "example.com"}), Decision("finish_recon", {"summary": "fixture complete"})]

    def choose(self, snapshot, config):
        return self.decisions.pop(0)


class FixtureExecutor:
    def execute(self, tool, arguments):
        return ToolResult(tool, "success", "example.com", stdout="app.example.com\n", observations=[{"type": "hostname", "value": "app.example.com"}])


class ActiveExecutor:
    def __init__(self):
        self.calls = []

    def execute(self, tool, arguments):
        self.calls.append((tool, arguments))
        if tool == "discover_ports":
            return ToolResult(tool, "success", "vpn.example.com", observations=[{"type": "open_port", "host": "vpn.example.com", "port": 443, "protocol": "tcp"}])
        if tool == "fingerprint_services":
            return ToolResult(tool, "success", "vpn.example.com:443", observations=[{"type": "service_fingerprint", "host": "vpn.example.com", "port": 443, "service": "https"}])
        return ToolResult(tool, "success", "example.com")


class PortThenFinishPlanner:
    def __init__(self):
        self.calls = 0

    def choose(self, snapshot, config):
        self.calls += 1
        if self.calls == 1:
            return Decision("discover_ports", {"hosts": ["vpn.example.com"]})
        return Decision("finish_recon", {"summary": "done"})


def test_fixture_run_persists_execution_and_observation(tmp_path: Path):
    config = RunConfig("example.com", database=str(tmp_path / "run.db"), evidence_dir=str(tmp_path / "evidence"))
    store = Store(config.database, config.evidence_dir)
    try:
        run_id = ReconAgent(store, config, FixturePlanner(), FixtureExecutor()).run()
        snapshot = store.snapshot(run_id)
        assert snapshot["run"]["status"] == "completed"
        assert len(snapshot["executions"]) == 1
        assert len(snapshot["observations"]) == 1
        assert Path(snapshot["executions"][0]["raw_output_path"]).exists()
    finally:
        store.close()


def test_active_port_discovery_is_not_allowed_in_passive_mode(tmp_path: Path):
    from react_recon.executor import Executor
    config = RunConfig("example.com", database=str(tmp_path / "run.db"), evidence_dir=str(tmp_path / "evidence"))
    result = Executor(config).execute("discover_ports", {"hosts": ["example.com"], "input_file": "hosts.txt"})
    assert result.status == "skipped"


def test_active_mode_requires_authorized_hosts():
    with pytest.raises(ValueError, match="authorized_hosts"):
        RunConfig("example.com", mode="active").validate()


def test_out_of_scope_active_host_is_skipped(tmp_path: Path):
    from react_recon.executor import Executor
    config = RunConfig("example.com", mode="active", authorized_hosts=["app.example.com"], database=str(tmp_path / "run.db"), evidence_dir=str(tmp_path / "evidence"))
    result = Executor(config).execute("probe_http", {"hosts": ["other.example.net"], "input_file": "hosts.txt"})
    assert result.status == "skipped"
    assert "out-of-scope" in result.limitations[0]


def test_docker_fallback_rewrites_temporary_input_path(tmp_path: Path):
    from react_recon.executor import Executor

    input_path = tmp_path / "hosts.txt"
    command = Executor(RunConfig("example.com"))._docker_command("example/tool:latest", ["dnsx", "-l", str(input_path)], str(input_path))
    assert "/workspace/hosts.txt" in command
    assert str(input_path) not in command[command.index("example/tool:latest") + 1 :]


def test_missing_gau_does_not_invent_projectdiscovery_image(tmp_path: Path, monkeypatch):
    from react_recon.executor import Executor

    monkeypatch.setattr("react_recon.executor.shutil.which", lambda name: "/usr/bin/docker" if name == "docker" else None)
    config = RunConfig("example.com", database=str(tmp_path / "run.db"), evidence_dir=str(tmp_path / "evidence"))
    result = Executor(config).execute("retrieve_passive_urls", {"root_fqdn": "example.com"})
    assert result.status == "failed"
    assert "install gau on the host" in result.stderr
    assert "projectdiscovery/gau" not in result.command


def test_successful_port_discovery_automatically_fingerprints_services(tmp_path: Path):
    config = RunConfig(
        "example.com",
        mode="active",
        authorized_hosts=["vpn.example.com"],
        database=str(tmp_path / "run.db"),
        evidence_dir=str(tmp_path / "evidence"),
    )
    store = Store(config.database, config.evidence_dir)
    executor = ActiveExecutor()
    try:
        run_id = ReconAgent(store, config, PortThenFinishPlanner(), executor).run()
        assert [tool for tool, _ in executor.calls] == ["discover_ports", "fingerprint_services"]
        assert executor.calls[1][1] == {"targets": [{"host": "vpn.example.com", "ports": [443]}]}
        snapshot = store.snapshot(run_id)
        fingerprint_task = next(task for task in snapshot["tasks"] if task["tool"] == "fingerprint_services")
        assert '"trigger": "discover_ports"' in fingerprint_task["arguments_json"]
    finally:
        store.close()
