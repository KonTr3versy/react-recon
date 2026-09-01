from pathlib import Path
import json
import os
import stat
import sys
from types import SimpleNamespace

import pytest

from react_recon.agent import ReconAgent
from react_recon.models import Decision, RunConfig, ToolResult
from react_recon.runtime import BoundedProcessResult, run_bounded_process
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
            address = arguments["approved_addresses"]["vpn.example.com"][0]
            return ToolResult(tool, "success", "vpn.example.com", observations=[{"type": "open_port", "host": "vpn.example.com", "ip": address, "port": 443, "protocol": "tcp"}])
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
        if self.calls == 2:
            return Decision("fingerprint_services", {})
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


def test_active_mode_requires_a_destination_network_without_host_enumeration():
    with pytest.raises(ValueError, match="authorized_network"):
        RunConfig("example.com", mode="active").validate()
    RunConfig(
        "example.com", mode="active", authorized_networks=["93.184.216.34/32"]
    ).validate()


def test_httpx_command_collects_response_classification_metadata():
    from react_recon.executor import Executor

    command = Executor(RunConfig("example.com"))._command("probe_http", {"input_file": "hosts.txt", "allow_file": "approved.txt"})
    assert all(flag in command for flag in ("-allow", "-ip", "-no-fallback", "-sc", "-cl", "-ct", "-location", "-td", "-hash", "-rstr", "-rsts"))
    assert command[command.index("-allow") + 1] == "approved.txt"
    assert command[command.index("-hash") + 1] == "sha256"


def test_dnsx_command_is_record_explicit_rate_limited_and_wildcard_aware():
    from react_recon.executor import Executor

    command = Executor(RunConfig("example.com", dns_rate_limit=37, concurrency=3))._command("resolve_dns", {"input_file": "hosts.txt"})
    assert all(flag in command for flag in ("-a", "-aaaa", "-cname", "-cdn", "-asn", "-auto-wildcard", "-omit-raw"))
    assert command[command.index("-rl") + 1] == "37"
    assert command[command.index("-t") + 1] == "3"


def test_alterx_is_active_only_scope_filtered_and_bounded(tmp_path: Path, monkeypatch):
    from react_recon.executor import Executor

    monkeypatch.setattr("react_recon.executor.shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        Executor,
        "_run_command",
        lambda *args, **kwargs: BoundedProcessResult(0, "one.example.com\ntwo.example.com\nthree.example.com\noutside.example.net\n", ""),
    )
    passive = Executor(RunConfig("example.com")).execute("generate_permutations", {"hosts": ["example.com"]})
    assert passive.status == "skipped"

    active = Executor(RunConfig("example.com", mode="active", authorized_networks=["93.184.216.34/32"], max_permutations=2)).execute("generate_permutations", {"hosts": ["example.com"]})
    assert active.status == "success"
    assert [item["value"] for item in active.observations] == ["one.example.com", "two.example.com"]
    assert "outside.example.net" not in {item["value"] for item in active.observations}


def test_out_of_scope_active_host_is_skipped(tmp_path: Path):
    from react_recon.executor import Executor
    config = RunConfig("example.com", mode="active", authorized_hosts=["app.example.com"], authorized_networks=["93.184.216.34/32"], database=str(tmp_path / "run.db"), evidence_dir=str(tmp_path / "evidence"))
    result = Executor(config).execute("probe_http", {"hosts": ["other.example.net"], "input_file": "hosts.txt"})
    assert result.status == "skipped"
    assert "out-of-scope" in result.limitations[0]


def test_docker_fallback_rewrites_temporary_input_path(tmp_path: Path):
    from react_recon.executor import Executor

    executor = Executor(RunConfig("example.com"))
    bundle = executor._materialize_input("resolve_dns", ["example.com"], {})
    assert bundle is not None
    try:
        command = executor._docker_command("example/tool@sha256:" + "1" * 64, ["dnsx", "-l", bundle.input_file], bundle)
        assert "/workspace/targets.txt" in command
        assert bundle.input_file not in command
        assert f"{bundle.root}:/workspace:ro" in command
        assert stat.S_IMODE(bundle.root.stat().st_mode) == 0o700
        assert stat.S_IMODE(Path(bundle.input_file).stat().st_mode) == 0o600
        assert sorted(path.name for path in bundle.root.iterdir()) == ["targets.txt"]
        assert all(flag in command for flag in ("--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges"))
    finally:
        bundle.cleanup()


def test_official_projectdiscovery_docker_image_does_not_repeat_entrypoint(tmp_path: Path):
    from react_recon.executor import Executor

    executor = Executor(RunConfig("example.com"))
    bundle = executor._materialize_input("resolve_dns", ["example.com"], {})
    assert bundle is not None
    image = Executor.DOCKER_IMAGES["resolve_dns"]
    try:
        command = executor._docker_command(image, ["dnsx", "-l", bundle.input_file, "-j"], bundle)
        image_index = command.index(image)
        assert command[image_index + 1 :] == ["-l", "/workspace/targets.txt", "-j"]
    finally:
        bundle.cleanup()


def test_nmap_docker_image_does_not_repeat_entrypoint():
    from react_recon.executor import Executor

    executor = Executor(RunConfig("example.com", mode="active", authorized_networks=["93.184.216.34/32"]))
    image = Executor.DOCKER_IMAGES["fingerprint_services"]
    command = executor._docker_command(image, ["nmap", "-n", "-Pn", "93.184.216.34"], None)
    image_index = command.index(image)
    assert command[image_index + 1 :] == ["-n", "-Pn", "93.184.216.34"]


def test_naabu_is_limited_to_port_discovery_before_nmap_fingerprinting():
    from react_recon.executor import Executor

    command = Executor(RunConfig("example.com", mode="active", authorized_networks=["93.184.216.34/32"]))._command("discover_ports", {"input_file": "hosts.txt"})
    assert "-verify" in command
    assert "-sD" not in command
    assert "-sV" not in command


def test_missing_gau_does_not_invent_projectdiscovery_image(tmp_path: Path, monkeypatch):
    from react_recon.executor import Executor

    monkeypatch.setattr("react_recon.executor.shutil.which", lambda name: "/usr/bin/docker" if name == "docker" else None)
    config = RunConfig("example.com", database=str(tmp_path / "run.db"), evidence_dir=str(tmp_path / "evidence"))
    result = Executor(config).execute("retrieve_passive_urls", {"root_fqdn": "example.com"})
    assert result.status == "failed"
    assert "install gau on the host" in result.stderr
    assert "projectdiscovery/gau" not in result.command


def test_successful_port_discovery_feeds_state_machine_fingerprinting(tmp_path: Path):
    config = RunConfig(
        "example.com",
        mode="active",
        authorized_hosts=["vpn.example.com"],
        authorized_networks=["93.184.216.34/32"],
        database=str(tmp_path / "run.db"),
        evidence_dir=str(tmp_path / "evidence"),
    )
    store = Store(config.database, config.evidence_dir)
    executor = ActiveExecutor()
    try:
        run_id = store.create_run(config)
        store.record_result(
            run_id,
            ToolResult(
                "resolve_dns",
                "success",
                "vpn.example.com",
                observations=[{"type": "dns_a", "host": "vpn.example.com", "value": "93.184.216.34"}],
            ),
        )
        ReconAgent(store, config, PortThenFinishPlanner(), executor).run(run_id)
        assert [tool for tool, _ in executor.calls] == ["discover_ports", "fingerprint_services"]
        assert executor.calls[1][1] == {"targets": [{"host": "vpn.example.com", "ip": "93.184.216.34", "ports": [443]}]}
        snapshot = store.snapshot(run_id)
        fingerprint_task = next(task for task in snapshot["tasks"] if task["tool"] == "fingerprint_services")
        assert '"vpn.example.com"' in fingerprint_task["arguments_json"]
    finally:
        store.close()


def test_destination_tools_fail_closed_without_approved_address_mapping(monkeypatch):
    from react_recon.executor import Executor

    monkeypatch.setattr("react_recon.executor.shutil.which", lambda name: f"/usr/bin/{name}")
    result = Executor(RunConfig("example.com")).execute("probe_http", {"hosts": ["app.example.com"]})
    assert result.status == "skipped"
    assert "approved hostname/IP mapping" in result.limitations[0]


def test_port_discovery_rejects_global_ip_outside_explicit_network():
    from react_recon.executor import Executor

    result = Executor(
        RunConfig(
            "example.com",
            mode="active",
            authorized_networks=["93.184.216.34/32"],
        )
    ).execute(
        "discover_ports",
        {
            "hosts": ["app.example.com"],
            "approved_addresses": {"app.example.com": ["8.8.8.8"]},
        },
    )
    assert result.status == "skipped"
    assert "approved hostname/IP mapping" in result.limitations[0]


def test_http_observations_must_match_approved_ip(monkeypatch):
    from react_recon.executor import Executor

    executor = Executor(RunConfig("example.com"))
    monkeypatch.setattr("react_recon.executor.shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        executor,
        "_run_command",
        lambda *args, **kwargs: BoundedProcessResult(
            0,
            json.dumps({"url": "https://app.example.com", "input": "app.example.com", "host_ip": "8.8.8.8"}) + "\n",
            "",
        ),
    )
    result = executor.execute(
        "probe_http",
        {"hosts": ["app.example.com"], "approved_addresses": {"app.example.com": ["93.184.216.34"]}},
    )
    assert result.status == "failed"
    assert result.observations == []


def test_httpx_uses_separate_processes_for_disjoint_host_bindings(monkeypatch):
    from react_recon.executor import Executor

    executor = Executor(RunConfig("example.com"))
    monkeypatch.setattr("react_recon.executor.shutil.which", lambda name: f"/usr/bin/{name}")
    observed_bindings = []

    def run_bound(command, timeout):
        input_path = Path(command[command.index("-l") + 1])
        allow_path = Path(command[command.index("-allow") + 1])
        host = input_path.read_text(encoding="utf-8").strip()
        address = allow_path.read_text(encoding="utf-8").strip()
        observed_bindings.append((host, address))
        return BoundedProcessResult(
            0,
            json.dumps(
                {
                    "url": f"https://{host}",
                    "input": host,
                    "host_ip": address,
                }
            )
            + "\n",
            "",
        )

    monkeypatch.setattr(executor, "_run_command", run_bound)
    result = executor.execute(
        "probe_http",
        {
            "hosts": ["one.example.com", "two.example.com"],
            "approved_addresses": {
                "one.example.com": ["93.184.216.34"],
                "two.example.com": ["1.1.1.1"],
            },
        },
    )

    assert result.status == "success"
    assert observed_bindings == [
        ("one.example.com", "93.184.216.34"),
        ("two.example.com", "1.1.1.1"),
    ]
    assert len(result.observations) == 2


def test_bounded_process_removes_model_keys_and_stops_large_output(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sentinel-openai")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sentinel-anthropic")
    check_env = run_bounded_process(
        [sys.executable, "-c", "import os; print(bool(os.getenv('OPENAI_API_KEY') or os.getenv('ANTHROPIC_API_KEY')))"] ,
        timeout=5,
        max_output_bytes=1024,
    )
    assert check_env.stdout.strip() == "False"

    oversized = run_bounded_process(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 200000); sys.stdout.flush()"],
        timeout=5,
        max_output_bytes=1024,
    )
    assert oversized.output_limited is True
    assert len(oversized.stdout.encode()) <= 1024


def test_output_limited_docker_client_triggers_cid_cleanup(tmp_path, monkeypatch):
    fake_docker = tmp_path / "docker"
    marker = tmp_path / "removed-container.txt"
    fake_docker.write_text(
        f"""#!{sys.executable}
import os
from pathlib import Path
import subprocess
import sys

if len(sys.argv) > 1 and sys.argv[1] == "rm":
    Path(os.environ["FAKE_DOCKER_MARKER"]).write_text(sys.argv[-1], encoding="utf-8")
    raise SystemExit(0)
cid_index = sys.argv.index("--cidfile") + 1
subprocess.Popen(
    [
        sys.executable,
        "-c",
        "import os,time; from pathlib import Path; time.sleep(0.2); Path(os.environ['FAKE_DOCKER_CID']).write_text('fixture-container-id', encoding='utf-8')",
    ],
    env=dict(os.environ, FAKE_DOCKER_CID=sys.argv[cid_index]),
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    start_new_session=True,
)
os.write(1, b"x" * 200000)
""",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)
    monkeypatch.setenv("FAKE_DOCKER_MARKER", str(marker))

    result = run_bounded_process(
        [str(fake_docker), "run", "--rm", "fixture@sha256:" + "a" * 64],
        timeout=5,
        max_output_bytes=1024,
    )

    assert result.output_limited is True
    assert marker.read_text(encoding="utf-8") == "fixture-container-id"


def test_custom_docker_fallback_requires_a_complete_digest():
    with pytest.raises(ValueError, match="sha256 digest"):
        RunConfig("example.com", docker_image="example/tool:edge").validate()
    with pytest.raises(ValueError, match="sha256 digest"):
        RunConfig("example.com", docker_image="example/tool@sha256:abcd").validate()

    config = RunConfig("example.com", docker_image="example/tool@sha256:" + "a" * 64)
    config.validate()
    assert config.docker_image.endswith("a" * 64)


def test_nmap_aggregate_output_limit_fails_closed(monkeypatch):
    from react_recon.executor import Executor

    config = RunConfig(
        "example.com",
        mode="active",
        authorized_networks=["93.184.216.34/32", "1.1.1.1/32"],
        max_output_bytes=260,
    )
    executor = Executor(config)
    monkeypatch.setattr("react_recon.executor.shutil.which", lambda name: "/usr/bin/nmap" if name == "nmap" else None)
    xml = "<?xml version='1.0'?><nmaprun><host><address addr='93.184.216.34'/><ports><port protocol='tcp' portid='443'><state state='open'/><service name='https'/></port></ports></host></nmaprun>"
    monkeypatch.setattr(executor, "_run_command", lambda *args, **kwargs: BoundedProcessResult(0, xml, ""))

    result = executor.execute(
        "fingerprint_services",
        {
            "targets": [
                {"host": "one.example.com", "ip": "93.184.216.34", "ports": [443]},
                {"host": "two.example.com", "ip": "1.1.1.1", "ports": [443]},
            ]
        },
    )

    assert result.status == "failed"
    assert result.observations == []
    assert any("aggregate Nmap output exceeded" in item for item in result.limitations)


def test_nmap_adds_ipv6_mode_for_bound_ipv6_target(monkeypatch):
    from react_recon.executor import Executor

    executor = Executor(
        RunConfig(
            "example.com",
            mode="active",
            authorized_networks=["2606:4700:4700::1111/128"],
        )
    )
    monkeypatch.setattr("react_recon.executor.shutil.which", lambda name: "/usr/bin/nmap" if name == "nmap" else None)
    commands = []

    def run_nmap(command, timeout):
        commands.append(command)
        return BoundedProcessResult(0, "<?xml version='1.0'?><nmaprun></nmaprun>", "")

    monkeypatch.setattr(executor, "_run_command", run_nmap)
    result = executor.execute(
        "fingerprint_services",
        {
            "targets": [
                {
                    "host": "v6.example.com",
                    "ip": "2606:4700:4700::1111",
                    "ports": [443],
                }
            ]
        },
    )

    assert result.status == "success"
    assert "-6" in commands[0]
