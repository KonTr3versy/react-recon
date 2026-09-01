from pathlib import Path

from react_recon.agent import ReconAgent
from react_recon.coverage import CoveragePlanner, build_coverage
from react_recon.models import RunConfig, ToolResult
from react_recon.storage import Store


class BaselineExecutor:
    def __init__(self) -> None:
        self.calls = []

    def execute(self, tool, arguments):
        self.calls.append((tool, arguments))
        observations = {
            "crtsh_search": [{"type": "ct_hostname", "value": "ct.example.com"}],
            "discover_subdomains": [{"type": "hostname", "value": "app.example.com"}],
            "retrieve_passive_urls": [{"type": "url_candidate", "value": "https://app.example.com/login"}],
            "resolve_dns": [
                {"type": "dns_a", "host": host, "value": "93.184.216.34"}
                for host in arguments.get("hosts", [])
            ],
            "probe_http": [
                {"type": "http_service", "value": f"https://{host}", "metadata": {"host": host, "status_code": 200}}
                for host in arguments.get("hosts", [])
            ],
        }.get(tool, [])
        return ToolResult(tool, "success", "example.com", observations=observations)


class ActiveWorkflowExecutor(BaselineExecutor):
    def execute(self, tool, arguments):
        self.calls.append((tool, arguments))
        if tool == "generate_permutations":
            return ToolResult(tool, "success", "example.com", observations=[{"type": "permutation_candidate", "value": "app-dev.example.com", "generator": "alterx"}])
        if tool == "resolve_permutations":
            return ToolResult(tool, "success", "app-dev.example.com", observations=[{"type": "dns_a", "host": "app-dev.example.com", "value": "1.1.1.1"}])
        if tool == "probe_permutation_http":
            return ToolResult(tool, "success", "app-dev.example.com", observations=[{"type": "http_service", "value": "https://app-dev.example.com", "metadata": {"host": "app-dev.example.com", "status_code": 403}}])
        if tool == "discover_ports":
            address = arguments["approved_addresses"]["app-dev.example.com"][0]
            return ToolResult(tool, "success", "example.com", observations=[{"type": "open_port", "host": "app-dev.example.com", "ip": address, "port": 8443, "protocol": "tcp"}])
        if tool == "fingerprint_services":
            return ToolResult(tool, "success", "app-dev.example.com:8443", observations=[{"type": "service_fingerprint", "host": "app-dev.example.com", "port": 8443, "service": "https-alt"}])
        observations = {
            "crtsh_search": [{"type": "ct_hostname", "value": "ct.example.com"}],
            "discover_subdomains": [{"type": "hostname", "value": "app.example.com"}],
            "retrieve_passive_urls": [{"type": "url_candidate", "value": "https://app.example.com/login"}],
            "resolve_dns": [{"type": "dns_a", "host": host, "value": "93.184.216.34"} for host in arguments.get("hosts", [])],
            "probe_http": [{"type": "http_service", "value": f"https://{host}", "metadata": {"host": host, "status_code": 200}} for host in arguments.get("hosts", [])],
        }.get(tool, [])
        return ToolResult(tool, "success", "example.com", observations=observations)


def test_default_planner_completes_passive_baseline_in_order(tmp_path: Path):
    config = RunConfig("example.com", database=str(tmp_path / "run.db"), evidence_dir=str(tmp_path / "evidence"))
    store = Store(config.database, config.evidence_dir)
    executor = BaselineExecutor()
    try:
        run_id = ReconAgent(store, config, executor=executor).run()
        assert [tool for tool, _ in executor.calls] == [
            "crtsh_search",
            "discover_subdomains",
            "retrieve_passive_urls",
            "resolve_dns",
            "probe_http",
        ]
        assert executor.calls[3][1]["hosts"] == ["app.example.com", "ct.example.com", "example.com"]
        assert executor.calls[4][1]["approved_addresses"] == {
            "app.example.com": ["93.184.216.34"],
            "ct.example.com": ["93.184.216.34"],
            "example.com": ["93.184.216.34"],
        }
        assert build_coverage(store, run_id)["analysis_ready"] is True
    finally:
        store.close()


def test_coverage_planner_retries_failure_then_advances():
    planner = CoveragePlanner()
    config = RunConfig("example.com", max_retries=1)
    snapshot = {
        "executions": [{"tool": "crtsh_search", "status": "failed"}],
        "observation_counts": {},
    }
    assert planner.choose(snapshot, config).tool == "crtsh_search"
    snapshot["executions"].insert(0, {"tool": "crtsh_search", "status": "failed"})
    assert planner.choose(snapshot, config).tool == "discover_subdomains"


def test_active_workflow_runs_one_bounded_expansion_then_ports_and_fingerprints(tmp_path: Path):
    config = RunConfig(
        "example.com",
        mode="active",
        planning_mode="deterministic",
        authorized_networks=["93.184.216.34/32", "1.1.1.1/32"],
        database=str(tmp_path / "run.db"),
        evidence_dir=str(tmp_path / "evidence"),
    )
    store = Store(config.database, config.evidence_dir)
    executor = ActiveWorkflowExecutor()
    try:
        run_id = ReconAgent(store, config, executor=executor).run()
        assert [tool for tool, _ in executor.calls] == [
            "crtsh_search",
            "discover_subdomains",
            "retrieve_passive_urls",
            "resolve_dns",
            "probe_http",
            "generate_permutations",
            "resolve_permutations",
            "probe_permutation_http",
            "discover_ports",
            "fingerprint_services",
        ]
        by_tool = {tool: arguments for tool, arguments in executor.calls}
        assert by_tool["resolve_permutations"]["hosts"] == ["app-dev.example.com"]
        assert by_tool["probe_permutation_http"]["hosts"] == ["app-dev.example.com"]
        assert by_tool["fingerprint_services"]["targets"] == [
            {"host": "app-dev.example.com", "ip": "1.1.1.1", "ports": [8443]}
        ]
        coverage = build_coverage(store, run_id)
        assert coverage["analysis_ready"] is True
        assert coverage["metrics"]["permutation_candidates"] == 1
        assert coverage["metrics"]["permutation_resolved_hosts"] == 1
    finally:
        store.close()


def test_incomplete_baseline_is_not_analysis_ready(tmp_path: Path):
    store = Store(str(tmp_path / "run.db"), str(tmp_path / "evidence"))
    try:
        run_id = store.create_run(RunConfig("example.com"))
        store.record_result(run_id, ToolResult("discover_subdomains", "success", "example.com"))
        coverage = build_coverage(store, run_id)
        assert coverage["analysis_ready"] is False
        assert "crtsh_search: pending" in coverage["gaps"]
    finally:
        store.close()


def test_resume_continues_from_durable_execution_state(tmp_path: Path):
    config = RunConfig("example.com", database=str(tmp_path / "run.db"), evidence_dir=str(tmp_path / "evidence"))
    store = Store(config.database, config.evidence_dir)
    executor = BaselineExecutor()
    try:
        run_id = store.create_run(config)
        store.record_result(run_id, executor.execute("crtsh_search", {"root_fqdn": "example.com"}))
        store.record_result(run_id, executor.execute("discover_subdomains", {"root_fqdn": "example.com"}))
        executor.calls.clear()

        ReconAgent(store, config, executor=executor).run(run_id)

        assert [tool for tool, _ in executor.calls] == ["retrieve_passive_urls", "resolve_dns", "probe_http"]
        assert store.snapshot(run_id)["run"]["status"] == "completed"
    finally:
        store.close()


def test_resume_cannot_reset_the_run_wide_tool_call_budget(tmp_path: Path):
    config = RunConfig(
        "example.com",
        max_tool_calls=1,
        database=str(tmp_path / "run.db"),
        evidence_dir=str(tmp_path / "evidence"),
    )
    store = Store(config.database, config.evidence_dir)
    executor = BaselineExecutor()
    try:
        run_id = store.create_run(config)
        store.record_result(run_id, executor.execute("crtsh_search", {"root_fqdn": "example.com"}))
        executor.calls.clear()

        ReconAgent(store, config, executor=executor).run(run_id)

        assert executor.calls == []
        assert store.execution_count(run_id) == 1
        assert store.snapshot(run_id)["run"]["status"] == "stopped"
    finally:
        store.close()


def test_repeated_tool_failure_finishes_with_coverage_gaps(tmp_path: Path):
    class FailingCrtExecutor(BaselineExecutor):
        def execute(self, tool, arguments):
            if tool == "crtsh_search":
                self.calls.append((tool, arguments))
                return ToolResult(tool, "failed", "example.com", stderr="fixture timeout")
            return super().execute(tool, arguments)

    config = RunConfig(
        "example.com",
        max_retries=1,
        database=str(tmp_path / "run.db"),
        evidence_dir=str(tmp_path / "evidence"),
    )
    store = Store(config.database, config.evidence_dir)
    executor = FailingCrtExecutor()
    try:
        run_id = ReconAgent(store, config, executor=executor).run()
        assert [tool for tool, _ in executor.calls].count("crtsh_search") == 2
        assert store.snapshot(run_id)["run"]["status"] == "completed_with_gaps"
        coverage = build_coverage(store, run_id)
        assert coverage["analysis_ready"] is True
        assert "crtsh_search: failed" in coverage["gaps"]
    finally:
        store.close()
