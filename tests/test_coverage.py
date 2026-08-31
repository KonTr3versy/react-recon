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
                {"type": "dns_a", "host": host, "value": "192.0.2.10"}
                for host in arguments.get("hosts", [])
            ],
            "probe_http": [
                {"type": "http_service", "value": f"https://{host}", "metadata": {"host": host, "status_code": 200}}
                for host in arguments.get("hosts", [])
            ],
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
        assert executor.calls[3][1]["hosts"] == ["app.example.com", "ct.example.com"]
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
