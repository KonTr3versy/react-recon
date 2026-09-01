import json
import stat
from pathlib import Path

from react_recon.models import RunConfig, ToolResult
from react_recon.reporting import write_report
from react_recon.storage import Store


def test_json_and_html_reports_are_written(tmp_path: Path):
    config = RunConfig("example.com", database=str(tmp_path / "run.db"), evidence_dir=str(tmp_path / "evidence"))
    store = Store(config.database, config.evidence_dir)
    try:
        run_id = store.create_run(config)
        store.record_result(run_id, ToolResult("discover_subdomains", "success", "example.com", observations=[{"type": "hostname", "value": "app.example.com"}]))
        store.finish_run(run_id, "completed")
        json_path = write_report(store, run_id, str(tmp_path / "report.json"), "json")
        html_path = write_report(store, run_id, str(tmp_path / "report.html"), "html")
        assert "app.example.com" in json_path.read_text(encoding="utf-8")
        assert "Recon report" in html_path.read_text(encoding="utf-8")
        assert stat.S_IMODE(json_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(html_path.stat().st_mode) == 0o600
    finally:
        store.close()


def test_html_identifies_analysis_provider_and_model(tmp_path: Path):
    config = RunConfig("example.com", database=str(tmp_path / "run.db"), evidence_dir=str(tmp_path / "evidence"))
    store = Store(config.database, config.evidence_dir)
    try:
        run_id = store.create_run(config)
        analysis_id = store.create_analysis(run_id, "claude-fixture", "v1", "digest", {}, [], provider="anthropic")
        store.complete_analysis(analysis_id, {"run_assessment": "Fixture", "priority_targets": [], "active_follow_up_candidates": []})
        html = write_report(store, run_id, str(tmp_path / "report.html"), "html").read_text(encoding="utf-8")
        assert "Provider: anthropic" in html
        assert "Model: claude-fixture" in html
    finally:
        store.close()


def test_nested_html_report_links_to_evidence_relative_to_its_directory(tmp_path: Path):
    config = RunConfig("example.com", database=str(tmp_path / "run.db"), evidence_dir=str(tmp_path / "evidence"))
    store = Store(config.database, config.evidence_dir)
    try:
        run_id = store.create_run(config)
        store.record_result(run_id, ToolResult("discover_subdomains", "success", "example.com"))
        store.finish_run(run_id, "completed")
        html_path = write_report(store, run_id, str(tmp_path / "reports" / "example.com-2026-08-31" / "report.html"), "html")
        rendered = html_path.read_text(encoding="utf-8")
        assert "../../evidence/" in rendered
        assert stat.S_IMODE(html_path.parent.stat().st_mode) == 0o700
    finally:
        store.close()


def test_reports_include_prioritized_responding_web_inventory(tmp_path: Path):
    config = RunConfig("example.com", database=str(tmp_path / "run.db"), evidence_dir=str(tmp_path / "evidence"))
    store = Store(config.database, config.evidence_dir)
    try:
        run_id = store.create_run(config)
        store.record_result(
            run_id,
            ToolResult(
                "probe_http",
                "success",
                "example.com",
                observations=[
                    {"type": "http_service", "value": "https://denied.example.com", "metadata": {"host": "denied.example.com", "status_code": 403, "title": "Restricted"}},
                    {"type": "http_service", "value": "https://live.example.com", "metadata": {"host": "live.example.com", "status_code": 200, "title": "Portal", "tech": ["nginx"]}},
                    {"type": "http_service", "value": "https://missing.example.com", "metadata": {"host": "missing.example.com", "status_code": 404}},
                ],
            ),
        )
        store.finish_run(run_id, "completed")
        json_report = json.loads(write_report(store, run_id, str(tmp_path / "report.json"), "json").read_text(encoding="utf-8"))
        html_report = write_report(store, run_id, str(tmp_path / "report.html"), "html").read_text(encoding="utf-8")
        assert [item["status_code"] for item in json_report["responsive_web_targets"]] == [200, 403, 404]
        assert json_report["coverage"]["responsive_web_endpoint_count"] == 3
        assert "Confirmed responding web endpoints" in html_report
        assert "Restricted" in html_report
    finally:
        store.close()
