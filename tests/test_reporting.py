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
    finally:
        store.close()


def test_html_identifies_analysis_provider_and_model(tmp_path: Path):
    config = RunConfig("example.com", database=str(tmp_path / "run.db"), evidence_dir=str(tmp_path / "evidence"))
    store = Store(config.database, config.evidence_dir)
    try:
        run_id = store.create_run(config)
        analysis_id = store.create_analysis(run_id, "claude-fixture", "v1", "digest", {}, [], provider="anthropic")
        store.complete_analysis(analysis_id, {"run_assessment": "Fixture", "priority_targets": []})
        html = write_report(store, run_id, str(tmp_path / "report.html"), "html").read_text(encoding="utf-8")
        assert "Provider: anthropic" in html
        assert "Model: claude-fixture" in html
    finally:
        store.close()
