import json
from pathlib import Path
import stat

import react_recon.cli as cli
from react_recon.cli import _run_report_directory, build_parser
from react_recon.files import harden_artifacts
from react_recon.models import RunConfig


def test_analyze_accepts_provider_and_model_overrides():
    args = build_parser().parse_args(
        ["analyze", "run-fixture", "--provider", "anthropic", "--model", "claude-fixture", "--max-targets", "4"]
    )
    assert args.provider == "anthropic"
    assert args.model == "claude-fixture"
    assert args.max_targets == 4


def test_run_accepts_end_to_end_workflow_options():
    args = build_parser().parse_args(
        [
            "run",
            "--root-fqdn",
            "example.com",
            "--mode",
            "passive",
            "--provider",
            "anthropic",
            "--model",
            "claude-fixture",
            "--planning-mode",
            "deterministic",
            "--max-adaptive-actions",
            "0",
            "--max-targets",
            "6",
            "--reports-dir",
            "deliverables",
            "--authorized-network",
            "10.20.0.0/16",
            "--max-output-bytes",
            "4096",
            "--max-evidence-bytes",
            "8192",
            "--max-observations",
            "250",
            "--max-observation-bytes",
            "1024",
            "--max-normalized-bytes",
            "16384",
            "--max-dns-binding-age-seconds",
            "900",
        ]
    )
    assert args.provider == "anthropic"
    assert args.model == "claude-fixture"
    assert args.planning_mode == "deterministic"
    assert args.max_adaptive_actions == 0
    assert args.max_targets == 6
    assert args.reports_dir == "deliverables"
    assert args.authorized_network == ["10.20.0.0/16"]
    assert args.max_output_bytes == 4096
    assert args.max_evidence_bytes == 8192
    assert args.max_observations == 250
    assert args.max_observation_bytes == 1024
    assert args.max_normalized_bytes == 16384
    assert args.max_dns_binding_age_seconds == 900
    assert args.collection_only is False


def test_active_run_defaults_to_bounded_hybrid_planning():
    args = build_parser().parse_args(
        [
            "run",
            "--root-fqdn",
            "example.com",
            "--mode",
            "active",
            "--authorized-network",
            "203.0.113.0/24",
        ]
    )
    assert args.planning_mode == "hybrid"
    assert args.max_adaptive_actions == 3


def test_run_report_directory_uses_domain_and_run_date():
    result = _run_report_directory("reports", "portal.example.com", "2026-08-31T17:30:00+00:00")
    assert result == Path("reports/portal.example.com-2026-08-31")


def test_active_run_allows_automatic_public_destination_selection():
    args = build_parser().parse_args(
        ["run", "--root-fqdn", "example.com", "--mode", "active"]
    )
    config = RunConfig(
        args.root_fqdn,
        mode=args.mode,
        authorized_networks=args.authorized_network,
    )
    config.validate()
    assert config.authorized_networks == []


def test_harden_artifacts_migrates_legacy_sensitive_paths(tmp_path, capsys):
    database = tmp_path / "state.db"
    database.write_bytes(b"")
    evidence_file = tmp_path / "evidence" / "run-legacy" / "evidence-old.jsonl"
    evidence_file.parent.mkdir(parents=True)
    evidence_file.write_text("{}\n", encoding="utf-8")
    report_file = tmp_path / "reports" / "example.com-2026-08-31" / "run-old.html"
    report_file.parent.mkdir(parents=True)
    report_file.write_text("legacy", encoding="utf-8")
    env_file = tmp_path / ".env"
    env_file.write_text("OPENAI_API_KEY=redacted\n", encoding="utf-8")
    for path in (database, evidence_file, report_file, env_file):
        path.chmod(0o644)
    for path in (evidence_file.parent, report_file.parent, report_file.parent.parent):
        path.chmod(0o755)

    result = cli.main(
        [
            "harden-artifacts",
            "--database",
            str(database),
            "--evidence-dir",
            str(tmp_path / "evidence"),
            "--reports-dir",
            str(tmp_path / "reports"),
            "--env-file",
            str(env_file),
        ]
    )

    assert result == 0
    assert json.loads(capsys.readouterr().out)["report_paths"] >= 2
    for path in (database, evidence_file, report_file, env_file):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    for path in (evidence_file.parent, report_file.parent, report_file.parent.parent):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700


def test_harden_artifacts_restricts_sqlite_sidecars(tmp_path):
    database = tmp_path / "state.db"
    paths = [
        database,
        Path(f"{database}-wal"),
        Path(f"{database}-shm"),
        Path(f"{database}-journal"),
    ]
    for path in paths:
        path.write_bytes(b"")
        path.chmod(0o644)

    counts = harden_artifacts(
        database,
        tmp_path / "evidence",
        tmp_path / "reports",
        tmp_path / ".env",
    )

    assert counts["database"] == 4
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in paths)


def test_normal_hardening_does_not_walk_a_broad_report_parent(tmp_path, monkeypatch):
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir(mode=0o755)
    (unrelated / "run-unrelated.html").write_text("not ours", encoding="utf-8")
    unrelated.chmod(0o755)
    monkeypatch.chdir(tmp_path)

    counts = harden_artifacts(
        tmp_path / "missing.db",
        tmp_path / "evidence",
        Path("."),
        tmp_path / ".env",
    )

    assert counts["report_paths"] == 0
    assert stat.S_IMODE(unrelated.stat().st_mode) == 0o755


def test_run_collects_analyzes_and_writes_both_reports(monkeypatch, tmp_path, capsys):
    database = tmp_path / "state.db"
    evidence = tmp_path / "evidence"
    reports = tmp_path / "reports"
    calls = {"analysis": [], "reports": []}

    class FixtureAgent:
        def __init__(self, store, config):
            self.store = store
            self.config = config

        def run(self):
            run_id = self.store.create_run(self.config)
            self.store.finish_run(run_id, "completed")
            return run_id

    def fixture_analyze(store, run_id, provider=None, model=None, max_targets=10):
        calls["analysis"].append((run_id, provider, model, max_targets))
        return "analysis-fixture"

    def fixture_report(store, run_id, output, fmt):
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(fmt, encoding="utf-8")
        calls["reports"].append((run_id, path, fmt))
        return path

    monkeypatch.setattr(cli, "ReconAgent", FixtureAgent)
    monkeypatch.setattr(cli, "analyze_run", fixture_analyze)
    monkeypatch.setattr(cli, "write_report", fixture_report)

    result = cli.main(
        [
            "run",
            "--root-fqdn",
            "example.com",
            "--mode",
            "passive",
            "--database",
            str(database),
            "--evidence-dir",
            str(evidence),
            "--reports-dir",
            str(reports),
            "--provider",
            "openai",
            "--model",
            "model-fixture",
            "--max-targets",
            "7",
        ]
    )

    assert result == 0
    output = json.loads(capsys.readouterr().out)
    assert calls["analysis"] == [(output["run_id"], "openai", "model-fixture", 7)]
    assert {item[2] for item in calls["reports"]} == {"html", "json"}
    assert Path(output["report_directory"]).name.startswith("example.com-")
    assert Path(output["html_report"]).read_text(encoding="utf-8") == "html"
    assert Path(output["json_report"]).read_text(encoding="utf-8") == "json"


def test_run_still_writes_both_reports_when_analysis_fails(monkeypatch, tmp_path, capsys):
    database = tmp_path / "state.db"
    evidence = tmp_path / "evidence"
    reports = tmp_path / "reports"

    class FixtureAgent:
        def __init__(self, store, config):
            self.store = store
            self.config = config

        def run(self):
            run_id = self.store.create_run(self.config)
            self.store.finish_run(run_id, "completed")
            return run_id

    def failed_analysis(*args, **kwargs):
        raise RuntimeError("fixture provider unavailable")

    def fixture_report(store, run_id, output, fmt):
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(fmt, encoding="utf-8")
        return path

    monkeypatch.setattr(cli, "ReconAgent", FixtureAgent)
    monkeypatch.setattr(cli, "analyze_run", failed_analysis)
    monkeypatch.setattr(cli, "write_report", fixture_report)

    result = cli.main(
        [
            "run",
            "--root-fqdn",
            "example.com",
            "--database",
            str(database),
            "--evidence-dir",
            str(evidence),
            "--reports-dir",
            str(reports),
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert result == 2
    assert output["analysis_id"] is None
    assert output["analysis_error"] == "fixture provider unavailable"
    assert Path(output["html_report"]).is_file()
    assert Path(output["json_report"]).is_file()
