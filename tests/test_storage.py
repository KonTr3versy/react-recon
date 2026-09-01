import json
import sqlite3
import stat
import tempfile
from pathlib import Path

import pytest

from react_recon.models import RunConfig, ToolResult
from react_recon.storage import Store


def test_compact_snapshot_really_bounds_observations(tmp_path):
    store = Store(str(tmp_path / "run.db"), str(tmp_path / "evidence"))
    try:
        run_id = store.create_run(RunConfig("example.com"))
        store.record_result(
            run_id,
            ToolResult(
                "retrieve_passive_urls",
                "success",
                "example.com",
                observations=[
                    {"type": "url_candidate", "value": f"https://example.com/{index}"}
                    for index in range(25)
                ],
            ),
        )
        snapshot = store.snapshot(run_id, compact=True)
        assert len(snapshot["observations"]) == 20
        assert snapshot["observation_counts"]["url_candidate"] == 25
    finally:
        store.close()


def test_open_port_targets_are_derived_from_evidence_and_authorization(tmp_path):
    store = Store(str(tmp_path / "run.db"), str(tmp_path / "evidence"))
    try:
        run_id = store.create_run(RunConfig("example.com", mode="active", authorized_hosts=["vpn.example.com"], authorized_networks=["93.184.216.34/32"]))
        store.record_result(
            run_id,
            ToolResult(
                "discover_ports",
                "success",
                "vpn.example.com",
                observations=[
                    {"type": "open_port", "host": "vpn.example.com", "ip": "93.184.216.34", "port": 443},
                    {"type": "open_port", "host": "other.example.com", "ip": "8.8.8.8", "port": 22},
                ],
            ),
        )
        eligible = [{"host": "vpn.example.com", "addresses": ["93.184.216.34"]}]
        assert store.open_port_targets(run_id, eligible) == [
            {"host": "vpn.example.com", "ip": "93.184.216.34", "ports": [443]}
        ]
    finally:
        store.close()


def test_active_scan_hosts_require_resolution_and_exclude_shared_infrastructure(tmp_path):
    store = Store(str(tmp_path / "run.db"), str(tmp_path / "evidence"))
    try:
        config = RunConfig(
            "example.com",
            mode="active",
            authorized_hosts=["explicit.example.com"],
            authorized_networks=[
                "93.184.216.34/32",
                "8.8.8.8/32",
                "1.1.1.1/32",
                "9.9.9.9/32",
            ],
        )
        run_id = store.create_run(config)
        store.record_result(
            run_id,
            ToolResult(
                "resolve_dns",
                "success",
                "example.com",
                observations=[
                    {"type": "dns_a", "host": "direct.example.com", "value": "93.184.216.34"},
                    {"type": "dns_a", "host": "cdn.example.com", "value": "8.8.8.8"},
                    {"type": "dns_cdn", "host": "cdn.example.com", "value": "cloudflare"},
                    {"type": "dns_cname", "host": "external.example.com", "value": "vendor.example.net"},
                    {"type": "dns_a", "host": "external.example.com", "value": "1.1.1.1"},
                    {"type": "dns_a", "host": "explicit.example.com", "value": "9.9.9.9"},
                    {"type": "dns_cdn", "host": "explicit.example.com", "value": "cloudflare"},
                ],
            ),
        )

        assert store.active_scan_hosts(run_id, config) == ["direct.example.com", "explicit.example.com"]
        assert "unresolved.example.com" not in store.active_scan_hosts(
            run_id,
            RunConfig("example.com", mode="active", authorized_hosts=["unresolved.example.com"], authorized_networks=["93.184.216.34/32"]),
        )
    finally:
        store.close()


def test_destination_policy_rejects_non_global_answers_unless_network_is_explicit(tmp_path):
    store = Store(str(tmp_path / "run.db"), str(tmp_path / "evidence"))
    try:
        default_config = RunConfig("example.com")
        default_run = store.create_run(default_config)
        store.record_result(
            default_run,
            ToolResult(
                "resolve_dns",
                "success",
                "internal.example.com",
                observations=[{"type": "dns_a", "host": "internal.example.com", "value": "10.10.10.10"}],
            ),
        )
        assert store.approved_targets(default_run, default_config) == []

        mixed_run = store.create_run(default_config)
        store.record_result(
            mixed_run,
            ToolResult(
                "resolve_dns",
                "success",
                "mixed.example.com",
                observations=[
                    {"type": "dns_a", "host": "mixed.example.com", "value": "93.184.216.34"},
                    {"type": "dns_a", "host": "mixed.example.com", "value": "127.0.0.1"},
                ],
            ),
        )
        assert store.approved_targets(mixed_run, default_config) == []

        explicit_config = RunConfig("example.com", authorized_networks=["10.10.10.0/24"])
        explicit_run = store.create_run(explicit_config)
        store.record_result(
            explicit_run,
            ToolResult(
                "resolve_dns",
                "success",
                "internal.example.com",
                observations=[{"type": "dns_a", "host": "internal.example.com", "value": "10.10.10.10"}],
            ),
        )
        assert store.approved_targets(explicit_run, explicit_config) == [
            {"host": "internal.example.com", "addresses": ["10.10.10.10"]}
        ]
    finally:
        store.close()


def test_stale_dns_binding_is_not_approved_for_downstream_execution(tmp_path):
    store = Store(str(tmp_path / "run.db"), str(tmp_path / "evidence"))
    try:
        config = RunConfig("example.com", max_dns_binding_age_seconds=60)
        run_id = store.create_run(config)
        store.record_result(
            run_id,
            ToolResult(
                "resolve_dns",
                "success",
                "app.example.com",
                observations=[
                    {"type": "dns_a", "host": "app.example.com", "value": "93.184.216.34"}
                ],
            ),
        )
        store.conn.execute(
            "UPDATE observations SET created_at='2000-01-01T00:00:00+00:00' WHERE run_id=?",
            (run_id,),
        )
        store.conn.execute(
            "UPDATE dns_snapshots SET captured_at='2000-01-01T00:00:00+00:00' WHERE run_id=?",
            (run_id,),
        )
        store.conn.commit()
        assert store.approved_targets(run_id, config) == []

        store.record_result(
            run_id,
            ToolResult(
                "resolve_dns",
                "success",
                "app.example.com",
                observations=[
                    {"type": "dns_a", "host": "app.example.com", "value": "93.184.216.34"}
                ],
            ),
        )
        assert store.approved_targets(run_id, config) == [
            {"host": "app.example.com", "addresses": ["93.184.216.34"]}
        ]
    finally:
        store.close()


def test_fresh_successful_empty_dns_snapshot_supersedes_positive_answer(tmp_path):
    store = Store(str(tmp_path / "run.db"), str(tmp_path / "evidence"))
    try:
        config = RunConfig("example.com")
        run_id = store.create_run(config)
        store.record_result(
            run_id,
            ToolResult(
                "resolve_dns",
                "success",
                "app.example.com",
                observations=[
                    {
                        "type": "dns_a",
                        "host": "app.example.com",
                        "value": "93.184.216.34",
                    }
                ],
            ),
        )
        assert store.approved_targets(run_id, config)

        store.record_result(
            run_id,
            ToolResult(
                "resolve_dns",
                "success",
                "app.example.com",
                target_outcomes=[
                    {"host": "app.example.com", "status": "completed"}
                ],
            ),
        )

        assert store.approved_targets(run_id, config) == []
    finally:
        store.close()


def test_latest_fresh_dns_snapshot_supersedes_stale_address_and_cdn_rows(tmp_path):
    store = Store(str(tmp_path / "run.db"), str(tmp_path / "evidence"))
    try:
        config = RunConfig(
            "example.com",
            mode="active",
            authorized_networks=["93.184.216.34/32"],
            max_dns_binding_age_seconds=60,
        )
        run_id = store.create_run(config)
        store.record_result(
            run_id,
            ToolResult(
                "resolve_dns",
                "success",
                "app.example.com",
                finished_at="2000-01-01T00:00:00+00:00",
                observations=[
                    {
                        "type": "dns_a",
                        "host": "app.example.com",
                        "value": "8.8.8.8",
                    },
                    {
                        "type": "dns_cname",
                        "host": "app.example.com",
                        "value": "shared.vendor.example.net",
                    },
                    {
                        "type": "dns_cdn",
                        "host": "app.example.com",
                        "value": "fixture-cdn",
                    },
                ],
            ),
        )
        store.record_result(
            run_id,
            ToolResult(
                "resolve_dns",
                "success",
                "app.example.com",
                observations=[
                    {
                        "type": "dns_a",
                        "host": "app.example.com",
                        "value": "93.184.216.34",
                    }
                ],
            ),
        )

        assert store.approved_targets(run_id, config, active=True) == [
            {"host": "app.example.com", "addresses": ["93.184.216.34"]}
        ]
    finally:
        store.close()


def test_candidate_hosts_prioritize_root_and_exact_authorized_seeds(tmp_path):
    store = Store(str(tmp_path / "run.db"), str(tmp_path / "evidence"))
    try:
        config = RunConfig(
            "example.com",
            authorized_hosts=["vpn.vendor.example.net"],
            max_assets=3,
        )
        run_id = store.create_run(config)
        store.record_result(
            run_id,
            ToolResult(
                "discover_subdomains",
                "success",
                "example.com",
                observations=[
                    {"type": "hostname", "value": "a.example.com"},
                    {
                        "type": "hostname",
                        "value": "child.vpn.vendor.example.net",
                    },
                ],
            ),
        )

        assert store.candidate_hosts(run_id, limit=1) == ["example.com"]
        assert store.candidate_hosts(run_id, limit=3) == [
            "example.com",
            "vpn.vendor.example.net",
            "a.example.com",
        ]
        assert "child.vpn.vendor.example.net" not in store.candidate_hosts(run_id)
    finally:
        store.close()


def test_asset_budget_must_fit_all_operator_supplied_seeds():
    with pytest.raises(ValueError, match="root_fqdn and every explicit"):
        RunConfig(
            "example.com",
            authorized_hosts=["vpn.vendor.example.net"],
            max_assets=1,
        ).validate()


def test_legacy_run_expands_asset_budget_only_to_fit_existing_seeds(tmp_path):
    store = Store(str(tmp_path / "run.db"), str(tmp_path / "evidence"))
    try:
        config = RunConfig(
            "example.com",
            authorized_hosts=["vpn.vendor.example.net"],
            max_assets=2,
        )
        run_id = store.create_run(config)
        payload = json.loads(store.get_run(run_id)["config_json"])
        payload["max_assets"] = 1
        store.conn.execute(
            "UPDATE runs SET config_json=? WHERE id=?",
            (json.dumps(payload), run_id),
        )
        store.conn.commit()

        resumed = store.run_config(run_id)
        assert resumed.max_assets == 2
        assert store.candidate_hosts(run_id, resumed.max_assets) == [
            "example.com",
            "vpn.vendor.example.net",
        ]
    finally:
        store.close()


def test_active_port_targets_require_explicit_destination_network(tmp_path):
    store = Store(str(tmp_path / "run.db"), str(tmp_path / "evidence"))
    try:
        config = RunConfig("example.com", mode="active", authorized_networks=["93.184.216.34/32"])
        run_id = store.create_run(config)
        store.record_result(
            run_id,
            ToolResult(
                "resolve_dns",
                "success",
                "delegated.example.com",
                observations=[
                    {"type": "dns_a", "host": "delegated.example.com", "value": "8.8.8.8"}
                ],
            ),
        )
        assert store.approved_targets(run_id, config, active=True) == []
        assert store.approved_targets(run_id, config, active=False) == [
            {"host": "delegated.example.com", "addresses": ["8.8.8.8"]}
        ]
    finally:
        store.close()


def test_database_and_evidence_are_owner_only(tmp_path):
    database = tmp_path / "run.db"
    evidence = tmp_path / "evidence"
    store = Store(str(database), str(evidence))
    try:
        run_id = store.create_run(RunConfig("example.com"))
        evidence_id = store.record_result(run_id, ToolResult("discover_subdomains", "success", "example.com"))
        raw_path = evidence / run_id / f"{evidence_id}.jsonl"
        assert stat.S_IMODE(database.stat().st_mode) == 0o600
        assert stat.S_IMODE(evidence.stat().st_mode) == 0o700
        assert stat.S_IMODE((evidence / run_id).stat().st_mode) == 0o700
        assert stat.S_IMODE(raw_path.stat().st_mode) == 0o600
    finally:
        store.close()


def test_store_tightens_recognized_legacy_evidence_modes(tmp_path):
    evidence_root = tmp_path / "evidence"
    run_directory = evidence_root / "run-legacy"
    run_directory.mkdir(parents=True, mode=0o755)
    raw_path = run_directory / "evidence-legacy.jsonl"
    raw_path.write_text("{}\n", encoding="utf-8")
    run_directory.chmod(0o755)
    raw_path.chmod(0o644)

    store = Store(str(tmp_path / "run.db"), str(evidence_root))
    try:
        assert stat.S_IMODE(run_directory.stat().st_mode) == 0o700
        assert stat.S_IMODE(raw_path.stat().st_mode) == 0o600
    finally:
        store.close()


def test_store_rejects_symlink_database(tmp_path):
    target = tmp_path / "target.db"
    target.write_text("do not overwrite", encoding="utf-8")
    link = tmp_path / "run.db"
    link.symlink_to(target)

    try:
        Store(str(link), str(tmp_path / "evidence"))
    except ValueError as exc:
        assert "symlink" in str(exc)
    else:
        raise AssertionError("Store accepted a symlink database")


def test_store_rejects_database_beneath_symlinked_parent(tmp_path):
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(ValueError, match="symlinked sensitive path"):
        Store(str(linked_parent / "run.db"), str(tmp_path / "evidence"))

    assert not (real_parent / "run.db").exists()


def test_store_rejects_broad_shared_evidence_root(tmp_path):
    with pytest.raises(ValueError, match="dedicated child path"):
        Store(str(tmp_path / "run.db"), tempfile.gettempdir())


def test_observation_and_evidence_limits_fail_closed(tmp_path):
    config = RunConfig(
        "example.com",
        database=str(tmp_path / "run.db"),
        evidence_dir=str(tmp_path / "evidence"),
        max_observations=1,
        max_output_bytes=32,
        max_evidence_bytes=2048,
    )
    store = Store(config.database, config.evidence_dir)
    try:
        run_id = store.create_run(config)
        store.record_result(
            run_id,
            ToolResult(
                "discover_subdomains",
                "success",
                "example.com",
                stdout="x" * 128,
                observations=[
                    {"type": "hostname", "value": "one.example.com"},
                    {"type": "hostname", "value": "two.example.com"},
                ],
            ),
        )
        snapshot = store.snapshot(run_id)
        assert snapshot["executions"][0]["status"] == "failed"
        assert snapshot["observations"] == []
        evidence_text = Path(snapshot["executions"][0]["raw_output_path"]).read_text(encoding="utf-8")
        assert "observation limit exceeded" in evidence_text
        assert "raw evidence limit exceeded" in evidence_text
        assert "x" * 128 not in evidence_text
        assert len(evidence_text.encode("utf-8")) <= config.max_evidence_bytes
    finally:
        store.close()


def test_exhausted_evidence_budget_never_writes_past_the_ceiling(tmp_path):
    config = RunConfig(
        "example.com",
        database=str(tmp_path / "run.db"),
        evidence_dir=str(tmp_path / "evidence"),
        max_output_bytes=1,
        max_evidence_bytes=1,
    )
    store = Store(config.database, config.evidence_dir)
    try:
        run_id = store.create_run(config)
        store.record_result(
            run_id,
            ToolResult("discover_subdomains", "success", "example.com", stdout="too large"),
        )
        execution = store.snapshot(run_id)["executions"][0]
        assert execution["status"] == "failed"
        assert execution["raw_output_path"] == ""
        assert "raw evidence limit exceeded" in execution["stderr"]
        evidence_bytes = sum(
            path.stat().st_size for path in (Path(config.evidence_dir) / run_id).glob("*.jsonl")
        )
        assert evidence_bytes <= config.max_evidence_bytes
    finally:
        store.close()


def test_oversized_normalized_observation_is_not_persisted(tmp_path):
    config = RunConfig(
        "example.com",
        database=str(tmp_path / "run.db"),
        evidence_dir=str(tmp_path / "evidence"),
        max_observation_bytes=128,
    )
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
                    {
                        "type": "http_service",
                        "value": "https://example.com",
                        "metadata": {"body": "x" * 512},
                    }
                ],
            ),
        )
        snapshot = store.snapshot(run_id)
        assert snapshot["executions"][0]["status"] == "failed"
        assert snapshot["observations"] == []
        evidence = Path(snapshot["executions"][0]["raw_output_path"]).read_text(encoding="utf-8")
        assert "observation size limit exceeded" in evidence
    finally:
        store.close()


def test_existing_analysis_table_is_migrated_with_openai_provider(tmp_path):
    database = tmp_path / "legacy.db"
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TABLE analysis_runs (id TEXT PRIMARY KEY, run_id TEXT, model TEXT, prompt_version TEXT, status TEXT, input_digest TEXT, input_json TEXT, output_json TEXT, error TEXT, created_at TEXT, updated_at TEXT)"
    )
    connection.execute(
        "INSERT INTO analysis_runs VALUES ('analysis-old', 'run-old', 'gpt-old', 'v1', 'failed', 'digest', '{}', NULL, 'old', 'now', 'now')"
    )
    connection.commit()
    connection.close()

    store = Store(str(database), str(tmp_path / "evidence"))
    try:
        row = store.conn.execute("SELECT provider FROM analysis_runs WHERE id='analysis-old'").fetchone()
        assert row["provider"] == "openai"
    finally:
        store.close()


def test_legacy_run_and_task_schema_resume_deterministically(tmp_path):
    database = tmp_path / "legacy-run.db"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE runs (id TEXT PRIMARY KEY, root_fqdn TEXT, mode TEXT, config_json TEXT, status TEXT, created_at TEXT, updated_at TEXT);
        CREATE TABLE tasks (id TEXT PRIMARY KEY, run_id TEXT, tool TEXT, arguments_json TEXT, status TEXT, attempts INTEGER DEFAULT 0, created_at TEXT, updated_at TEXT);
        """
    )
    legacy_config = RunConfig("example.com").__dict__
    for field in (
        "ai_provider",
        "ai_model",
        "planning_mode",
        "max_adaptive_actions",
    ):
        legacy_config.pop(field)
    connection.execute(
        "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            "run-legacy",
            "example.com",
            "passive",
            json.dumps(legacy_config),
            "stopped",
            "now",
            "now",
        ),
    )
    connection.execute(
        "INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "task-legacy",
            "run-legacy",
            "crtsh_search",
            "{}",
            "completed",
            1,
            "now",
            "now",
        ),
    )
    connection.commit()
    connection.close()

    store = Store(str(database), str(tmp_path / "evidence"))
    try:
        config = store.run_config("run-legacy")
        assert config.planning_mode == "deterministic"
        assert config.max_adaptive_actions == 0
        task = store.task_records("run-legacy")[0]
        assert task["phase"] == "coverage"
        assert task["decision_json"] == "{}"
        assert task["progress_json"] is None
    finally:
        store.close()
