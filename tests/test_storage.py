import sqlite3

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
        run_id = store.create_run(RunConfig("example.com", mode="active", authorized_hosts=["vpn.example.com"]))
        store.record_result(
            run_id,
            ToolResult(
                "discover_ports",
                "success",
                "vpn.example.com",
                observations=[
                    {"type": "open_port", "host": "vpn.example.com", "port": 443},
                    {"type": "open_port", "host": "other.example.com", "port": 22},
                ],
            ),
        )
        assert store.open_port_targets(run_id, ["vpn.example.com"]) == [{"host": "vpn.example.com", "ports": [443]}]
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
