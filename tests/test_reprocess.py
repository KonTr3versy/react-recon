import hashlib
import json
from pathlib import Path

import pytest

from react_recon.models import RunConfig, ToolResult
from react_recon.reprocess import _parse_nmap_documents, reprocess_run
from react_recon.storage import Store


def test_reprocess_rebuilds_normalized_state_without_network_and_is_idempotent(tmp_path: Path):
    store = Store(str(tmp_path / "run.db"), str(tmp_path / "evidence"))
    try:
        run_id = store.create_run(RunConfig("example.com"))
        raw = '{"url":"https://app.example.com/admin"}\n'
        store.record_result(
            run_id,
            ToolResult(
                "retrieve_passive_urls",
                "success",
                "example.com",
                stdout=raw,
                observations=[{"type": "url_candidate", "value": raw.strip()}],
            ),
        )
        analysis_id = store.create_analysis(run_id, "fixture", "v1", hashlib.sha256(b"fixture").hexdigest(), {}, [])
        store.complete_analysis(analysis_id, {"priority_targets": []})

        first = reprocess_run(store, run_id)
        second = reprocess_run(store, run_id)
        values = [json.loads(row["value_json"])["value"] for row in store.snapshot(run_id)["observations"]]

        assert values == ["https://app.example.com/admin"]
        assert first["network_requests"] == 0
        assert first["analyses_marked_stale"] == 1
        assert second["analyses_marked_stale"] == 0
        assert second["observations_written"] == 1
        assert store.latest_analysis(run_id) is None
    finally:
        store.close()


def test_reprocess_parses_concatenated_nmap_xml_documents():
    document = """<?xml version='1.0'?><nmaprun><host><address addr='192.0.2.4'/><hostnames><hostname name='vpn.example.com'/></hostnames><ports><port protocol='tcp' portid='443'><state state='open'/><service name='https'/></port></ports></host></nmaprun>"""
    observations = _parse_nmap_documents(document + "\n" + document)
    assert len(observations) == 2
    assert observations[0]["service"] == "https"


def test_reprocess_preserves_observations_from_completed_partial_targets(tmp_path: Path):
    store = Store(str(tmp_path / "run.db"), str(tmp_path / "evidence"))
    try:
        run_id = store.create_run(RunConfig("example.com"))
        completed_output = json.dumps(
            {
                "url": "https://app.example.com",
                "input": "app.example.com",
                "host_ip": "93.184.216.34",
                "status_code": 200,
            }
        ) + "\n"
        rejected_output = json.dumps(
            {
                "url": "https://vpn.example.com",
                "input": "vpn.example.com",
                "host_ip": "8.8.8.8",
                "status_code": 200,
            }
        ) + "\n"
        raw = completed_output + "\n" + rejected_output
        store.record_result(
            run_id,
            ToolResult(
                "probe_http",
                "failed",
                "app.example.com,vpn.example.com",
                stdout=raw,
                observations=[
                    {
                        "type": "http_service",
                        "value": "https://app.example.com",
                        "metadata": json.loads(completed_output),
                    }
                ],
                target_outcomes=[
                    {
                        "host": "app.example.com",
                        "addresses": ["93.184.216.34"],
                        "status": "completed",
                        "stdout_start": 0,
                        "stdout_end": len(completed_output),
                    },
                    {
                        "host": "vpn.example.com",
                        "addresses": ["93.184.216.35"],
                        "status": "failed",
                        "stdout_start": len(completed_output) + 1,
                        "stdout_end": len(raw),
                    },
                ],
            ),
        )

        summary = reprocess_run(store, run_id)
        observations = store.snapshot(run_id)["observations"]
        assert summary["observations_written"] == 1
        assert json.loads(observations[0]["value_json"])["value"] == "https://app.example.com"
    finally:
        store.close()


def test_reprocess_restores_controller_hostname_for_nmap_ip_output(tmp_path: Path):
    store = Store(str(tmp_path / "run.db"), str(tmp_path / "evidence"))
    try:
        config = RunConfig(
            "example.com",
            mode="active",
            authorized_networks=["93.184.216.34/32"],
        )
        run_id = store.create_run(config)
        raw = "<?xml version='1.0'?><nmaprun><host><address addr='93.184.216.34'/><ports><port protocol='tcp' portid='443'><state state='open'/><service name='https'/></port></ports></host></nmaprun>"
        store.record_result(
            run_id,
            ToolResult(
                "fingerprint_services",
                "success",
                "vpn.example.com[93.184.216.34]",
                stdout=raw,
                observations=[
                    {
                        "type": "service_fingerprint",
                        "host": "vpn.example.com",
                        "ip": "93.184.216.34",
                        "port": 443,
                        "protocol": "tcp",
                        "addresses": ["93.184.216.34"],
                        "service": "https",
                    }
                ],
                target_outcomes=[
                    {
                        "host": "vpn.example.com",
                        "ip": "93.184.216.34",
                        "ports": [443],
                        "status": "completed",
                        "stdout_start": 0,
                        "stdout_end": len(raw),
                    }
                ],
            ),
        )

        reprocess_run(store, run_id)
        value = json.loads(store.snapshot(run_id)["observations"][0]["value_json"])
        assert value["host"] == "vpn.example.com"
        assert value["ip"] == "93.184.216.34"
    finally:
        store.close()


def test_reprocess_does_not_refresh_dns_with_missing_execution_timestamp(tmp_path: Path):
    store = Store(str(tmp_path / "run.db"), str(tmp_path / "evidence"))
    try:
        config = RunConfig("example.com")
        run_id = store.create_run(config)
        raw = json.dumps(
            {"host": "app.example.com", "a": ["93.184.216.34"]}
        ) + "\n"
        evidence_id = store.record_result(
            run_id,
            ToolResult(
                "resolve_dns",
                "success",
                "app.example.com",
                stdout=raw,
                observations=[
                    {
                        "type": "dns_a",
                        "host": "app.example.com",
                        "value": "93.184.216.34",
                    }
                ],
            ),
        )
        store.conn.execute(
            "DELETE FROM dns_snapshots WHERE evidence_id=?", (evidence_id,)
        )
        store.conn.execute(
            "UPDATE executions SET finished_at=NULL WHERE id=?", (evidence_id,)
        )
        store.conn.commit()

        reprocess_run(store, run_id)
        assert store.approved_targets(run_id, config) == []
        created_at = store.conn.execute(
            "SELECT created_at FROM observations WHERE evidence_id=?", (evidence_id,)
        ).fetchone()["created_at"]
        assert created_at is None
    finally:
        store.close()


def test_reprocess_preserves_expired_dns_capture_time(tmp_path: Path):
    store = Store(str(tmp_path / "run.db"), str(tmp_path / "evidence"))
    try:
        config = RunConfig("example.com", max_dns_binding_age_seconds=60)
        run_id = store.create_run(config)
        raw = json.dumps(
            {"host": "app.example.com", "a": ["93.184.216.34"]}
        ) + "\n"
        store.record_result(
            run_id,
            ToolResult(
                "resolve_dns",
                "success",
                "app.example.com",
                stdout=raw,
                finished_at="2000-01-01T00:00:00+00:00",
                observations=[
                    {
                        "type": "dns_a",
                        "host": "app.example.com",
                        "value": "93.184.216.34",
                    }
                ],
            ),
        )

        reprocess_run(store, run_id)
        assert store.approved_targets(run_id, config) == []
        assert store.conn.execute(
            "SELECT created_at FROM observations WHERE run_id=?", (run_id,)
        ).fetchone()["created_at"] == "2000-01-01T00:00:00+00:00"
    finally:
        store.close()


def test_reprocess_rejects_legacy_evidence_above_output_ceiling(tmp_path: Path):
    config = RunConfig(
        "example.com",
        database=str(tmp_path / "run.db"),
        evidence_dir=str(tmp_path / "evidence"),
        max_output_bytes=32,
    )
    store = Store(config.database, config.evidence_dir)
    try:
        run_id = store.create_run(config)
        evidence_id = store.record_result(run_id, ToolResult("discover_subdomains", "success", "example.com"))
        path = config.evidence_dir + f"/{run_id}/{evidence_id}.jsonl"
        Path(path).write_text(json.dumps({"run_id": run_id, "tool": "discover_subdomains", "stdout": "x" * 1024}) + "\n")

        with pytest.raises(ValueError, match="output ceiling"):
            reprocess_run(store, run_id)
    finally:
        store.close()
