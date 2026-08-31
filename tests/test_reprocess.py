import hashlib
import json
from pathlib import Path

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
