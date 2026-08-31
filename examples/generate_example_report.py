"""Generate sanitized example reports without network or model access."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from react_recon.models import RunConfig, ToolResult
from react_recon.profiles import build_target_profiles
from react_recon.reporting import write_report
from react_recon.storage import Store


ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
DATABASE = EXAMPLES / "sample.db"
EVIDENCE = Path("examples/sample-evidence")


def main() -> None:
    # The generator owns only these two synthetic paths, making regeneration
    # predictable without touching an operator's normal evidence directory.
    DATABASE.unlink(missing_ok=True)
    shutil.rmtree(ROOT / EVIDENCE, ignore_errors=True)

    store = Store(str(DATABASE), str(EVIDENCE))
    try:
        run_id = store.create_run(RunConfig("example.com", evidence_dir=str(EVIDENCE)))
        store.record_result(
            run_id,
            ToolResult(
                "crtsh_search",
                "success",
                "example.com",
                stdout='[{"id": 1001, "name_value": "portal.example.com"}]',
                observations=[{"type": "ct_hostname", "value": "portal.example.com", "certificate_id": 1001}],
            ),
        )
        store.record_result(
            run_id,
            ToolResult(
                "discover_subdomains",
                "success",
                "example.com",
                stdout='{"host":"portal.example.com","source":"fixture"}\n',
                observations=[{"type": "hostname", "value": "portal.example.com", "source": "fixture"}],
            ),
        )
        store.record_result(
            run_id,
            ToolResult(
                "retrieve_passive_urls",
                "success",
                "example.com",
                stdout='{"url":"https://portal.example.com/login"}\n',
                observations=[{"type": "url_candidate", "value": "https://portal.example.com/login"}],
            ),
        )

        dns_task = store.add_task(run_id, "resolve_dns", {"hosts": ["portal.example.com"]})
        store.record_result(
            run_id,
            ToolResult(
                "resolve_dns",
                "success",
                "portal.example.com",
                stdout='{"host":"portal.example.com","a":["192.0.2.10"]}\n',
                observations=[{"type": "dns_a", "host": "portal.example.com", "value": "192.0.2.10"}],
            ),
        )
        store.complete_task(dns_task)

        http_task = store.add_task(run_id, "probe_http", {"hosts": ["portal.example.com"]})
        store.record_result(
            run_id,
            ToolResult(
                "probe_http",
                "success",
                "portal.example.com",
                stdout='{"url":"https://portal.example.com","status_code":302,"location":"/login"}\n',
                observations=[
                    {
                        "type": "http_service",
                        "value": "https://portal.example.com",
                        "metadata": {
                            "host": "portal.example.com",
                            "url": "https://portal.example.com",
                            "status_code": 302,
                            "location": "/login",
                            "port": "443",
                            "tech": ["Example Gateway"],
                        },
                    }
                ],
            ),
        )
        store.complete_task(http_task)
        store.finish_run(run_id, "completed")

        profiles = build_target_profiles(store.snapshot(run_id))
        profile = next(item for item in profiles if item["host"] == "portal.example.com")
        fact = profile["fact_refs"][0]
        input_payload = {"fixture": True, "target_profiles": profiles}
        analysis_id = store.create_analysis(
            run_id,
            "fixture-model",
            "example-v1",
            hashlib.sha256(repr(input_payload).encode()).hexdigest(),
            input_payload,
            profiles,
        )
        store.complete_analysis(
            analysis_id,
            {
                "run_assessment": "One verified external portal warrants focused manual characterization.",
                "priority_targets": [
                    {
                        "rank": 1,
                        "priority": "P1",
                        "host": "portal.example.com",
                        "related_hosts": [],
                        "interesting_exposure": "Verified HTTPS portal with a login redirect.",
                        "why_interesting": "It is a confirmed external authentication boundary.",
                        "pentester_objective": "Characterize authentication behavior and exposed metadata.",
                        "confidence": "high",
                        "observed_facts": [fact],
                        "next_steps": ["Review the authentication flow and certificate relationships manually."],
                        "caveats": ["Synthetic example; no target interaction occurred."],
                    }
                ],
                "cross_asset_patterns": [],
                "information_opportunities": [],
                "collection_gaps": ["No active port or service enumeration was performed."],
            },
        )
        write_report(store, run_id, str(EXAMPLES / "example-report.json"), "json")
        write_report(store, run_id, str(EXAMPLES / "example-report.html"), "html")
    finally:
        store.close()
        DATABASE.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
