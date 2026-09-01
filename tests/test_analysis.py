import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from react_recon.analysis import ANALYSIS_SCHEMA, AnthropicReconAnalyst, OpenAIReconAnalyst, analyze_run, build_analyst
from react_recon.models import RunConfig, ToolResult
from react_recon.profiles import build_target_profiles
from react_recon.reporting import write_report
from react_recon.storage import Store


class FixtureAnalyst:
    provider = "fixture"
    model = "fixture-model"

    def analyze(self, payload, max_targets):
        profile = next(item for item in payload["target_profiles"] if item["host"] == "vpn.example.com")
        fact = profile["fact_refs"][0]
        return {
            "run_assessment": "One verified remote-access boundary deserves focused manual review.",
            "priority_targets": [
                {
                    "rank": 1,
                    "priority": "P1",
                    "host": profile["host"],
                    "related_hosts": [],
                    "interesting_exposure": "External HTTPS remote-access interface",
                    "why_interesting": "It is a verified identity and remote-access boundary.",
                    "pentester_objective": "Characterize the exposed authentication surface and related gateways.",
                    "confidence": "high",
                    "observed_facts": [{"fact_id": fact["fact_id"]}],
                    "next_steps": ["Review redirects, authentication metadata, and related certificates."],
                    "caveats": ["No authenticated testing was performed."],
                }
            ],
            "active_follow_up_candidates": [
                {
                    "rank": 1,
                    "host": profile["host"],
                    "observed_url": "https://vpn.example.com",
                    "why_active": "The passive run observed a redirecting remote-access boundary.",
                    "active_objective": "Enumerate exposed TCP services and fingerprint verified open ports.",
                    "confidence": "high",
                    "fact_ids": [fact["fact_id"]],
                }
            ],
            "cross_asset_patterns": [],
            "information_opportunities": [],
            "collection_gaps": ["Service version was not identified."],
        }


class InvalidReferenceAnalyst(FixtureAnalyst):
    def analyze(self, payload, max_targets):
        output = super().analyze(payload, max_targets)
        output["priority_targets"][0]["observed_facts"][0]["fact_id"] = "fact-invented"
        return output


class FactTamperingAnalyst(FixtureAnalyst):
    def analyze(self, payload, max_targets):
        output = super().analyze(payload, max_targets)
        output["priority_targets"][0]["observed_facts"][0]["statement"] = "Invented vulnerable service claim"
        return output


class UnsupportedClaimAnalyst(FixtureAnalyst):
    def analyze(self, payload, max_targets):
        output = super().analyze(payload, max_targets)
        output["priority_targets"][0]["why_interesting"] = "This host is vulnerable and exploitable."
        return output


class RetryableReferenceAnalyst(FixtureAnalyst):
    def __init__(self):
        self.calls = 0

    def analyze(self, payload, max_targets):
        self.calls += 1
        output = super().analyze(payload, max_targets)
        if self.calls == 1:
            output["priority_targets"][0]["observed_facts"][0]["fact_id"] = "fact-typo"
        return output


class InvalidActiveFollowUpAnalyst(FixtureAnalyst):
    def analyze(self, payload, max_targets):
        output = super().analyze(payload, max_targets)
        output["active_follow_up_candidates"][0]["observed_url"] = "https://invented.example.com"
        return output


class ActiveModeFollowUpAnalyst(FixtureAnalyst):
    pass


def test_analysis_schema_uses_provider_compatible_nullable_fields():
    def assert_no_type_arrays(value):
        if isinstance(value, dict):
            assert not isinstance(value.get("type"), list)
            for child in value.values():
                assert_no_type_arrays(child)
        elif isinstance(value, list):
            for child in value:
                assert_no_type_arrays(child)

    assert_no_type_arrays(ANALYSIS_SCHEMA)


def test_analysis_schema_transforms_with_installed_anthropic_sdk():
    anthropic = pytest.importorskip("anthropic")
    transformed = anthropic.transform_schema(ANALYSIS_SCHEMA)
    assert transformed["properties"]["active_follow_up_candidates"]


def _store_with_recon(tmp_path: Path) -> tuple[Store, str]:
    store = Store(str(tmp_path / "run.db"), str(tmp_path / "evidence"))
    run_id = store.create_run(RunConfig("example.com"))
    store.record_result(run_id, ToolResult("crtsh_search", "success", "example.com", observations=[]))
    store.record_result(run_id, ToolResult("discover_subdomains", "success", "example.com", observations=[{"type": "hostname", "value": "vpn.example.com"}]))
    store.record_result(run_id, ToolResult("retrieve_passive_urls", "success", "example.com", observations=[]))
    dns_task = store.add_task(run_id, "resolve_dns", {"hosts": ["example.com", "vpn.example.com"]})
    store.record_result(run_id, ToolResult("resolve_dns", "success", "vpn.example.com", observations=[{"type": "dns_a", "host": "example.com", "value": "192.0.2.3"}, {"type": "dns_a", "host": "vpn.example.com", "value": "192.0.2.4"}]))
    store.complete_task(dns_task)
    http_task = store.add_task(run_id, "probe_http", {"hosts": ["example.com", "vpn.example.com"]})
    store.record_result(
        run_id,
        ToolResult(
            "probe_http",
            "success",
            "vpn.example.com",
            observations=[
                {
                    "type": "http_service",
                    "value": "https://example.com",
                    "metadata": {"host": "example.com", "url": "https://example.com", "status_code": 200, "port": "443"},
                },
                {
                    "type": "http_service",
                    "value": "https://vpn.example.com",
                    "metadata": {"host": "vpn.example.com", "url": "https://vpn.example.com", "status_code": 302, "location": "/global-protect/login.esp", "port": "443"},
                }
            ],
        ),
    )
    store.complete_task(http_task)
    return store, run_id


def test_profiles_prioritize_verified_remote_access(tmp_path: Path):
    store, run_id = _store_with_recon(tmp_path)
    try:
        profile = build_target_profiles(store.snapshot(run_id))[0]
        assert profile["host"] == "vpn.example.com"
        assert profile["verified"] is True
        assert profile["deterministic_priority"] == "P1"
        assert any(signal["code"] == "remote_access" for signal in profile["signals"])
    finally:
        store.close()


@pytest.mark.parametrize(
    ("status_code", "priority", "signal_code"),
    [
        (200, "successful", "http_success"),
        (302, "redirect", "http_redirect"),
        (403, "authorization_boundary", "http_authorization_boundary"),
        (404, "other_response", "http_response"),
        (503, "server_error", "http_server_error"),
    ],
)
def test_profiles_classify_responding_http_statuses(tmp_path: Path, status_code: int, priority: str, signal_code: str):
    store = Store(str(tmp_path / "run.db"), str(tmp_path / "evidence"))
    run_id = store.create_run(RunConfig("example.com"))
    store.record_result(
        run_id,
        ToolResult(
            "probe_http",
            "success",
            "app.example.com",
            observations=[
                {
                    "type": "http_service",
                    "value": "https://app.example.com",
                    "metadata": {"host": "app.example.com", "status-code": status_code},
                }
            ],
        ),
    )
    try:
        profile = build_target_profiles(store.snapshot(run_id))[0]
        assert profile["http_responsive"] is True
        assert profile["http_status_codes"] == [status_code]
        assert profile["http_response_priority"] == priority
        assert any(signal["code"] == signal_code for signal in profile["signals"])
    finally:
        store.close()


def test_responding_web_target_sorts_before_dns_only_target_at_same_priority(tmp_path: Path):
    store = Store(str(tmp_path / "run.db"), str(tmp_path / "evidence"))
    run_id = store.create_run(RunConfig("example.com"))
    store.record_result(
        run_id,
        ToolResult(
            "resolve_dns",
            "success",
            "example.com",
            observations=[
                {"type": "dns_a", "host": "vpn.example.com", "value": "192.0.2.10"},
                {"type": "dns_a", "host": "app.example.com", "value": "192.0.2.20"},
            ],
        ),
    )
    store.record_result(
        run_id,
        ToolResult(
            "probe_http",
            "success",
            "app.example.com",
            observations=[{"type": "http_service", "value": "https://app.example.com", "metadata": {"host": "app.example.com", "status_code": 200}}],
        ),
    )
    try:
        profiles = build_target_profiles(store.snapshot(run_id))
        assert [profile["host"] for profile in profiles] == ["app.example.com", "vpn.example.com"]
    finally:
        store.close()


def test_analysis_is_persisted_and_rendered_as_concise_brief(tmp_path: Path):
    store, run_id = _store_with_recon(tmp_path)
    try:
        analysis_id = analyze_run(store, run_id, analyst=FixtureAnalyst())
        analysis = store.latest_analysis(run_id)
        assert analysis["id"] == analysis_id
        assert analysis["provider"] == "fixture"
        assert analysis["output"]["priority_targets"][0]["host"] == "vpn.example.com"
        recommendation = analysis["output"]["active_follow_up_candidates"][0]
        assert recommendation["host"] == "vpn.example.com"
        assert recommendation["evidence_ids"]
        report = write_report(store, run_id, str(tmp_path / "brief.html"), "html").read_text(encoding="utf-8")
        assert "Priority target queue" in report
        assert "External HTTPS remote-access interface" in report
        assert "Recommended for active follow-up" in report
        assert "Enumerate exposed TCP services" in report
        assert "Evidence appendix" in report
    finally:
        store.close()


def test_analysis_rejects_invented_evidence_ids(tmp_path: Path):
    store, run_id = _store_with_recon(tmp_path)
    try:
        with pytest.raises(ValueError, match="unknown fact ID"):
            analyze_run(store, run_id, analyst=InvalidReferenceAnalyst())
        assert store.latest_analysis(run_id) is None
    finally:
        store.close()


def test_analysis_replaces_model_fact_text_with_deterministic_fact(tmp_path: Path):
    store, run_id = _store_with_recon(tmp_path)
    try:
        analyze_run(store, run_id, analyst=FactTamperingAnalyst())
        fact = store.latest_analysis(run_id)["output"]["priority_targets"][0]["observed_facts"][0]
        profile = next(item for item in build_target_profiles(store.snapshot(run_id)) if item["host"] == "vpn.example.com")
        expected = {item["fact_id"]: item for item in profile["fact_refs"]}
        assert fact["statement"] != "Invented vulnerable service claim"
        assert fact == expected[fact["fact_id"]]
    finally:
        store.close()


def test_analysis_rejects_unsupported_security_claims(tmp_path: Path):
    store, run_id = _store_with_recon(tmp_path)
    try:
        with pytest.raises(ValueError, match="unsupported security claim"):
            analyze_run(store, run_id, analyst=UnsupportedClaimAnalyst())
    finally:
        store.close()


def test_analysis_retries_once_after_reference_validation_error(tmp_path: Path):
    store, run_id = _store_with_recon(tmp_path)
    analyst = RetryableReferenceAnalyst()
    try:
        analyze_run(store, run_id, analyst=analyst)
        assert analyst.calls == 2
        assert store.latest_analysis(run_id) is not None
    finally:
        store.close()


def test_passive_active_follow_up_rejects_unobserved_url(tmp_path: Path):
    store, run_id = _store_with_recon(tmp_path)
    try:
        with pytest.raises(ValueError, match="unobserved URL"):
            analyze_run(store, run_id, analyst=InvalidActiveFollowUpAnalyst())
    finally:
        store.close()


def test_active_run_rejects_passive_follow_up_queue(tmp_path: Path):
    store, run_id = _store_with_recon(tmp_path)
    try:
        store.conn.execute("UPDATE runs SET mode='active' WHERE id=?", (run_id,))
        config = RunConfig("example.com", mode="active", authorized_networks=["93.184.216.34/32"])
        store.conn.execute("UPDATE runs SET config_json=? WHERE id=?", (json.dumps(config.__dict__), run_id))
        for tool in ("generate_permutations", "resolve_permutations", "probe_permutation_http", "discover_ports"):
            store.record_result(run_id, ToolResult(tool, "skipped", "example.com"))
        store.conn.commit()
        with pytest.raises(ValueError, match="only valid for passive runs"):
            analyze_run(store, run_id, analyst=ActiveModeFollowUpAnalyst())
    finally:
        store.close()


def test_provider_factory_uses_shared_environment(monkeypatch):
    monkeypatch.setenv("REACT_RECON_AI_PROVIDER", "anthropic")
    monkeypatch.setenv("REACT_RECON_AI_MODEL", "claude-fixture")
    analyst = build_analyst()
    assert isinstance(analyst, AnthropicReconAnalyst)
    assert analyst.model == "claude-fixture"
    with pytest.raises(ValueError, match="unknown AI provider"):
        build_analyst("unknown")


def test_openai_adapter_uses_responses_structured_output():
    calls = []
    client = SimpleNamespace(
        responses=SimpleNamespace(
            create=lambda **kwargs: calls.append(kwargs) or SimpleNamespace(output_text=json.dumps({"run_assessment": "fixture"}))
        )
    )
    output = OpenAIReconAnalyst("gpt-fixture", client=client).analyze({"target_profiles": []}, 3)
    assert output["run_assessment"] == "fixture"
    assert calls[0]["store"] is False
    assert calls[0]["text"]["format"]["schema"]["required"][0] == "run_assessment"


def test_anthropic_adapter_uses_messages_structured_output(monkeypatch):
    calls = []
    response = SimpleNamespace(content=[SimpleNamespace(type="text", text=json.dumps({"run_assessment": "fixture"}))])
    client = SimpleNamespace(messages=SimpleNamespace(create=lambda **kwargs: calls.append(kwargs) or response))
    fake_module = SimpleNamespace(Anthropic=lambda: client, transform_schema=lambda schema: schema)
    monkeypatch.setitem(sys.modules, "anthropic", fake_module)

    output = AnthropicReconAnalyst("claude-fixture", client=client).analyze({"target_profiles": []}, 3)

    assert output["run_assessment"] == "fixture"
    assert calls[0]["max_tokens"] == 8192
    assert calls[0]["output_config"]["format"]["type"] == "json_schema"
    assert calls[0]["messages"][0]["role"] == "user"
