import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from react_recon.agent import ReconAgent
from react_recon.models import Decision, RunConfig, ToolResult
from react_recon.planning import (
    PLANNER_SCHEMA,
    AdaptiveDecision,
    AdaptivePlanner,
    build_action_catalog,
    evaluate_progress,
    progress_metrics,
    tool_target_state,
)
from react_recon.providers import AnthropicStructuredModel, OpenAIStructuredModel
from react_recon.reporting import build_report, write_report
from react_recon.storage import Store


class WorkflowExecutor:
    def __init__(self, *, generate_permutation: bool = False) -> None:
        self.calls = []
        self.generate_permutation = generate_permutation

    def execute(self, tool, arguments):
        self.calls.append((tool, arguments))
        if tool == "crtsh_search":
            observations = [{"type": "ct_hostname", "value": "vpn.example.com"}]
        elif tool == "discover_subdomains":
            observations = [{"type": "hostname", "value": "app.example.com"}]
        elif tool == "retrieve_passive_urls":
            observations = []
        elif tool == "resolve_dns":
            observations = [
                {
                    "type": "dns_a",
                    "host": host,
                    "value": "93.184.216.34",
                }
                for host in arguments.get("hosts", [])
            ]
        elif tool == "probe_http":
            observations = [
                {
                    "type": "http_service",
                    "value": f"https://{host}",
                    "metadata": {"host": host, "status_code": 200},
                }
                for host in arguments.get("hosts", [])
            ]
        elif tool == "generate_permutations" and self.generate_permutation:
            observations = [
                {
                    "type": "permutation_candidate",
                    "value": "dev.example.com",
                    "generator": "alterx",
                }
            ]
        elif tool == "resolve_permutations":
            observations = [
                {
                    "type": "dns_a",
                    "host": host,
                    "value": "93.184.216.34",
                }
                for host in arguments.get("hosts", [])
            ]
        elif tool == "probe_permutation_http":
            observations = [
                {
                    "type": "http_service",
                    "value": f"https://{host}",
                    "metadata": {"host": host, "status_code": 403},
                }
                for host in arguments.get("hosts", [])
            ]
        else:
            observations = []
        return ToolResult(tool, "success", "example.com", observations=observations)


class CatalogPlanner:
    provider = "fixture"
    model = "fixture-model"

    def __init__(self, tools):
        self.tools = list(tools)
        self.calls = 0

    def choose(self, payload):
        self.calls += 1
        tool = self.tools.pop(0)
        if tool == "finish_recon":
            ids = []
        else:
            ids = [
                item["candidate_id"]
                for item in payload["available_actions"]
                if item["tool"] == tool
            ][:1]
            assert ids, f"fixture expected a catalog candidate for {tool}"
        return AdaptiveDecision(
            tool=tool,
            candidate_ids=ids,
            objective=f"fixture objective for {tool}",
            rationale="fixture rationale",
            expected_observation="fixture observation",
            stop_condition="fixture stop",
        )


class FailIfCalledPlanner:
    provider = "fixture"
    model = "fixture-model"

    def choose(self, payload):
        raise AssertionError("adaptive planner must not be called")


def _config(tmp_path: Path, **overrides) -> RunConfig:
    values = {
        "root_fqdn": "example.com",
        "mode": "active",
        "authorized_networks": ["93.184.216.34/32"],
        "database": str(tmp_path / "run.db"),
        "evidence_dir": str(tmp_path / "evidence"),
        "ai_provider": "openai",
        "ai_model": "fixture-model",
    }
    values.update(overrides)
    return RunConfig(**values)


def _seed_passive_baseline(store: Store, config: RunConfig) -> str:
    run_id = store.create_run(config)

    def persist(tool, arguments, observations):
        task_id = store.add_task(run_id, tool, arguments, phase="baseline")
        store.record_result(
            run_id,
            ToolResult(tool, "success", "example.com", observations=observations),
        )
        store.complete_task(task_id)

    persist("crtsh_search", {"root_fqdn": "example.com"}, [])
    persist(
        "discover_subdomains",
        {"root_fqdn": "example.com"},
        [
            {"type": "hostname", "value": "app.example.com"},
            {"type": "hostname", "value": "vpn.example.com"},
        ],
    )
    persist("retrieve_passive_urls", {"root_fqdn": "example.com"}, [])
    hosts = ["app.example.com", "example.com", "vpn.example.com"]
    persist(
        "resolve_dns",
        {"hosts": hosts},
        [
            {"type": "dns_a", "host": host, "value": "93.184.216.34"}
            for host in hosts
        ],
    )
    persist(
        "probe_http",
        {
            "hosts": hosts,
            "approved_addresses": {
                host: ["93.184.216.34"] for host in hosts
            },
        },
        [
            {
                "type": "http_service",
                "value": f"https://{host}",
                "metadata": {"host": host, "status_code": 200},
            }
            for host in hosts
        ],
    )
    return run_id


def test_passive_hybrid_run_never_calls_adaptive_planner(tmp_path: Path):
    config = _config(tmp_path, mode="passive", authorized_networks=[])
    store = Store(config.database, config.evidence_dir)
    executor = WorkflowExecutor()
    try:
        ReconAgent(
            store,
            config,
            executor=executor,
            adaptive_planner=FailIfCalledPlanner(),
        ).run()
        assert [tool for tool, _ in executor.calls] == [
            "crtsh_search",
            "discover_subdomains",
            "retrieve_passive_urls",
            "resolve_dns",
            "probe_http",
        ]
    finally:
        store.close()


def test_active_catalog_exposes_probed_public_host_for_model_selected_port_scan(
    tmp_path: Path,
):
    config = _config(tmp_path, authorized_networks=[])
    store = Store(config.database, config.evidence_dir)
    try:
        run_id = _seed_passive_baseline(store, config)
        catalog = build_action_catalog(store, run_id, config)
        port_cards = [
            card for card in catalog.cards if card["tool"] == "discover_ports"
        ]

        assert port_cards
        assert port_cards[0]["http_status_codes"] == [200]
        assert port_cards[0]["http_response_priority"] == "successful"
        assert port_cards[0]["resolved_addresses"] == ["93.184.216.34"]

        decision = AdaptiveDecision(
            tool="discover_ports",
            candidate_ids=[port_cards[0]["candidate_id"]],
            objective="Enumerate services on the responding host",
            rationale="The host returned a successful HTTP response",
            expected_observation="Open TCP services",
            stop_condition="The selected DNS-bound address has been scanned",
        )
        arguments = catalog.resolve(decision)
        selected_host = port_cards[0]["host"]
        assert arguments == {
            "hosts": [selected_host],
            "approved_addresses": {selected_host: ["93.184.216.34"]},
        }
    finally:
        store.close()


def test_adaptive_subset_is_not_duplicated_by_fallback(tmp_path: Path):
    config = _config(tmp_path)
    store = Store(config.database, config.evidence_dir)
    executor = WorkflowExecutor()
    planner = CatalogPlanner(["discover_ports", "finish_recon"])
    try:
        run_id = ReconAgent(
            store, config, executor=executor, adaptive_planner=planner
        ).run()
        port_calls = [args["hosts"] for tool, args in executor.calls if tool == "discover_ports"]
        assert len(port_calls) == 2
        assert set(port_calls[0]).isdisjoint(port_calls[1])
        assert set(port_calls[0]) | set(port_calls[1]) == {
            "app.example.com",
            "example.com",
            "vpn.example.com",
        }
        assert store.adaptive_stop_reason(run_id) == "explicit_finish"
    finally:
        store.close()


def test_new_target_after_early_port_action_is_scanned_by_fallback(tmp_path: Path):
    config = _config(tmp_path)
    store = Store(config.database, config.evidence_dir)
    executor = WorkflowExecutor(generate_permutation=True)
    planner = CatalogPlanner(
        ["discover_ports", "generate_permutations", "resolve_permutations"]
    )
    try:
        ReconAgent(
            store, config, executor=executor, adaptive_planner=planner
        ).run()
        port_calls = [args["hosts"] for tool, args in executor.calls if tool == "discover_ports"]
        assert len(port_calls) == 2
        assert "dev.example.com" in port_calls[1]
        assert set(port_calls[0]).isdisjoint(port_calls[1])
    finally:
        store.close()


def test_adaptive_actions_emit_bounded_pacing_progress(tmp_path: Path):
    config = _config(tmp_path)
    store = Store(config.database, config.evidence_dir)
    executor = WorkflowExecutor(generate_permutation=True)
    planner = CatalogPlanner(
        ["discover_ports", "generate_permutations", "resolve_permutations"]
    )
    events = []
    try:
        ReconAgent(
            store,
            config,
            executor=executor,
            adaptive_planner=planner,
            progress=events.append,
        ).run()
    finally:
        store.close()

    pacing = [event for event in events if event["event"] == "adaptive_progress"]
    assert [event["completed"] for event in pacing] == [1, 2, 3]
    assert all(event["total"] == 3 for event in pacing)
    assert [event["tool"] for event in pacing] == [
        "discover_ports",
        "generate_permutations",
        "resolve_permutations",
    ]


def test_candidate_ids_are_stable_opaque_and_tool_bound(tmp_path: Path):
    config = _config(tmp_path)
    store = Store(config.database, config.evidence_dir)
    try:
        run_id = _seed_passive_baseline(store, config)
        first = build_action_catalog(store, run_id, config)
        second = build_action_catalog(store, run_id, config)
        assert [item.candidate_id for item in first.entries] == [
            item.candidate_id for item in second.entries
        ]
        assert all("example.com" not in item.candidate_id for item in first.entries)

        port_entry = next(
            item for item in first.entries if item.candidate.tool == "discover_ports"
        )
        generate_entry = next(
            item
            for item in first.entries
            if item.candidate.tool == "generate_permutations"
        )
        with pytest.raises(ValueError, match="unknown or stale"):
            first.resolve(
                AdaptiveDecision(
                    "discover_ports", ["cand-invented"], "", "", "", ""
                )
            )
        with pytest.raises(ValueError, match="not valid"):
            first.resolve(
                AdaptiveDecision(
                    "discover_ports",
                    [generate_entry.candidate_id],
                    "",
                    "",
                    "",
                    "",
                )
            )
        with pytest.raises(ValueError, match="unique and limited"):
            first.resolve(
                AdaptiveDecision(
                    "discover_ports",
                    [port_entry.candidate_id] * 26,
                    "",
                    "",
                    "",
                    "",
                )
            )
    finally:
        store.close()


def test_successful_negative_action_counts_as_target_coverage_progress(tmp_path: Path):
    config = _config(tmp_path)
    store = Store(config.database, config.evidence_dir)
    try:
        run_id = _seed_passive_baseline(store, config)
        catalog = build_action_catalog(store, run_id, config)
        entry = next(
            item for item in catalog.entries if item.candidate.tool == "discover_ports"
        )
        arguments = catalog.resolve(
            AdaptiveDecision(
                "discover_ports", [entry.candidate_id], "", "", "", ""
            )
        )
        before = progress_metrics(store, run_id, config, "discover_ports")
        task_id = store.add_task(
            run_id, "discover_ports", arguments, phase="adaptive"
        )
        store.record_result(
            run_id, ToolResult("discover_ports", "success", entry.candidate.host)
        )
        store.complete_task(task_id)
        after = progress_metrics(store, run_id, config, "discover_ports")
        progress = evaluate_progress(before, after, "success")
        assert progress["made_progress"] is True
        assert progress["progress_basis"] == "new_target_coverage"
    finally:
        store.close()


def test_partial_batch_coverage_retries_only_failed_target(tmp_path: Path):
    class PartialExecutor:
        def execute(self, tool, arguments):
            return ToolResult(
                tool,
                "failed",
                "example.com",
                target_outcomes=[
                    {"host": "app.example.com", "status": "completed"},
                    {"host": "vpn.example.com", "status": "failed"},
                    {"host": "later.example.com", "status": "unattempted"},
                ],
            )

    config = _config(tmp_path)
    store = Store(config.database, config.evidence_dir)
    try:
        run_id = store.create_run(config)
        store.record_result(
            run_id,
            ToolResult(
                "resolve_dns",
                "success",
                "example.com",
                observations=[
                    {
                        "type": "dns_a",
                        "host": host,
                        "value": "93.184.216.34",
                    }
                    for host in (
                        "app.example.com",
                        "vpn.example.com",
                        "later.example.com",
                    )
                ],
            ),
        )
        arguments = {
            "hosts": [
                "app.example.com",
                "vpn.example.com",
                "later.example.com",
            ],
            "approved_addresses": {
                "app.example.com": ["93.184.216.34"],
                "vpn.example.com": ["93.184.216.34"],
                "later.example.com": ["93.184.216.34"],
            },
        }
        before = progress_metrics(store, run_id, config, "probe_http")
        task_id, result = ReconAgent(
            store, config, executor=PartialExecutor()
        )._execute_decision(
            run_id,
            Decision("probe_http", arguments),
            phase="fallback",
            decision_record={},
        )
        store.update_task_progress(task_id, {"made_progress": True})
        state = tool_target_state(store, run_id, config, "probe_http")
        after = progress_metrics(store, run_id, config, "probe_http")

        assert {item.host for item in state.remaining} == {
            "vpn.example.com",
            "later.example.com",
        }
        assert any("app.example.com" in key for key in state.completed_keys)
        assert evaluate_progress(before, after, result.status)["made_progress"] is True
        saved = json.loads(store.task_records(run_id, tool="probe_http")[0]["progress_json"])
        assert "coverage" in saved
        assert saved["made_progress"] is True
    finally:
        store.close()


def test_two_failed_adaptive_actions_stop_then_fallback_recovers(tmp_path: Path):
    class RecoveringExecutor(WorkflowExecutor):
        def __init__(self):
            super().__init__()
            self.port_attempts = 0

        def execute(self, tool, arguments):
            if tool == "discover_ports":
                self.calls.append((tool, arguments))
                self.port_attempts += 1
                if self.port_attempts <= 2:
                    return ToolResult(tool, "failed", "example.com")
                return ToolResult(tool, "success", "example.com")
            return super().execute(tool, arguments)

    config = _config(tmp_path)
    store = Store(config.database, config.evidence_dir)
    executor = RecoveringExecutor()
    planner = CatalogPlanner(["discover_ports", "discover_ports"])
    try:
        run_id = ReconAgent(
            store, config, executor=executor, adaptive_planner=planner
        ).run()
        assert store.adaptive_action_count(run_id) == 2
        assert store.adaptive_stop_reason(run_id) == "no_progress_or_repeated_failure"
        assert executor.port_attempts == 3
    finally:
        store.close()


def test_provider_error_falls_back_without_persisting_keys(
    tmp_path: Path, monkeypatch
):
    secret = "fixture-provider-key"
    monkeypatch.setenv("OPENAI_API_KEY", secret)

    class UnavailablePlanner:
        provider = "fixture"
        model = "fixture-model"

        def choose(self, payload):
            raise RuntimeError(f"fixture provider unavailable: {secret}")

    config = _config(tmp_path)
    store = Store(config.database, config.evidence_dir)
    executor = WorkflowExecutor()
    try:
        run_id = ReconAgent(
            store,
            config,
            executor=executor,
            adaptive_planner=UnavailablePlanner(),
        ).run()
        assert store.adaptive_stop_reason(run_id) == "provider_error"
        assert store.adaptive_action_count(run_id) == 0
        assert any(tool == "discover_ports" for tool, _ in executor.calls)
        assert store.snapshot(run_id)["run"]["status"] == "completed"
        assert secret not in json.dumps(build_report(store, run_id))
    finally:
        store.close()


def test_adaptive_action_limit_is_durable_across_resume(tmp_path: Path):
    config = _config(tmp_path)
    store = Store(config.database, config.evidence_dir)
    executor = WorkflowExecutor()
    try:
        run_id = _seed_passive_baseline(store, config)
        catalog = build_action_catalog(store, run_id, config)
        selected = [
            entry for entry in catalog.entries if entry.candidate.tool == "discover_ports"
        ][:3]
        for index, entry in enumerate(selected):
            decision = {
                "provider": "fixture",
                "model": "fixture-model",
                "candidate_ids": [entry.candidate_id],
            }
            arguments = catalog.resolve(
                AdaptiveDecision(
                    "discover_ports",
                    [entry.candidate_id],
                    "",
                    "",
                    "",
                    "",
                )
            )
            task_id = store.add_task(
                run_id,
                "discover_ports",
                arguments,
                phase="adaptive",
                decision=decision,
            )
            store.record_result(
                run_id, ToolResult("discover_ports", "success", entry.candidate.host)
            )
            store.complete_task(
                task_id,
                progress={
                    "made_progress": True,
                    "progress_basis": "new_target_coverage",
                    "stop_reason": "adaptive_action_limit" if index == 2 else None,
                },
            )

        ReconAgent(
            store,
            config,
            executor=executor,
            adaptive_planner=FailIfCalledPlanner(),
        ).run(run_id)
        assert store.adaptive_action_count(run_id) == 3
        assert store.adaptive_stop_reason(run_id) == "adaptive_action_limit"
    finally:
        store.close()


def test_planner_rejects_fields_that_could_carry_raw_targets():
    class RawTargetModel:
        provider = "fixture"
        model = "fixture-model"

        def generate(self, **kwargs):
            return {
                "tool": "discover_ports",
                "candidate_ids": ["cand-one"],
                "objective": "fixture",
                "rationale": "fixture",
                "expected_observation": "fixture",
                "stop_condition": "fixture",
                "hosts": ["invented.example.com"],
            }

    with pytest.raises(ValueError, match="unexpected fields"):
        AdaptivePlanner(structured_model=RawTargetModel()).choose({})


def test_openai_and_anthropic_planners_use_the_same_schema(monkeypatch):
    decision = {
        "tool": "finish_recon",
        "candidate_ids": [],
        "objective": "done",
        "rationale": "done",
        "expected_observation": "none",
        "stop_condition": "done",
    }
    openai_calls = []
    openai_client = SimpleNamespace(
        responses=SimpleNamespace(
            create=lambda **kwargs: openai_calls.append(kwargs)
            or SimpleNamespace(output_text=json.dumps(decision))
        )
    )
    AdaptivePlanner(
        structured_model=OpenAIStructuredModel(
            "gpt-fixture", client=openai_client
        )
    ).choose({"available_actions": []})

    anthropic_calls = []
    response = SimpleNamespace(
        content=[SimpleNamespace(type="text", text=json.dumps(decision))]
    )
    anthropic_client = SimpleNamespace(
        messages=SimpleNamespace(
            create=lambda **kwargs: anthropic_calls.append(kwargs) or response
        )
    )
    monkeypatch.setitem(
        sys.modules,
        "anthropic",
        SimpleNamespace(
            Anthropic=lambda: anthropic_client,
            transform_schema=lambda schema: schema,
        ),
    )
    AdaptivePlanner(
        structured_model=AnthropicStructuredModel(
            "claude-fixture", client=anthropic_client
        )
    ).choose({"available_actions": []})

    assert openai_calls[0]["text"]["format"]["schema"] == PLANNER_SCHEMA
    assert (
        anthropic_calls[0]["output_config"]["format"]["schema"]
        == PLANNER_SCHEMA
    )


def test_adaptive_decisions_are_in_json_and_collapsed_html(tmp_path: Path):
    config = _config(tmp_path)
    store = Store(config.database, config.evidence_dir)
    try:
        run_id = _seed_passive_baseline(store, config)
        task_id = store.add_task(
            run_id,
            "discover_ports",
            {"hosts": ["vpn.example.com"]},
            phase="adaptive",
            decision={
                "provider": "fixture",
                "model": "fixture-model",
                "candidate_ids": ["cand-fixture"],
                "objective": "Prioritize the VPN boundary",
            },
        )
        store.complete_task(
            task_id,
            progress={
                "made_progress": True,
                "progress_basis": "new_target_coverage",
            },
        )
        report = build_report(store, run_id)
        assert report["adaptive_decisions"][0]["candidate_ids"] == [
            "cand-fixture"
        ]
        html = write_report(
            store, run_id, str(tmp_path / "report.html"), "html"
        ).read_text(encoding="utf-8")
        assert "Adaptive collection decisions" in html
        assert "Prioritize the VPN boundary" in html
    finally:
        store.close()
