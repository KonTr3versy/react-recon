from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Sequence, Set

from .models import Decision, RunConfig
from .planning import arguments_for_candidates, tool_target_state
from .storage import Store


PASSIVE_BASELINE = (
    "crtsh_search",
    "discover_subdomains",
    "retrieve_passive_urls",
    "resolve_dns",
    "probe_http",
)
ACTIVE_EXPANSION = (
    "generate_permutations",
    "resolve_permutations",
    "probe_permutation_http",
    "discover_ports",
)
ROOT_TOOLS = {"crtsh_search", "discover_subdomains", "retrieve_passive_urls"}


class CoveragePlanner:
    """Deterministically completes missing per-target coverage."""

    def __init__(
        self,
        store: Optional[Store] = None,
        stages: Optional[Sequence[str]] = None,
    ) -> None:
        self.store = store
        self.stages = tuple(stages) if stages is not None else None

    def choose(self, snapshot: Dict[str, Any], config: RunConfig) -> Decision:
        executions = snapshot.get("executions", [])
        attempts: Dict[str, List[Dict[str, Any]]] = {}
        for execution in executions:
            attempts.setdefault(str(execution.get("tool")), []).append(execution)

        if self.stages is None:
            stages = list(PASSIVE_BASELINE)
            if config.mode == "active":
                stages.extend(ACTIVE_EXPANSION)
                if snapshot.get("observation_counts", {}).get("open_port", 0) > 0:
                    stages.append("fingerprint_services")
        else:
            stages = list(self.stages)

        run_id = str(snapshot.get("run", {}).get("id", ""))
        for tool in stages:
            tool_attempts = attempts.get(tool, [])
            if self.store is not None and run_id:
                tool_attempts = self.store.tool_execution_records(run_id, tool)
            if tool in ROOT_TOOLS:
                if self._needs_attempt(tool, tool_attempts, config.max_retries):
                    return Decision(
                        tool,
                        {"root_fqdn": config.root_fqdn},
                        rationale=f"complete mandatory baseline step: {tool}",
                    )
                continue

            if self.store is None or not run_id:
                if self._needs_attempt(tool, tool_attempts, config.max_retries):
                    return Decision(
                        tool,
                        {},
                        rationale=f"complete configured coverage stage: {tool}",
                    )
                continue

            target_state = tool_target_state(self.store, run_id, config, tool)
            if target_state.remaining:
                return Decision(
                    tool,
                    arguments_for_candidates(tool, target_state.remaining),
                    rationale=(
                        f"complete {len(target_state.remaining)} missing target(s) "
                        f"for deterministic stage: {tool}"
                    ),
                )
            if target_state.expected or target_state.exhausted_keys:
                # New targets discovered later will make the stage eligible
                # again because target state is rebuilt on every cycle.
                continue
            if tool == "fingerprint_services":
                continue
            if self._needs_attempt(tool, tool_attempts, config.max_retries):
                return Decision(
                    tool,
                    arguments_for_candidates(tool, []),
                    rationale=f"record empty or unavailable stage coverage: {tool}",
                )

        return Decision(
            "finish_recon", {"summary": "configured deterministic workflow attempted"}
        )

    @staticmethod
    def _needs_attempt(
        tool: str, executions: List[Dict[str, Any]], max_retries: int
    ) -> bool:
        if not executions:
            return True
        latest = executions[0]  # compact snapshots order newest executions first
        if latest.get("status") != "failed":
            return False
        return len(executions) <= max_retries


def build_coverage(store: Store, run_id: str) -> Dict[str, Any]:
    snapshot = store.snapshot(run_id)
    config = store.run_config(run_id)

    executions_by_tool: Dict[str, List[Dict[str, Any]]] = {}
    for execution in snapshot["executions"]:
        executions_by_tool.setdefault(execution["tool"], []).append(execution)

    candidate_hosts = set(store.candidate_hosts(run_id))
    resolved_hosts = set(store.resolved_hosts(run_id))
    http_hosts: Set[str] = set()
    open_ports: Dict[str, Set[int]] = {}
    fingerprinted: Dict[str, Set[int]] = {}
    for row in snapshot["observations"]:
        try:
            value = json.loads(row["value_json"])
        except json.JSONDecodeError:
            continue
        if row["type"] == "http_service":
            metadata = value.get("metadata", {})
            host = metadata.get("host") or metadata.get("input")
            if isinstance(host, str):
                http_hosts.add(host.lower().rstrip("."))
        elif row["type"] == "open_port" and isinstance(value.get("host"), str):
            open_ports.setdefault(value["host"].lower().rstrip("."), set()).add(
                int(value.get("port", 0))
            )
        elif row["type"] == "service_fingerprint" and isinstance(
            value.get("host"), str
        ):
            fingerprinted.setdefault(
                value["host"].lower().rstrip("."), set()
            ).add(int(value.get("port", 0)))

    permutation_candidates = set(
        store.permutation_candidates(run_id, config.max_permutations)
    )
    approved_baseline = {
        item["host"]
        for item in store.approved_targets(
            run_id, config, source_tool="resolve_dns"
        )
    }
    approved_permutations = {
        item["host"]
        for item in store.approved_targets(
            run_id, config, source_tool="resolve_permutations"
        )
    }
    permutation_resolved = set(
        store.resolved_hosts(run_id, source_tool="resolve_permutations")
    )

    tools = list(PASSIVE_BASELINE)
    if config.mode == "active":
        tools.extend(ACTIVE_EXPANSION)
        if open_ports:
            tools.append("fingerprint_services")

    steps = []
    gaps = []
    for tool in tools:
        executions = executions_by_tool.get(tool, [])
        latest = executions[-1] if executions else None
        if tool in ROOT_TOOLS:
            expected_count: Optional[int] = None
            attempted_count: Optional[int] = None
            missing_targets: List[str] = []
            state = "pending" if latest is None else str(latest["status"])
        else:
            target_state = tool_target_state(store, run_id, config, tool)
            expected_keys = {candidate.key for candidate in target_state.expected}
            missing_keys = expected_keys - target_state.completed_keys
            expected_count = len(expected_keys)
            attempted_count = len(target_state.attempted_keys & expected_keys)
            missing_targets = sorted(missing_keys)[:25]
            if not expected_keys and (
                latest is None or latest["status"] == "skipped"
            ):
                state = "not_applicable"
            elif missing_keys:
                if missing_keys.issubset(target_state.exhausted_keys):
                    state = "failed"
                elif latest is None:
                    state = "pending"
                else:
                    state = "incomplete"
            elif latest is None:
                state = "pending"
            else:
                state = str(latest["status"])

        step = {
            "tool": tool,
            "state": state,
            "attempts": len(executions),
            "expected_target_count": expected_count,
            "attempted_target_count": attempted_count,
            "missing_targets": missing_targets,
        }
        steps.append(step)
        if state in {"failed", "incomplete", "pending"}:
            message = f"{tool}: {state}"
            if missing_targets:
                message += f" ({len(missing_targets)} targets not completed)"
            gaps.append(message)

    baseline_attempted = all(
        step["state"] not in {"pending", "incomplete"} for step in steps
    )
    baseline_successful = all(
        step["state"] in {"success", "not_applicable"} for step in steps
    )
    return {
        "baseline_attempted": baseline_attempted,
        "baseline_successful": baseline_successful,
        "analysis_ready": baseline_attempted,
        "steps": steps,
        "metrics": {
            "discovered_hosts": len(candidate_hosts),
            "dns_resolved_hosts": len(resolved_hosts),
            "approved_http_probe_hosts": len(
                approved_baseline | approved_permutations
            ),
            "dns_hosts_excluded_by_destination_policy": len(
                resolved_hosts - approved_baseline
            )
            + len(permutation_resolved - approved_permutations),
            "http_responding_hosts": len(http_hosts),
            "permutation_candidates": len(permutation_candidates),
            "permutation_resolved_hosts": len(permutation_resolved),
            "hosts_with_open_ports": len(open_ports),
            "open_port_count": sum(len(ports) for ports in open_ports.values()),
            "fingerprinted_service_count": sum(
                len(ports) for ports in fingerprinted.values()
            ),
        },
        "gaps": gaps,
    }
