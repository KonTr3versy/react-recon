from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set

from .models import Decision, RunConfig
from .storage import Store


PASSIVE_BASELINE = ("crtsh_search", "discover_subdomains", "retrieve_passive_urls", "resolve_dns", "probe_http")
ACTIVE_EXPANSION = ("generate_permutations", "resolve_permutations", "probe_permutation_http", "discover_ports")


class CoveragePlanner:
    """Deterministically completes the minimum evidence collection pack."""

    def choose(self, snapshot: Dict[str, Any], config: RunConfig) -> Decision:
        executions = snapshot.get("executions", [])
        attempts: Dict[str, List[Dict[str, Any]]] = {}
        for execution in executions:
            attempts.setdefault(str(execution.get("tool")), []).append(execution)

        for tool in PASSIVE_BASELINE:
            if self._needs_attempt(tool, attempts.get(tool, []), config.max_retries):
                arguments: Dict[str, Any] = {"root_fqdn": config.root_fqdn} if tool in {"crtsh_search", "discover_subdomains", "retrieve_passive_urls"} else {"hosts": []}
                return Decision(tool, arguments, rationale=f"complete mandatory baseline step: {tool}")

        if config.mode == "active":
            for tool in ACTIVE_EXPANSION:
                if self._needs_attempt(tool, attempts.get(tool, []), config.max_retries):
                    return Decision(tool, {"hosts": []}, rationale=f"complete bounded active stage: {tool}")

        has_open_ports = snapshot.get("observation_counts", {}).get("open_port", 0) > 0
        if config.mode == "active" and has_open_ports and self._needs_attempt("fingerprint_services", attempts.get("fingerprint_services", []), config.max_retries):
            return Decision("fingerprint_services", {}, rationale="fingerprint only ports already observed open")

        return Decision("finish_recon", {"summary": "configured deterministic workflow attempted"})

    @staticmethod
    def _needs_attempt(tool: str, executions: List[Dict[str, Any]], max_retries: int) -> bool:
        if not executions:
            return True
        latest = executions[0]  # compact snapshots order newest executions first
        if latest.get("status") != "failed":
            return False
        return len(executions) <= max_retries


def build_coverage(store: Store, run_id: str) -> Dict[str, Any]:
    snapshot = store.snapshot(run_id)
    run = snapshot["run"]
    try:
        config = RunConfig(**json.loads(run["config_json"]))
    except (TypeError, ValueError, json.JSONDecodeError):
        config = RunConfig(root_fqdn=run["root_fqdn"], mode=run["mode"])

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
            open_ports.setdefault(value["host"].lower().rstrip("."), set()).add(int(value.get("port", 0)))
        elif row["type"] == "service_fingerprint" and isinstance(value.get("host"), str):
            fingerprinted.setdefault(value["host"].lower().rstrip("."), set()).add(int(value.get("port", 0)))

    permutation_candidates = set(store.permutation_candidates(run_id, config.max_permutations))
    approved_baseline = {
        item["host"]
        for item in store.approved_targets(run_id, config, source_tool="resolve_dns")
    }
    approved_permutations = {
        item["host"]
        for item in store.approved_targets(run_id, config, source_tool="resolve_permutations")
    }
    permutation_resolved = set(store.resolved_hosts(run_id, source_tool="resolve_permutations"))
    active_hosts = set(store.active_scan_hosts(run_id, config, config.max_assets)) if config.mode == "active" else set()
    expected_targets = {
        "resolve_dns": candidate_hosts,
        "probe_http": approved_baseline,
        "generate_permutations": set(store.candidate_hosts(run_id, min(config.max_assets, 100))) if config.mode == "active" else set(),
        "resolve_permutations": permutation_candidates,
        "probe_permutation_http": approved_permutations,
        "discover_ports": active_hosts,
        "fingerprint_services": set(open_ports) if config.mode == "active" else set(),
    }
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
        expected = expected_targets.get(tool)
        attempted = set(store.attempted_hosts(run_id, tool)) if expected is not None else set()
        missing_targets = sorted(expected - attempted) if expected else []
        if expected is not None and not expected and (latest is None or latest["status"] == "skipped"):
            state = "not_applicable"
        elif latest is None:
            state = "pending"
        else:
            state = str(latest["status"])
        if missing_targets and state == "success":
            state = "incomplete"
        step = {
            "tool": tool,
            "state": state,
            "attempts": len(executions),
            "expected_target_count": len(expected) if expected is not None else None,
            "attempted_target_count": len(attempted) if expected is not None else None,
            "missing_targets": missing_targets[:25],
        }
        steps.append(step)
        if state in {"failed", "incomplete", "pending"}:
            message = f"{tool}: {state}"
            if missing_targets:
                message += f" ({len(missing_targets)} targets not attempted)"
            gaps.append(message)

    baseline_attempted = all(step["state"] not in {"pending", "incomplete"} for step in steps)
    baseline_successful = all(step["state"] in {"success", "not_applicable"} for step in steps)
    return {
        "baseline_attempted": baseline_attempted,
        "baseline_successful": baseline_successful,
        "analysis_ready": baseline_attempted,
        "steps": steps,
        "metrics": {
            "discovered_hosts": len(candidate_hosts),
            "dns_resolved_hosts": len(resolved_hosts),
            "approved_http_probe_hosts": len(approved_baseline | approved_permutations),
            "dns_hosts_excluded_by_destination_policy": len(resolved_hosts - approved_baseline) + len(permutation_resolved - approved_permutations),
            "http_responding_hosts": len(http_hosts),
            "permutation_candidates": len(permutation_candidates),
            "permutation_resolved_hosts": len(permutation_resolved),
            "hosts_with_open_ports": len(open_ports),
            "open_port_count": sum(len(ports) for ports in open_ports.values()),
            "fingerprinted_service_count": sum(len(ports) for ports in fingerprinted.values()),
        },
        "gaps": gaps,
    }
