from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable, Dict, List

from .parsers import parse_alterx, parse_crtsh, parse_dnsx, parse_gau, parse_httpx, parse_naabu, parse_nmap, parse_subfinder
from .scope import normalize_host
from .storage import Store


Parser = Callable[[str], List[Dict[str, Any]]]
PARSERS: Dict[str, Parser] = {
    "crtsh_search": parse_crtsh,
    "discover_subdomains": parse_subfinder,
    "retrieve_passive_urls": parse_gau,
    "resolve_dns": parse_dnsx,
    "generate_permutations": parse_alterx,
    "resolve_permutations": parse_dnsx,
    "probe_http": parse_httpx,
    "probe_permutation_http": parse_httpx,
    "discover_ports": parse_naabu,
    "fingerprint_services": lambda text: _parse_nmap_documents(text),
}


def reprocess_run(store: Store, run_id: str) -> Dict[str, Any]:
    """Rebuild normalized state from existing JSONL without target traffic."""
    snapshot = store.snapshot(run_id)
    config = store.run_config(run_id)
    evidence_root = (store.evidence_dir / run_id).resolve()
    replacements: Dict[str, List[Dict[str, Any]]] = {}
    tool_counts: Dict[str, int] = {}
    skipped = []

    # Parse and validate every evidence record before changing SQLite. A corrupt
    # or out-of-root path therefore fails the operation without partial writes.
    for execution in snapshot["executions"]:
        tool = str(execution["tool"])
        parser = PARSERS.get(tool)
        if parser is None:
            skipped.append({"evidence_id": execution["id"], "tool": tool, "reason": "no registered parser"})
            continue
        if not execution.get("raw_output_path"):
            skipped.append(
                {
                    "evidence_id": execution["id"],
                    "tool": tool,
                    "reason": "raw evidence omitted because the run evidence budget was exhausted",
                }
            )
            replacements[execution["id"]] = []
            continue
        raw_path = Path(str(execution["raw_output_path"]))
        if raw_path.is_symlink():
            raise ValueError(f"refusing symlinked evidence file: {raw_path}")
        path = raw_path.resolve()
        try:
            path.relative_to(evidence_root)
        except ValueError as exc:
            raise ValueError(f"evidence path is outside the run directory: {path}") from exc
        if not path.is_file():
            raise ValueError(f"missing evidence file: {path}")
        # Existing evidence may predate output ceilings. Bound the read before
        # JSON decoding so reprocessing cannot reintroduce unbounded memory use.
        maximum_record_bytes = config.max_evidence_bytes
        with path.open("rb") as handle:
            first_line_bytes = handle.readline(maximum_record_bytes + 1)
        if len(first_line_bytes) > maximum_record_bytes or not first_line_bytes.endswith(b"\n"):
            raise ValueError(f"evidence record exceeds the configured output ceiling: {path}")
        first_line = first_line_bytes.decode("utf-8", errors="strict")
        try:
            record = json.loads(first_line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"malformed evidence record: {path}") from exc
        if record.get("run_id") != run_id or record.get("tool") != tool:
            raise ValueError(f"evidence identity mismatch: {path}")
        stdout = record.get("stdout", "")
        if not isinstance(stdout, str):
            raise ValueError(f"evidence stdout is not text: {path}")
        if len(stdout.encode("utf-8")) > config.max_output_bytes:
            raise ValueError(f"evidence stdout exceeds the configured output ceiling: {path}")
        outcomes = record.get("target_outcomes", [])
        if isinstance(outcomes, list) and outcomes and tool in {
            "probe_http",
            "probe_permutation_http",
        }:
            observations = _parse_completed_http_targets(stdout, outcomes)
        elif (
            isinstance(outcomes, list)
            and outcomes
            and tool == "fingerprint_services"
        ):
            observations = _parse_completed_nmap_targets(stdout, outcomes)
        else:
            observations = parser(stdout) if execution["status"] == "success" else []
        if sum(len(items) for items in replacements.values()) + len(observations) > config.max_observations:
            raise ValueError(f"reprocessed observations exceed the run ceiling of {config.max_observations}")
        replacements[execution["id"]] = observations
        tool_counts[tool] = tool_counts.get(tool, 0) + len(observations)

    summary = store.reprocess_observations(run_id, replacements)
    return {"run_id": run_id, **summary, "observations_by_tool": tool_counts, "skipped": skipped, "network_requests": 0}


def _parse_nmap_documents(text: str) -> List[Dict[str, Any]]:
    boundary = r"(?=<\?xml\s)" if "<?xml" in text else r"(?=<nmaprun\b)"
    documents = [item for item in re.split(boundary, text) if item.strip()]
    observations: List[Dict[str, Any]] = []
    for document in documents:
        observations.extend(parse_nmap(document))
    return observations


def _target_stdout(text: str, outcome: Dict[str, Any]) -> str:
    start = outcome.get("stdout_start")
    end = outcome.get("stdout_end")
    if (
        isinstance(start, bool)
        or isinstance(end, bool)
        or not isinstance(start, int)
        or not isinstance(end, int)
        or start < 0
        or end < start
        or end > len(text)
    ):
        raise ValueError("completed target has invalid raw-output boundaries")
    return text[start:end]


def _parse_completed_http_targets(
    text: str, outcomes: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    observations: List[Dict[str, Any]] = []
    for outcome in outcomes:
        if not isinstance(outcome, dict) or outcome.get("status") != "completed":
            continue
        try:
            host = normalize_host(str(outcome.get("host", "")))
            raw_addresses = outcome.get("addresses", [])
            if not isinstance(raw_addresses, list):
                raise ValueError("addresses must be a list")
            addresses = {
                normalize_host(str(item))
                for item in raw_addresses
            }
        except (TypeError, ValueError):
            raise ValueError("completed HTTP target has invalid binding metadata")
        if not addresses:
            raise ValueError("completed HTTP target has no approved addresses")
        for observation in parse_httpx(_target_stdout(text, outcome)):
            if observation.get("type") == "http_probe_failure":
                try:
                    observed_host = normalize_host(
                        str(observation.get("host", ""))
                    )
                except ValueError:
                    continue
                if observed_host == host:
                    observations.append(observation)
                continue
            metadata = (
                observation.get("metadata")
                if isinstance(observation.get("metadata"), dict)
                else {}
            )
            try:
                observed_host = normalize_host(
                    str(metadata.get("input") or metadata.get("host") or "")
                )
                observed_address = normalize_host(
                    str(metadata.get("host_ip") or metadata.get("ip") or "")
                )
            except ValueError:
                continue
            if observed_host == host and observed_address in addresses:
                observations.append(observation)
    return _dedupe_observations(observations)


def _parse_completed_nmap_targets(
    text: str, outcomes: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    observations: List[Dict[str, Any]] = []
    for outcome in outcomes:
        if not isinstance(outcome, dict) or outcome.get("status") != "completed":
            continue
        try:
            host = normalize_host(str(outcome.get("host", "")))
            address = normalize_host(str(outcome.get("ip", "")))
            raw_ports = outcome.get("ports", [])
            if not isinstance(raw_ports, list):
                raise ValueError("ports must be a list")
            ports = set()
            for raw_port in raw_ports:
                if isinstance(raw_port, bool):
                    raise ValueError("port must be an integer")
                port = int(raw_port)
                if not 1 <= port <= 65535:
                    raise ValueError("port is outside the TCP range")
                ports.add(port)
        except (TypeError, ValueError):
            raise ValueError("completed Nmap target has invalid binding metadata")
        if not ports:
            raise ValueError("completed Nmap target has no approved ports")
        for observation in parse_nmap(_target_stdout(text, outcome)):
            try:
                observed_addresses = {
                    normalize_host(str(item))
                    for item in observation.get("addresses", [])
                }
                port = int(observation.get("port", 0))
            except (TypeError, ValueError):
                continue
            if address not in observed_addresses or port not in ports:
                continue
            observations.append(
                {
                    **observation,
                    "host": host,
                    "ip": address,
                    "addresses": [address],
                }
            )
    return _dedupe_observations(observations)


def _dedupe_observations(
    observations: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    seen = set()
    result = []
    for observation in observations:
        key = json.dumps(observation, sort_keys=True)
        if key not in seen:
            seen.add(key)
            result.append(observation)
    return result
