from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable, Dict, List

from .parsers import parse_crtsh, parse_dnsx, parse_gau, parse_httpx, parse_naabu, parse_nmap, parse_subfinder
from .storage import Store


Parser = Callable[[str], List[Dict[str, Any]]]
PARSERS: Dict[str, Parser] = {
    "crtsh_search": parse_crtsh,
    "discover_subdomains": parse_subfinder,
    "retrieve_passive_urls": parse_gau,
    "resolve_dns": parse_dnsx,
    "probe_http": parse_httpx,
    "discover_ports": parse_naabu,
    "fingerprint_services": lambda text: _parse_nmap_documents(text),
}


def reprocess_run(store: Store, run_id: str) -> Dict[str, Any]:
    """Rebuild normalized state from existing JSONL without target traffic."""
    snapshot = store.snapshot(run_id)
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
        path = Path(str(execution["raw_output_path"])).resolve()
        try:
            path.relative_to(evidence_root)
        except ValueError as exc:
            raise ValueError(f"evidence path is outside the run directory: {path}") from exc
        if not path.is_file():
            raise ValueError(f"missing evidence file: {path}")
        with path.open("r", encoding="utf-8") as handle:
            first_line = handle.readline()
        try:
            record = json.loads(first_line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"malformed evidence record: {path}") from exc
        if record.get("run_id") != run_id or record.get("tool") != tool:
            raise ValueError(f"evidence identity mismatch: {path}")
        stdout = record.get("stdout", "")
        if not isinstance(stdout, str):
            raise ValueError(f"evidence stdout is not text: {path}")
        observations = parser(stdout) if execution["status"] == "success" else []
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
