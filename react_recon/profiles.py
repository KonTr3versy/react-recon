from __future__ import annotations

import json
from collections import Counter
from pathlib import PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

from .scope import in_scope, normalize_host


REMOTE_ACCESS_TERMS = ("vpn", "global-protect", "globalprotect", "citrix", "rdweb", "anyconnect", "fortigate", "pulse", "remote")
ADMIN_TERMS = ("admin", "manage", "management", "console", "control", "dashboard")
DEVELOPMENT_TERMS = ("dev", "stage", "staging", "test", "qa", "uat", "nonprod", "sandbox", "legacy")
INFORMATION_TERMS = ("help", "docs", "support", "swagger", "graphql", "api", "portal")
PORT_GROUPS = {
    "file_transfer": {20, 21, 22, 69, 445, 873},
    "mail": {25, 110, 143, 465, 587, 993, 995},
    "database": {1433, 1521, 3306, 5432, 6379, 9200, 27017},
    "remote_management": {22, 23, 3389, 5900, 5985, 5986},
}
STANDARD_WEB_PORTS = {80, 443}
AUTHORIZATION_STATUS_CODES = {401, 403, 407}
HTTP_RESPONSE_PRIORITY = {
    "successful": 0,
    "authorization_boundary": 1,
    "redirect": 2,
    "server_error": 3,
    "other_response": 4,
    "none": 5,
}


def build_target_profiles(snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Correlate normalized observations into compact per-host analyst input."""
    root_fqdn = str(snapshot["run"]["root_fqdn"])
    try:
        authorized_hosts = json.loads(snapshot["run"].get("config_json", "{}")).get("authorized_hosts", [])
    except (TypeError, json.JSONDecodeError):
        authorized_hosts = []
    profiles: Dict[str, Dict[str, Any]] = {}

    def profile_for(raw_host: str) -> Optional[Dict[str, Any]]:
        try:
            host = normalize_host(raw_host)
            if not in_scope(host, root_fqdn, authorized_hosts):
                return None
        except ValueError:
            return None
        return profiles.setdefault(host, _empty_profile(host))

    for row in snapshot.get("observations", []):
        value = _load_value(row.get("value_json"))
        if not isinstance(value, dict):
            continue
        kind = str(row.get("type", value.get("type", "unknown")))
        obs_id = str(row.get("id", ""))
        evidence_id = str(row.get("evidence_id", ""))

        if kind in {"hostname", "ct_hostname"}:
            profile = profile_for(str(value.get("value", "")))
            if profile:
                profile["candidate_sources"].add(str(row.get("source_tool", kind)))
                _reference(profile, obs_id, evidence_id)
                profile["fact_refs"].append(_fact_ref(obs_id, evidence_id, f"Passively discovered hostname via {row.get('source_tool', kind)}"))
            continue

        if kind.startswith("dns_"):
            profile = profile_for(str(value.get("host", "")))
            if profile:
                record_type = kind.removeprefix("dns_")
                profile["dns"].setdefault(record_type, set()).add(str(value.get("value", "")))
                profile["verified"] = True
                _reference(profile, obs_id, evidence_id)
                profile["fact_refs"].append(_fact_ref(obs_id, evidence_id, f"DNS {record_type.upper()} record: {value.get('value', '')}"))
            continue

        if kind == "http_service":
            metadata = value.get("metadata") if isinstance(value.get("metadata"), dict) else {}
            raw_url = str(value.get("value") or metadata.get("url") or "")
            host = str(metadata.get("host") or metadata.get("input") or urlsplit(raw_url).hostname or "")
            profile = profile_for(host)
            if profile:
                service = _compact_http_service(raw_url, metadata, obs_id, evidence_id)
                profile["http_services"].append(service)
                profile["verified"] = True
                profile["service_verified"] = True
                _reference(profile, obs_id, evidence_id)
                status = service.get("status_code", "unknown")
                profile["fact_refs"].append(_fact_ref(obs_id, evidence_id, f"HTTP endpoint {raw_url} returned status {status}"))
            continue

        if kind == "http_probe_failure":
            profile = profile_for(str(value.get("host", "")))
            if profile:
                failure = {"error": value.get("error"), "observation_id": obs_id, "evidence_id": evidence_id}
                profile["http_probe_failures"].append(failure)
                _reference(profile, obs_id, evidence_id)
                profile["fact_refs"].append(_fact_ref(obs_id, evidence_id, "httpx did not verify a responding HTTP service"))
            continue

        if kind == "open_port":
            profile = profile_for(str(value.get("host", "")))
            if profile and str(value.get("port", "")).isdigit():
                record = {key: value[key] for key in ("port", "protocol", "ip", "tls", "cdn", "cdn_name", "service", "version") if value.get(key) is not None}
                record.update({"observation_id": obs_id, "evidence_id": evidence_id})
                profile["open_ports"].append(record)
                profile["verified"] = True
                profile["service_verified"] = True
                _reference(profile, obs_id, evidence_id)
                profile["fact_refs"].append(_fact_ref(obs_id, evidence_id, f"Open {record.get('protocol', 'tcp')} port {record['port']}"))
            continue

        if kind == "service_fingerprint":
            profile = profile_for(str(value.get("host", "")))
            if profile:
                record = {key: value[key] for key in ("port", "protocol", "service", "product", "version", "extra_info", "tunnel", "cpe", "confidence") if value.get(key) is not None}
                record.update({"observation_id": obs_id, "evidence_id": evidence_id})
                profile["services"].append(record)
                profile["verified"] = True
                profile["service_verified"] = True
                _reference(profile, obs_id, evidence_id)
                identity = " ".join(str(record.get(key, "")) for key in ("service", "product", "version")).strip() or "unidentified service"
                profile["fact_refs"].append(_fact_ref(obs_id, evidence_id, f"Port {record.get('port')} identified as {identity}"))
            continue

        if kind == "url_candidate":
            raw_url = str(value.get("value", ""))
            parsed = urlsplit(raw_url)
            profile = profile_for(parsed.hostname or "")
            if profile:
                profile["url_count"] += 1
                if parsed.path and len(profile["url_samples"]) < 10:
                    profile["url_samples"].add(parsed.path)
                suffix = PurePosixPath(parsed.path).suffix.lower()
                if suffix:
                    profile["url_extensions"][suffix] += 1
                # URL feeds can contain thousands of records. Retain a small
                # representative citation set while preserving aggregate counts.
                if len(profile["url_observation_ids"]) < 5 and obs_id:
                    profile["url_observation_ids"].add(obs_id)
                    profile["observation_ids"].add(obs_id)
                if evidence_id:
                    profile["evidence_ids"].add(evidence_id)

    completed = [_finalize_profile(profile) for profile in profiles.values()]
    priority_order = {"P1": 0, "P2": 1, "P3": 2, "Context": 3}
    return sorted(
        completed,
        key=lambda item: (
            priority_order[item["deterministic_priority"]],
            HTTP_RESPONSE_PRIORITY[item["http_response_priority"]],
            -item["internal_score"],
            item["host"],
        ),
    )


def select_analyst_profiles(profiles: List[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
    """Select signal-bearing profiles while retaining a few verified controls."""
    interesting = [profile for profile in profiles if profile["signals"]]
    if len(interesting) < limit:
        seen = {profile["host"] for profile in interesting}
        interesting.extend(profile for profile in profiles if profile["verified"] and profile["host"] not in seen)
    return interesting[:limit]


def _empty_profile(host: str) -> Dict[str, Any]:
    return {
        "host": host,
        "verified": False,
        "service_verified": False,
        "candidate_sources": set(),
        "dns": {},
        "http_services": [],
        "http_responsive": False,
        "http_status_codes": [],
        "http_response_priority": "none",
        "http_probe_failures": [],
        "open_ports": [],
        "services": [],
        "url_count": 0,
        "url_samples": set(),
        "url_extensions": Counter(),
        "url_observation_ids": set(),
        "observation_ids": set(),
        "evidence_ids": set(),
        "fact_refs": [],
    }


def _compact_http_service(url: str, metadata: Dict[str, Any], obs_id: str, evidence_id: str) -> Dict[str, Any]:
    record: Dict[str, Any] = {"url": url, "observation_id": obs_id, "evidence_id": evidence_id}
    status_code = metadata.get("status_code", metadata.get("status-code"))
    if str(status_code).isdigit():
        record["status_code"] = int(status_code)
    for key in ("title", "location", "port", "scheme", "tech", "webserver", "server", "host_ip", "cname", "asn", "tls", "favicon", "jarm", "response_time", "time", "content_length", "content_type", "hash"):
        if metadata.get(key) not in (None, "", [], {}):
            record[key] = metadata[key]
    return record


def _finalize_profile(profile: Dict[str, Any]) -> Dict[str, Any]:
    profile["candidate_sources"] = sorted(profile["candidate_sources"])
    profile["dns"] = {key: sorted(values) for key, values in sorted(profile["dns"].items())}
    profile["open_ports"] = _dedupe_records(profile["open_ports"], ("port", "protocol", "ip"))
    profile["services"] = _dedupe_records(profile["services"], ("port", "protocol", "service", "product", "version"))
    profile["http_services"] = _dedupe_records(profile["http_services"], ("url", "status_code", "location"))
    profile["http_status_codes"] = sorted(
        {int(service["status_code"]) for service in profile["http_services"] if str(service.get("status_code", "")).isdigit()}
    )
    profile["http_responsive"] = bool(profile["http_services"])
    profile["http_response_priority"] = _best_http_response_priority(profile["http_status_codes"])
    profile["http_probe_failures"] = _dedupe_records(profile["http_probe_failures"], ("observation_id",))
    profile["url_samples"] = sorted(profile["url_samples"])
    profile["url_extensions"] = dict(profile["url_extensions"].most_common(10))
    profile["url_observation_ids"] = sorted(profile["url_observation_ids"])
    profile["observation_ids"] = sorted(item for item in profile["observation_ids"] if item)
    profile["evidence_ids"] = sorted(item for item in profile["evidence_ids"] if item)
    profile["fact_refs"] = _dedupe_records(profile["fact_refs"], ("fact_id",))[:25]
    profile["signals"] = _interest_signals(profile)
    profile["internal_score"] = min(100, sum(signal["weight"] for signal in profile["signals"]))
    score = profile["internal_score"]
    profile["deterministic_priority"] = "P1" if score >= 35 else "P2" if score >= 20 else "P3" if score > 0 else "Context"
    return profile


def _interest_signals(profile: Dict[str, Any]) -> List[Dict[str, Any]]:
    surface_parts: List[str] = [profile["host"]]
    technology_parts: List[str] = []
    for service in profile["http_services"]:
        surface_parts.extend(str(service.get(key, "")) for key in ("url", "title", "location", "webserver", "server"))
        technology_parts.append(str(service.get("tech", "")))
    for service in profile["services"]:
        technology_parts.extend(str(service.get(key, "")) for key in ("service", "product", "version", "extra_info"))
    surface_text = " ".join(surface_parts).lower()
    technology_text = " ".join(technology_parts).lower()
    all_text = f"{surface_text} {technology_text}"
    ports = {int(item["port"]) for item in profile["open_ports"] if str(item.get("port", "")).isdigit()}
    ports.update(int(item["port"]) for item in profile["services"] if str(item.get("port", "")).isdigit())
    references = {"observation_ids": profile["observation_ids"], "evidence_ids": profile["evidence_ids"]}
    signals: List[Dict[str, Any]] = []

    def add(code: str, label: str, reason: str, weight: int) -> None:
        signals.append({"code": code, "label": label, "reason": reason, "weight": weight, **references})

    # A completed HTTP exchange is stronger targeting evidence than a passive
    # hostname or DNS record. Use one best-response signal per host so multiple
    # schemes do not inflate priority merely by returning similar responses.
    response_priority = profile["http_response_priority"]
    statuses = ", ".join(str(code) for code in profile["http_status_codes"]) or "unknown"
    if response_priority == "successful":
        add("http_success", "Responding web application", f"Observed successful HTTP response status: {statuses}.", 20)
    elif response_priority == "authorization_boundary":
        add("http_authorization_boundary", "Responding access-controlled web endpoint", f"Observed HTTP response requiring or denying authorization: {statuses}.", 22)
    elif response_priority == "redirect":
        add("http_redirect", "Responding redirecting web endpoint", f"Observed HTTP redirect response status: {statuses}.", 18)
    elif response_priority == "server_error":
        add("http_server_error", "Responding web endpoint with server error", f"Observed HTTP server-error response status: {statuses}.", 8)
    elif response_priority == "other_response":
        add("http_response", "Responding web endpoint", f"Observed HTTP response status: {statuses}.", 5)

    if any(term in all_text for term in REMOTE_ACCESS_TERMS):
        if profile["service_verified"]:
            add("remote_access", "Remote access or identity surface", "A responding service and its metadata indicate an external access boundary.", 35)
        elif profile["verified"]:
            add("remote_access_dns", "DNS-resolved remote access candidate", "The hostname resolves and its naming suggests an external access boundary, but no responding service was observed.", 20)
        else:
            add("remote_access_candidate", "Unverified remote access candidate", "Passive naming suggests an external access boundary, but no live service was verified.", 8)
    if any(term in surface_text for term in ADMIN_TERMS):
        if profile["service_verified"]:
            add("administrative", "Administrative surface", "A responding service and its metadata indicate a possible management interface.", 30)
        elif profile["verified"]:
            add("administrative_dns", "DNS-resolved administrative candidate", "The hostname resolves and suggests a management role, but no responding service was observed.", 15)
        else:
            add("administrative_candidate", "Unverified administrative candidate", "Passive naming suggests a possible management role, but no live service was verified.", 8)
    if any(term in profile["host"] for term in DEVELOPMENT_TERMS):
        add("nonproduction", "Nonproduction or legacy naming", "Hostname or service metadata suggests a development, test, staging, or legacy role.", 15)
    if any(term in surface_text for term in INFORMATION_TERMS):
        add("information_surface", "Information-rich application surface", "Naming or metadata suggests documentation, support, API, or portal content.", 10)
    for code, grouped_ports in PORT_GROUPS.items():
        matches = sorted(ports & grouped_ports)
        if matches:
            label = code.replace("_", " ").title()
            add(code, label, f"Observed associated ports: {', '.join(str(port) for port in matches)}.", 20)
    web_ports = {int(service.get("port", 0)) for service in profile["http_services"] if str(service.get("port", "")).isdigit()}
    nonstandard = sorted((ports | web_ports) - STANDARD_WEB_PORTS)
    if nonstandard and profile["http_services"]:
        add("nonstandard_web", "Web service on a nonstandard port", f"Observed web exposure outside 80/443: {', '.join(str(port) for port in nonstandard)}.", 15)
    if len(ports) >= 3:
        add("multi_service", "Multiple exposed services", f"Observed {len(ports)} distinct open ports.", 10)
    if any(service.get("product") or service.get("version") for service in profile["services"]):
        add("explicit_version", "Explicit product or version metadata", "Service fingerprinting returned product or version details for manual review.", 10)
    return signals


def _best_http_response_priority(status_codes: List[int]) -> str:
    classes = {_http_response_class(code) for code in status_codes}
    if not classes and status_codes:
        classes.add("other_response")
    return min(classes or {"none"}, key=lambda item: HTTP_RESPONSE_PRIORITY[item])


def _http_response_class(status_code: int) -> str:
    if 200 <= status_code <= 299:
        return "successful"
    if status_code in AUTHORIZATION_STATUS_CODES:
        return "authorization_boundary"
    if 300 <= status_code <= 399:
        return "redirect"
    if 500 <= status_code <= 599:
        return "server_error"
    return "other_response"


def _fact_ref(obs_id: str, evidence_id: str, statement: str) -> Dict[str, Any]:
    fact_id = "fact-" + obs_id.removeprefix("obs-") if obs_id else ""
    return {"fact_id": fact_id, "statement": statement, "observation_ids": [obs_id] if obs_id else [], "evidence_ids": [evidence_id] if evidence_id else []}


def _reference(profile: Dict[str, Any], obs_id: str, evidence_id: str) -> None:
    if obs_id:
        profile["observation_ids"].add(obs_id)
    if evidence_id:
        profile["evidence_ids"].add(evidence_id)


def _load_value(value: Any) -> Any:
    try:
        return json.loads(value) if isinstance(value, str) else value
    except json.JSONDecodeError:
        return None


def _dedupe_records(records: Iterable[Dict[str, Any]], keys: Tuple[str, ...]) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    seen = set()
    for record in records:
        marker = json.dumps([record.get(key) for key in keys], sort_keys=True, default=str)
        if marker not in seen:
            seen.add(marker)
            result.append(record)
    return result
