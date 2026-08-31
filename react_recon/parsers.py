from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from typing import Any, Dict, Iterable, List

from .scope import normalize_host


def parse_subfinder(text: str) -> List[Dict[str, Any]]:
    # Tool output is untrusted. Keep valid records, normalize hosts, and skip
    # malformed lines without turning them into negative findings.
    observations: List[Dict[str, Any]] = []
    for line in text.splitlines():
        value = line.strip()
        if not value:
            continue
        try:
            item = json.loads(value)
            host = item.get("host") or item.get("subdomain") or item.get("value")
            source = item.get("source")
        except json.JSONDecodeError:
            host, source = value, None
        if host:
            try:
                observations.append({"type": "hostname", "value": normalize_host(str(host)), "source": source})
            except ValueError:
                continue
    return _dedupe(observations)


def parse_dnsx(text: str) -> List[Dict[str, Any]]:
    # Flatten each dnsx record array into deterministic, reportable observations.
    observations: List[Dict[str, Any]] = []
    for line in text.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = item.get("host") or item.get("name")
        if not host:
            continue
        for record_type in ("a", "aaaa", "cname", "ns", "mx", "txt"):
            values = item.get(record_type) or item.get(record_type.upper()) or []
            if isinstance(values, str):
                values = [values]
            for value in values:
                observations.append({"type": f"dns_{record_type}", "host": host, "value": value})
    return _dedupe(observations)


def parse_httpx(text: str) -> List[Dict[str, Any]]:
    # Keep the complete httpx object as metadata while using URL as the stable
    # observation value.
    observations: List[Dict[str, Any]] = []
    for line in text.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("failed") is True:
            host = item.get("host") or item.get("input")
            if host:
                observations.append({"type": "http_probe_failure", "host": host, "error": item.get("error"), "metadata": item})
            continue
        url = item.get("url")
        if url:
            observations.append({"type": "http_service", "value": url, "metadata": item})
    return _dedupe(observations)


def parse_naabu(text: str) -> List[Dict[str, Any]]:
    # Naabu emits JSONL when -json is enabled, but older/plain invocations use
    # host:port. Support both so a successful scan cannot silently disappear
    # from normalized state as the tool version or flags change.
    observations: List[Dict[str, Any]] = []
    for line in text.splitlines():
        value = line.strip()
        if not value:
            continue
        try:
            item = json.loads(value)
        except json.JSONDecodeError:
            item = None
        if isinstance(item, dict):
            host = item.get("host") or item.get("ip")
            port = item.get("port")
            if host and isinstance(port, (int, str)) and str(port).isdigit():
                observation = {
                    "type": "open_port",
                    "host": str(host),
                    "port": int(port),
                    "protocol": item.get("protocol", "tcp"),
                }
                for key in ("ip", "tls", "cdn", "cdn_name", "service", "version"):
                    if item.get(key) is not None:
                        observation[key] = item[key]
                observations.append(observation)
            continue
        if ":" in value:
            host, port = value.rsplit(":", 1)
            if port.isdigit():
                observations.append({"type": "open_port", "host": host.strip("[]"), "port": int(port), "protocol": "tcp"})
    return _dedupe(observations)


def parse_nmap(text: str) -> List[Dict[str, Any]]:
    """Normalize Nmap XML into host/port service observations."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    observations: List[Dict[str, Any]] = []
    for host_node in root.findall("host"):
        addresses = [node.get("addr") for node in host_node.findall("address") if node.get("addr")]
        hostname_node = host_node.find("hostnames/hostname")
        host = hostname_node.get("name") if hostname_node is not None else (addresses[0] if addresses else None)
        if not host:
            continue
        for port_node in host_node.findall("ports/port"):
            state = port_node.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port_node.find("service")
            observation: Dict[str, Any] = {
                "type": "service_fingerprint",
                "host": host,
                "port": int(port_node.get("portid", "0")),
                "protocol": port_node.get("protocol", "tcp"),
                "addresses": addresses,
            }
            if service is not None:
                for source, destination in (
                    ("name", "service"),
                    ("product", "product"),
                    ("version", "version"),
                    ("extrainfo", "extra_info"),
                    ("tunnel", "tunnel"),
                    ("method", "method"),
                    ("conf", "confidence"),
                ):
                    if service.get(source):
                        observation[destination] = service.get(source)
                cpe = service.find("cpe")
                if cpe is not None and cpe.text:
                    observation["cpe"] = cpe.text
            observations.append(observation)
    return _dedupe(observations)


def parse_gau(text: str) -> List[Dict[str, Any]]:
    # gau contributes passive URL candidates only; this parser never fetches it.
    observations: List[Dict[str, Any]] = []
    for line in text.splitlines():
        value = line.strip()
        if not value:
            continue
        try:
            item = json.loads(value)
        except json.JSONDecodeError:
            item = None
        url = item.get("url") if isinstance(item, dict) else value
        if url:
            observations.append({"type": "url_candidate", "value": str(url)})
    return _dedupe(observations)


def parse_crtsh(text: str) -> List[Dict[str, Any]]:
    # Flatten certificate names and retain certificate metadata for provenance.
    try:
        certificates = json.loads(text)
    except json.JSONDecodeError:
        return []
    observations: List[Dict[str, Any]] = []
    for certificate in certificates if isinstance(certificates, list) else []:
        names = str(certificate.get("name_value", "")).splitlines()
        for name in names:
            name = name.strip().lower().lstrip("*.").rstrip(".")
            if name:
                observations.append({"type": "ct_hostname", "value": name, "certificate_id": certificate.get("id"), "common_name": certificate.get("common_name"), "issuer_name": certificate.get("issuer_name"), "not_before": certificate.get("not_before"), "not_after": certificate.get("not_after")})
    return _dedupe(observations)


def _dedupe(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # Stable JSON keys provide order-preserving deduplication across reruns.
    result: List[Dict[str, Any]] = []
    seen = set()
    for item in items:
        key = json.dumps(item, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result
