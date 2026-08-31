from __future__ import annotations

import ipaddress
import re
from typing import Iterable

_HOST_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$", re.I)


def normalize_host(value: str) -> str:
    # Normalize before policy checks so case, trailing dots, and IP formatting
    # cannot create separate scope identities.
    value = value.strip().lower().rstrip(".")
    if not value:
        raise ValueError("empty host")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if not _HOST_RE.fullmatch(value):
            raise ValueError(f"invalid hostname: {value}")
        return value


def in_scope(host: str, root_fqdn: str, authorized_hosts: Iterable[str]) -> bool:
    # This broad root/subdomain test supports passive discovery. Executor adds
    # an explicit-host requirement before active probing or port discovery.
    candidate = normalize_host(host)
    root = normalize_host(root_fqdn)
    allowed = {normalize_host(item) for item in authorized_hosts}
    if candidate == root or (not _is_ip(candidate) and candidate.endswith("." + root)):
        return True
    return candidate in allowed


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
