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


def normalize_network(value: str) -> str:
    """Return a canonical IP/CIDR authorization entry."""
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError as exc:
        raise ValueError(f"invalid authorized network: {value}") from exc


def address_is_authorized(value: str, authorized_networks: Iterable[str] = ()) -> bool:
    """Allow globally routed addresses or an explicitly authorized IP/CIDR.

    Hostname ownership does not imply authority over loopback, private,
    link-local, metadata, multicast, reserved, or unspecified destinations.
    Internal assessments can opt in with --authorized-network.
    """
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    for item in authorized_networks:
        try:
            if address in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            return False
    return address.is_global


def address_in_authorized_networks(
    value: str, authorized_networks: Iterable[str]
) -> bool:
    """Require an address to be inside an operator-supplied IP/CIDR."""
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    for item in authorized_networks:
        try:
            if address in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            return False
    return False


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
