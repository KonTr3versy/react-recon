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
    return _is_public_destination(address)


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


def address_is_active_scan_authorized(
    value: str, authorized_networks: Iterable[str] = ()
) -> bool:
    """Authorize an active scan destination from DNS evidence and run policy.

    With no operator-supplied network restriction, a globally routable address
    discovered through the controller's fresh DNS binding is eligible. When at
    least one network is supplied, the entries become a strict narrowing
    allowlist. Private, loopback, link-local, multicast, reserved, and
    unspecified destinations therefore still require an explicit IP/CIDR.
    """
    networks = tuple(authorized_networks)
    if networks:
        return address_in_authorized_networks(value, networks)
    return address_is_authorized(value)


def _is_public_destination(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Reject special-use and transition addresses from automatic execution."""
    if (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        return False
    if isinstance(address, ipaddress.IPv6Address) and (
        address.ipv4_mapped is not None
        or address.sixtofour is not None
        or address.teredo is not None
    ):
        # Transition forms can encode a non-global IPv4 destination while the
        # outer IPv6 address appears global on some Python/platform versions.
        return False
    return True


def in_scope(host: str, root_fqdn: str, authorized_hosts: Iterable[str]) -> bool:
    # The root and its descendants are the run's hostname boundary. Exact
    # authorized_hosts extend that boundary without authorizing sibling names.
    # Destination-touching adapters apply DNS-binding and IP policy separately.
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
