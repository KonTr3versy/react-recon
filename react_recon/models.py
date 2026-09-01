from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional

from .scope import _is_ip, normalize_host, normalize_network


def utc_now() -> str:
    # A single UTC representation keeps evidence timelines comparable.
    return datetime.now(timezone.utc).isoformat()


@dataclass
class RunConfig:
    # RunConfig is the execution policy: scope, mode, budgets, and persistence
    # paths are validated before the agent can invoke a tool.
    root_fqdn: str
    mode: str = "passive"
    authorized_hosts: List[str] = field(default_factory=list)
    authorized_networks: List[str] = field(default_factory=list)
    max_tool_calls: int = 25
    max_assets: int = 500
    max_permutations: int = 2000
    max_output_bytes: int = 16 * 1024 * 1024
    max_evidence_bytes: int = 64 * 1024 * 1024
    max_observations: int = 20_000
    max_observation_bytes: int = 256 * 1024
    max_normalized_bytes: int = 32 * 1024 * 1024
    max_dns_binding_age_seconds: int = 3600
    max_duration_seconds: int = 1800
    max_retries: int = 2
    rate_limit: int = 10
    dns_rate_limit: int = 50
    concurrency: int = 2
    database: str = "react-recon.db"
    evidence_dir: str = "evidence"
    # An empty value selects Executor's immutable per-tool image manifest.
    # A custom fallback is accepted only as a content-addressed digest.
    docker_image: str = ""

    def validate(self) -> None:
        if self.mode not in {"passive", "active"}:
            raise ValueError("mode must be passive or active")
        self.root_fqdn = normalize_host(self.root_fqdn)
        if _is_ip(self.root_fqdn) or "." not in self.root_fqdn:
            raise ValueError("root_fqdn must be a fully qualified domain name")
        self.authorized_hosts = [normalize_host(item) for item in self.authorized_hosts]
        self.authorized_networks = [normalize_network(item) for item in self.authorized_networks]
        if self.mode == "active" and not self.authorized_networks:
            raise ValueError(
                "active mode requires at least one authorized_network for port and service probing"
            )
        # Migrate the auto-selection sentinel stored by pre-hardening runs.
        # It is normalized before any executor can use it as an image name.
        if self.docker_image.rsplit(":", 1) == ["projectdiscovery/recon", "latest"]:
            self.docker_image = ""
        if self.docker_image and not re.fullmatch(r"[^@\s]+@sha256:[0-9a-fA-F]{64}", self.docker_image):
            raise ValueError("custom docker_image must be pinned by sha256 digest")
        # Active mode is an explicit operator assertion that the configured
        # root FQDN and its descendants are authorized. authorized_hosts remains
        # available for exact additional hosts outside that domain boundary.
        for name in (
            "max_tool_calls",
            "max_assets",
            "max_permutations",
            "max_output_bytes",
            "max_evidence_bytes",
            "max_observations",
            "max_observation_bytes",
            "max_normalized_bytes",
            "max_dns_binding_age_seconds",
            "max_duration_seconds",
            "max_retries",
            "rate_limit",
            "dns_rate_limit",
            "concurrency",
        ):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be positive")


@dataclass
class ToolResult:
    # Every adapter returns this common ledger shape, including failures and
    # skips, so missing observations are never ambiguous.
    tool: str
    status: str
    target: str
    stdout: str = ""
    stderr: str = ""
    return_code: Optional[int] = None
    command: str = ""
    started_at: str = field(default_factory=utc_now)
    finished_at: str = field(default_factory=utc_now)
    observations: List[Dict[str, Any]] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    runner: str = "host"


@dataclass
class Decision:
    # A decision is data validated by the controller, never executable code.
    tool: str
    arguments: Dict[str, Any]
    rationale: str = ""
    expected_observation: str = ""
    stop_condition: str = ""
