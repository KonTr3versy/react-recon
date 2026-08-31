from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


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
    max_tool_calls: int = 25
    max_assets: int = 500
    max_duration_seconds: int = 1800
    max_retries: int = 2
    rate_limit: int = 10
    concurrency: int = 2
    database: str = "react-recon.db"
    evidence_dir: str = "evidence"
    docker_image: str = "projectdiscovery/recon:latest"

    def validate(self) -> None:
        if self.mode not in {"passive", "active"}:
            raise ValueError("mode must be passive or active")
        if not self.root_fqdn or "." not in self.root_fqdn:
            raise ValueError("root_fqdn must be a fully qualified domain name")
        if self.mode == "active" and not self.authorized_hosts:
            raise ValueError("active mode requires authorized_hosts")
        for name in ("max_tool_calls", "max_assets", "max_duration_seconds", "max_retries", "rate_limit", "concurrency"):
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
