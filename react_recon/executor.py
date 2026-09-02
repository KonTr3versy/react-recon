from __future__ import annotations

import shutil
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional
from urllib.error import HTTPError, URLError

from .files import write_private_text
from .models import RunConfig, ToolResult, utc_now
from .parsers import (
    parse_alterx,
    parse_crtsh,
    parse_dnsx,
    parse_gau,
    parse_httpx,
    parse_naabu,
    parse_nmap,
    parse_subfinder,
)
from .runtime import BoundedProcessResult, run_bounded_process
from .scope import address_is_active_scan_authorized, address_is_authorized, in_scope, normalize_host


Parser = Callable[[str], List[dict]]


@dataclass
class InputBundle:
    temporary_directory: tempfile.TemporaryDirectory[str]
    input_file: str
    allow_file: str = ""
    config_file: str = ""

    @property
    def root(self) -> Path:
        return Path(self.temporary_directory.name).resolve()

    def cleanup(self) -> None:
        self.temporary_directory.cleanup()


class Executor:
    # These registries are the only route from a planner decision to an
    # external program. They make the execution boundary auditable.
    COMMANDS: Dict[str, str] = {
        "discover_subdomains": "subfinder",
        "resolve_dns": "dnsx",
        "probe_http": "httpx",
        "generate_permutations": "alterx",
        "resolve_permutations": "dnsx",
        "probe_permutation_http": "httpx",
        "discover_ports": "naabu",
        "retrieve_passive_urls": "gau",
    }
    PARSERS: Dict[str, Parser] = {
        "discover_subdomains": parse_subfinder,
        "resolve_dns": parse_dnsx,
        "probe_http": parse_httpx,
        "generate_permutations": parse_alterx,
        "resolve_permutations": parse_dnsx,
        "probe_permutation_http": parse_httpx,
        "discover_ports": parse_naabu,
        "retrieve_passive_urls": parse_gau,
    }
    BINARIES = ("subfinder", "dnsx", "httpx", "alterx", "naabu", "gau")
    # A run may last up to max_duration_seconds, but no individual collector
    # receives that complete budget. These fixed ceilings prevent one stalled
    # dependency from making the controller appear hung indefinitely.
    TOOL_TIMEOUT_SECONDS: Dict[str, int] = {
        "crtsh_search": 100,
        "discover_subdomains": 180,
        "resolve_dns": 180,
        "probe_http": 300,
        "generate_permutations": 60,
        "resolve_permutations": 180,
        "probe_permutation_http": 300,
        "discover_ports": 300,
        "retrieve_passive_urls": 120,
        "fingerprint_services": 300,
    }
    # Docker Hub manifest-list digests checked against the published image
    # repositories on 2026-08-31. Digests are architecture-neutral and
    # immutable; host-installed tool versions are pinned separately.
    DOCKER_IMAGES: Dict[str, str] = {
        "discover_subdomains": "projectdiscovery/subfinder@sha256:c0f4683f91e8e30fbb5bf45051ef45e245ef48424b0d5bc99f8a72cb45163ea9",
        "resolve_dns": "projectdiscovery/dnsx@sha256:8fced0bedf3655e06c9f1805f6277d60d4988a4b13209e24b3d7cde7baa656ec",
        "probe_http": "projectdiscovery/httpx@sha256:e2f89a700e535b3e0d5ccf95e3383ebb54c2faecd8e8100573455cd0cbe8e02d",
        "generate_permutations": "projectdiscovery/alterx@sha256:001bd5ba7ac4a94114a190622025f5288b5967980fe4e840b32e5f7f4cc77e96",
        "resolve_permutations": "projectdiscovery/dnsx@sha256:8fced0bedf3655e06c9f1805f6277d60d4988a4b13209e24b3d7cde7baa656ec",
        "probe_permutation_http": "projectdiscovery/httpx@sha256:e2f89a700e535b3e0d5ccf95e3383ebb54c2faecd8e8100573455cd0cbe8e02d",
        "discover_ports": "projectdiscovery/naabu@sha256:0b7efcd6eb4bf7be2c5cfb2bbfe091a132df0e442e549267bca818a4cef15ea4",
        "fingerprint_services": "instrumentisto/nmap@sha256:3cca6ece8de5a571c956022ec6c2cf343da8c4416fa36e1891e8c33623cfc845",
    }
    DESTINATION_TOOLS = {"probe_http", "probe_permutation_http", "discover_ports"}
    INPUT_TOOLS = {
        "resolve_dns",
        "probe_http",
        "generate_permutations",
        "resolve_permutations",
        "probe_permutation_http",
        "discover_ports",
    }

    def __init__(self, config: RunConfig) -> None:
        config.validate()
        self.config = config

    def execute(self, tool: str, arguments: Dict[str, object]) -> ToolResult:
        if tool == "crtsh_search":
            return self._crtsh_search(str(arguments.get("root_fqdn", "")))
        if tool == "fingerprint_services":
            return self._fingerprint_services(arguments)
        if tool not in self.COMMANDS:
            raise ValueError(f"unknown tool: {tool}")
        if tool in {"generate_permutations", "resolve_permutations", "probe_permutation_http", "discover_ports"} and self.config.mode != "active":
            return ToolResult(tool, "skipped", str(arguments), limitations=[f"{tool} is disabled in passive mode"])

        hosts = arguments.get("hosts") or []
        target = str(arguments.get("target") or arguments.get("root_fqdn") or (hosts[0] if isinstance(hosts, list) and hosts else ""))
        if tool in self.INPUT_TOOLS and (not isinstance(hosts, list) or not hosts):
            return ToolResult(tool, "skipped", target, limitations=["no eligible hosts were available for this baseline step"])
        if tool in self.INPUT_TOOLS:
            for host in hosts:
                normalized_host = normalize_host(str(host))
                if not in_scope(normalized_host, self.config.root_fqdn, self.config.authorized_hosts):
                    return ToolResult(tool, "skipped", str(host), limitations=[f"out-of-scope target: {host}"])

        approved_addresses: Dict[str, List[str]] = {}
        if tool in self.DESTINATION_TOOLS:
            approved_addresses = self._approved_address_map(
                hosts,
                arguments.get("approved_addresses"),
                active_scan=(tool == "discover_ports"),
            )
            if not approved_addresses or set(approved_addresses) != {normalize_host(str(host)) for host in hosts}:
                return ToolResult(tool, "skipped", target, limitations=["no complete approved hostname/IP mapping was available"])
        if tool in {"probe_http", "probe_permutation_http"}:
            return self._probe_http_bound(tool, approved_addresses)

        bundle: Optional[InputBundle] = None
        limitations: List[str] = []
        try:
            # The controller creates a dedicated private input bundle; planner
            # supplied paths are ignored and never mounted into a container.
            bundle = self._materialize_input(tool, hosts, approved_addresses)
            command_arguments = dict(arguments)
            if bundle:
                command_arguments.update({
                    "input_file": bundle.input_file,
                    "allow_file": bundle.allow_file,
                    "config_file": bundle.config_file,
                })
            command = self._command(tool, command_arguments)
            binary = shutil.which(command[0])
            runner = "host"
            if binary:
                command[0] = binary
            else:
                docker = shutil.which("docker")
                if docker is None:
                    return ToolResult(tool, "failed", target, command=" ".join(command), stderr=f"missing executable: {command[0]} and docker fallback unavailable")
                if tool == "retrieve_passive_urls":
                    return ToolResult(tool, "failed", target, command=" ".join(command), stderr="missing executable: gau; install gau on the host")
                image = self.config.docker_image or self.DOCKER_IMAGES[tool]
                command = self._docker_command(image, command, bundle, docker)
                runner = "docker"

            started = utc_now()
            start_time = time.monotonic()
            try:
                completed = self._run_command(command, self.tool_timeout_seconds(tool))
            except OSError as exc:
                return ToolResult(tool, "failed", target, stderr=str(exc), command=" ".join(command), runner=runner)

            status = "success" if completed.returncode == 0 else "failed"
            if completed.timed_out:
                status = "failed"
                limitations.append(
                    f"tool execution timed out after {self.tool_timeout_seconds(tool)} seconds"
                )
            if completed.output_limited:
                status = "failed"
                limitations.append(f"tool output exceeded {self.config.max_output_bytes} bytes")
            stdout, stderr = completed.stdout, completed.stderr
            observations = self.PARSERS[tool](stdout) if status == "success" else []

            if tool == "generate_permutations":
                seeds = {normalize_host(str(host)) for host in hosts}
                observations = [
                    item for item in observations
                    if item.get("value") not in seeds
                    and in_scope(str(item.get("value", "")), self.config.root_fqdn, self.config.authorized_hosts)
                ][: self.config.max_permutations]
            elif tool == "discover_ports":
                observations, rejected = self._remap_naabu_observations(observations, approved_addresses)
                if rejected:
                    status = "failed"
                    limitations.append(f"rejected {rejected} Naabu observations outside the approved IP set")

            if len(observations) > self.config.max_observations:
                status = "failed"
                observations = []
                limitations.append(f"tool observations exceeded the run ceiling of {self.config.max_observations}")
            limitations.append(f"duration_seconds={time.monotonic()-start_time:.3f}")
            target_outcomes = []
            if tool in {"resolve_dns", "resolve_permutations"}:
                outcome_status = "completed" if status == "success" else "failed"
                target_outcomes = [
                    {
                        "host": normalize_host(str(host)),
                        "status": outcome_status,
                    }
                    for host in hosts
                ]
            return ToolResult(
                tool,
                status,
                target,
                stdout,
                stderr,
                completed.returncode,
                " ".join(command),
                started,
                utc_now(),
                observations,
                limitations,
                runner,
                target_outcomes=target_outcomes,
            )
        finally:
            if bundle:
                bundle.cleanup()

    def _run_command(self, command: List[str], timeout: int) -> BoundedProcessResult:
        return run_bounded_process(command, timeout, self.config.max_output_bytes)

    def tool_timeout_seconds(self, tool: str) -> int:
        """Return the fixed tool ceiling clamped to the complete run budget."""
        configured = self.TOOL_TIMEOUT_SECONDS.get(
            tool, self.config.max_duration_seconds
        )
        return max(1, min(configured, self.config.max_duration_seconds))

    @classmethod
    def collector_name(cls, tool: str) -> str:
        if tool == "crtsh_search":
            return "crt.sh"
        if tool == "fingerprint_services":
            return "nmap"
        return cls.COMMANDS.get(tool, tool)

    def _probe_http_bound(self, tool: str, approved: Dict[str, List[str]]) -> ToolResult:
        """Probe hosts in groups that share the exact same approved IP set.

        A single run-wide httpx allowlist permits one hostname to resolve to an
        address approved for a different hostname. Grouping by identical
        bindings preserves batching where it is safe while ensuring every
        process receives only the addresses approved for all of its inputs.
        """
        groups: Dict[tuple[str, ...], List[str]] = {}
        for host, addresses in sorted(approved.items()):
            groups.setdefault(tuple(sorted(addresses)), []).append(host)

        binary = shutil.which(self.COMMANDS[tool])
        docker = shutil.which("docker") if binary is None else None
        if binary is None and docker is None:
            return ToolResult(
                tool,
                "failed",
                ",".join(sorted(approved)),
                stderr=f"missing executable: {self.COMMANDS[tool]} and docker fallback unavailable",
            )

        started = utc_now()
        started_monotonic = time.monotonic()
        outputs: List[str] = []
        errors: List[str] = []
        observations: List[dict] = []
        commands: List[str] = []
        limitations: List[str] = [f"hostname_ip_binding_groups={len(groups)}"]
        completed_groups = 0
        failed_groups = 0
        stdout_bytes = 0
        stderr_bytes = 0
        stdout_characters = 0
        aggregate_limited = False
        observation_limited = False
        target_status = {host: "unattempted" for host in approved}
        target_output: Dict[str, Dict[str, int]] = {}

        tool_timeout = self.tool_timeout_seconds(tool)
        for addresses, group_hosts in groups.items():
            if time.monotonic() - started_monotonic >= tool_timeout:
                failed_groups += 1
                limitations.append("HTTP probe duration budget exhausted")
                break
            group_approved = {host: list(addresses) for host in group_hosts}
            bundle = self._materialize_input(tool, group_hosts, group_approved)
            if bundle is None:
                failed_groups += 1
                for host in group_hosts:
                    target_status[host] = "failed"
                continue
            try:
                command = self._command(
                    tool,
                    {"input_file": bundle.input_file, "allow_file": bundle.allow_file},
                )
                if binary:
                    command[0] = binary
                else:
                    command = self._docker_command(
                        self.config.docker_image or self.DOCKER_IMAGES[tool],
                        command,
                        bundle,
                        str(docker),
                    )
                commands.append(" ".join(command))
                remaining = max(
                    1,
                    tool_timeout
                    - int(time.monotonic() - started_monotonic),
                )
                try:
                    completed = self._run_command(command, remaining)
                except OSError as exc:
                    failed_groups += 1
                    for host in group_hosts:
                        target_status[host] = "failed"
                    errors.append(f"{','.join(group_hosts)}: {exc}")
                    continue

                stdout_piece = completed.stdout
                stderr_piece = (
                    f"{','.join(group_hosts)}: {completed.stderr.strip()}"
                    if completed.stderr
                    else ""
                )
                stdout_piece_bytes = len(stdout_piece.encode("utf-8")) + (1 if outputs else 0)
                stderr_piece_bytes = len(stderr_piece.encode("utf-8")) + (
                    1 if errors and stderr_piece else 0
                )
                if (
                    stdout_bytes + stdout_piece_bytes > self.config.max_output_bytes
                    or stderr_bytes + stderr_piece_bytes > self.config.max_output_bytes
                ):
                    aggregate_limited = True
                    failed_groups += 1
                    for host in group_hosts:
                        target_status[host] = "failed"
                    break
                stdout_start = stdout_characters + (1 if outputs else 0)
                stdout_end = stdout_start + len(stdout_piece)
                outputs.append(stdout_piece)
                stdout_characters = stdout_end
                for host in group_hosts:
                    target_output[host] = {
                        "stdout_start": stdout_start,
                        "stdout_end": stdout_end,
                    }
                stdout_bytes += stdout_piece_bytes
                if stderr_piece:
                    errors.append(stderr_piece)
                    stderr_bytes += stderr_piece_bytes

                if completed.timed_out:
                    failed_groups += 1
                    for host in group_hosts:
                        target_status[host] = "failed"
                    limitations.append(f"HTTP probe timed out for {','.join(group_hosts)}")
                    continue
                if completed.output_limited:
                    failed_groups += 1
                    aggregate_limited = True
                    for host in group_hosts:
                        target_status[host] = "failed"
                    limitations.append(f"HTTP output exceeded {self.config.max_output_bytes} bytes")
                    break
                if completed.returncode != 0:
                    failed_groups += 1
                    for host in group_hosts:
                        target_status[host] = "failed"
                    continue

                parsed, rejected = self._validate_http_observations(
                    parse_httpx(completed.stdout), group_approved
                )
                if rejected:
                    failed_groups += 1
                    for host in group_hosts:
                        target_status[host] = "failed"
                    limitations.append(
                        f"rejected {rejected} HTTP observations outside the bound addresses for {','.join(group_hosts)}"
                    )
                    continue
                if len(observations) + len(parsed) > self.config.max_observations:
                    failed_groups += 1
                    observation_limited = True
                    for host in group_hosts:
                        target_status[host] = "failed"
                    limitations.append(
                        f"HTTP observations exceeded the run ceiling of {self.config.max_observations}"
                    )
                    observations = []
                    break
                observations.extend(parsed)
                completed_groups += 1
                for host in group_hosts:
                    target_status[host] = "completed"
            finally:
                bundle.cleanup()

        if aggregate_limited or observation_limited:
            observations = []
            for host, state in target_status.items():
                if state == "completed":
                    target_status[host] = "failed"
        if aggregate_limited:
            limitations.append(
                f"aggregate HTTP output exceeded {self.config.max_output_bytes} bytes"
            )
        status = (
            "success"
            if completed_groups == len(groups) and failed_groups == 0
            else "failed"
        )
        limitations.extend(
            [
                f"probed_binding_groups={completed_groups}/{len(groups)}",
                f"duration_seconds={time.monotonic()-started_monotonic:.3f}",
            ]
        )
        return ToolResult(
            tool,
            status,
            ",".join(sorted(approved)),
            "\n".join(outputs),
            "\n".join(errors),
            0 if status == "success" else 1,
            " ; ".join(commands),
            started,
            utc_now(),
            observations,
            limitations,
            "host" if binary else "docker",
            target_outcomes=[
                {
                    "host": host,
                    "addresses": sorted(approved[host]),
                    "status": target_status[host],
                    **target_output.get(host, {}),
                }
                for host in sorted(target_status)
            ],
        )

    def _crtsh_search(self, root_fqdn: str) -> ToolResult:
        if not root_fqdn:
            raise ValueError("crt.sh search requires root_fqdn")
        url = "https://crt.sh/?" + urllib.parse.urlencode({"q": "%." + root_fqdn, "output": "json"})
        started = utc_now()
        attempts = 0
        stdout, status, code, stderr = "", "failed", None, ""
        limitations = ["Certificate Transparency names are candidates and require DNS/HTTP validation."]
        for attempt in range(self.config.max_retries + 1):
            attempts = attempt + 1
            try:
                request = urllib.request.Request(url, headers={"User-Agent": "react-recon/0.1"})
                with urllib.request.urlopen(request, timeout=30) as response:
                    body = response.read(self.config.max_output_bytes + 1)
                if len(body) > self.config.max_output_bytes:
                    stderr = f"crt.sh response exceeded {self.config.max_output_bytes} bytes"
                    limitations.append(stderr)
                    break
                stdout = body.decode("utf-8", errors="replace")
                status, code, stderr = "success", 0, ""
                break
            except HTTPError as exc:
                stderr = str(exc)
                code = exc.code
                if exc.code != 429 and exc.code < 500:
                    break
            except (URLError, TimeoutError, OSError) as exc:
                stderr = str(exc)
            if attempt < self.config.max_retries:
                time.sleep(min(2**attempt, 4))
        observations = parse_crtsh(stdout) if status == "success" else []
        observations = [item for item in observations if in_scope(str(item.get("value", "")), root_fqdn, [])]
        if len(observations) > self.config.max_observations:
            status = "failed"
            observations = []
            limitations.append(f"crt.sh observations exceeded the run ceiling of {self.config.max_observations}")
        limitations.append(f"attempts={attempts}")
        return ToolResult("crtsh_search", status, root_fqdn, stdout, stderr, code, "GET " + url, started, utc_now(), observations, limitations, "host")

    def _fingerprint_services(self, arguments: Dict[str, object]) -> ToolResult:
        """Run version-light Nmap against exact Naabu hostname/IP/port tuples."""
        targets = arguments.get("targets") or []
        if self.config.mode != "active":
            return ToolResult("fingerprint_services", "skipped", str(targets), limitations=["service fingerprinting is disabled in passive mode"])
        if not isinstance(targets, list) or not targets:
            return ToolResult("fingerprint_services", "skipped", "", limitations=["no normalized open ports available for service fingerprinting"])

        normalized_targets: List[tuple[str, str, List[int]]] = []
        seen_targets: set[tuple[str, str, tuple[int, ...]]] = set()
        for item in targets:
            if not isinstance(item, dict):
                continue
            try:
                host = normalize_host(str(item.get("host", "")))
                address = normalize_host(str(item.get("ip", "")))
            except ValueError:
                continue
            raw_ports = item.get("ports", [])
            if not isinstance(raw_ports, list):
                continue
            ports = sorted({int(port) for port in raw_ports if str(port).isdigit() and 1 <= int(port) <= 65535})
            if not in_scope(host, self.config.root_fqdn, self.config.authorized_hosts) or not address_is_active_scan_authorized(address, self.config.authorized_networks) or not ports:
                continue
            key = (host, address, tuple(ports))
            if key not in seen_targets:
                seen_targets.add(key)
                normalized_targets.append((host, address, ports))
        if not normalized_targets:
            return ToolResult("fingerprint_services", "skipped", "", limitations=["no eligible hostname/IP/port tuples available"])
        if len(normalized_targets) > self.config.max_assets:
            return ToolResult(
                "fingerprint_services",
                "failed",
                "",
                limitations=[f"fingerprint target count exceeded the run ceiling of {self.config.max_assets}"],
            )

        nmap = shutil.which("nmap")
        docker = shutil.which("docker")
        if nmap is None and docker is None:
            return ToolResult("fingerprint_services", "failed", ",".join(host for host, _, _ in normalized_targets), stderr="missing executable: nmap and docker fallback unavailable")

        started = utc_now()
        started_monotonic = time.monotonic()
        outputs: List[str] = []
        errors: List[str] = []
        observations: List[dict] = []
        commands: List[str] = []
        runner = "host" if nmap else "docker"
        successes = 0
        stdout_bytes = 0
        stderr_bytes = 0
        stdout_characters = 0
        aggregate_limited = False
        observation_limited = False
        target_status = {
            (host, address, tuple(ports)): "unattempted"
            for host, address, ports in normalized_targets
        }
        target_output: Dict[tuple[str, str, tuple[int, ...]], Dict[str, int]] = {}
        tool_timeout = self.tool_timeout_seconds("fingerprint_services")
        for host, address, ports in normalized_targets:
            outcome_key = (host, address, tuple(ports))
            if time.monotonic() - started_monotonic >= tool_timeout:
                break
            # -n and an explicit IP eliminate the prior DNS TOCTOU. -sT keeps
            # Docker fallback compatible with a cap-drop=ALL container.
            nmap_args = ["-n", "-Pn", "-sT", "-sV", "--version-light", "-oX", "-", "-p", ",".join(str(port) for port in ports)]
            if ":" in address:
                nmap_args.append("-6")
            nmap_args.append(address)
            command = [str(nmap), *nmap_args] if nmap else self._docker_command(self.DOCKER_IMAGES["fingerprint_services"], ["nmap", *nmap_args], None, str(docker))
            commands.append(" ".join(command))
            remaining = max(
                1,
                tool_timeout - int(time.monotonic() - started_monotonic),
            )
            try:
                completed = self._run_command(command, remaining)
            except OSError as exc:
                target_status[outcome_key] = "failed"
                errors.append(f"{host}[{address}]: {exc}")
                continue
            stdout_piece = completed.stdout
            stderr_piece = f"{host}[{address}]: {completed.stderr.strip()}" if completed.stderr else ""
            stdout_piece_bytes = len(stdout_piece.encode("utf-8")) + (1 if outputs else 0)
            stderr_piece_bytes = len(stderr_piece.encode("utf-8")) + (1 if errors and stderr_piece else 0)
            if stdout_bytes + stdout_piece_bytes > self.config.max_output_bytes or stderr_bytes + stderr_piece_bytes > self.config.max_output_bytes:
                aggregate_limited = True
                target_status[outcome_key] = "failed"
                break
            stdout_start = stdout_characters + (1 if outputs else 0)
            stdout_end = stdout_start + len(stdout_piece)
            outputs.append(stdout_piece)
            stdout_characters = stdout_end
            target_output[outcome_key] = {
                "stdout_start": stdout_start,
                "stdout_end": stdout_end,
            }
            stdout_bytes += stdout_piece_bytes
            if stderr_piece:
                errors.append(stderr_piece)
                stderr_bytes += stderr_piece_bytes
            if completed.timed_out:
                target_status[outcome_key] = "failed"
                errors.append(f"{host}[{address}]: timeout")
                break
            if completed.output_limited:
                target_status[outcome_key] = "failed"
                aggregate_limited = True
                errors.append(f"{host}[{address}]: output limit exceeded")
                break
            if completed.returncode == 0:
                parsed = parse_nmap(completed.stdout)
                if len(observations) + len(parsed) > self.config.max_observations:
                    target_status[outcome_key] = "failed"
                    observation_limited = True
                    break
                for observation in parsed:
                    observation["host"] = host
                    observation["ip"] = address
                    observation["addresses"] = [address]
                    observations.append(observation)
                target_status[outcome_key] = "completed"
                successes += 1
            else:
                target_status[outcome_key] = "failed"

        status = "success" if successes == len(normalized_targets) and not aggregate_limited and not observation_limited else "failed"
        limitations = [f"fingerprinted_targets={successes}/{len(normalized_targets)}", f"duration_seconds={time.monotonic()-started_monotonic:.3f}"]
        if aggregate_limited:
            observations = []
            for key, state in target_status.items():
                if state == "completed":
                    target_status[key] = "failed"
            limitations.append(f"aggregate Nmap output exceeded {self.config.max_output_bytes} bytes")
        if observation_limited:
            observations = []
            for key, state in target_status.items():
                if state == "completed":
                    target_status[key] = "failed"
            limitations.append(f"Nmap observations exceeded the run ceiling of {self.config.max_observations}")
        return ToolResult(
            "fingerprint_services",
            status,
            ",".join(
                f"{host}[{address}]" for host, address, _ in normalized_targets
            ),
            "\n".join(outputs),
            "\n".join(errors),
            0 if status == "success" else 1,
            " ; ".join(commands),
            started,
            utc_now(),
            observations,
            limitations,
            runner,
            target_outcomes=[
                {
                    "host": host,
                    "ip": address,
                    "ports": ports,
                    "status": target_status[(host, address, tuple(ports))],
                    **target_output.get((host, address, tuple(ports)), {}),
                }
                for host, address, ports in normalized_targets
            ],
        )

    def _approved_address_map(
        self,
        hosts: List[object],
        raw: object,
        *,
        active_scan: bool = False,
    ) -> Dict[str, List[str]]:
        if not isinstance(raw, dict):
            return {}
        approved: Dict[str, List[str]] = {}
        host_set = {normalize_host(str(host)) for host in hosts}
        for raw_host, raw_addresses in raw.items():
            try:
                host = normalize_host(str(raw_host))
            except ValueError:
                continue
            if host not in host_set or not isinstance(raw_addresses, list):
                continue
            addresses: List[str] = []
            for raw_address in raw_addresses:
                try:
                    address = normalize_host(str(raw_address))
                except ValueError:
                    continue
                destination_allowed = (
                    address_is_active_scan_authorized(
                        address, self.config.authorized_networks
                    )
                    if active_scan
                    else address_is_authorized(
                        address, self.config.authorized_networks
                    )
                )
                if destination_allowed:
                    addresses.append(address)
            if addresses:
                approved[host] = sorted(set(addresses))
        return approved

    def _validate_http_observations(self, observations: List[dict], approved: Dict[str, List[str]]) -> tuple[List[dict], int]:
        accepted: List[dict] = []
        rejected = 0
        for observation in observations:
            if observation.get("type") != "http_service":
                accepted.append(observation)
                continue
            metadata = observation.get("metadata") if isinstance(observation.get("metadata"), dict) else {}
            raw_host = metadata.get("input") or metadata.get("host")
            raw_address = metadata.get("host_ip") or metadata.get("ip")
            try:
                host = normalize_host(str(raw_host or ""))
                address = normalize_host(str(raw_address or ""))
            except ValueError:
                rejected += 1
                continue
            if address not in approved.get(host, []):
                rejected += 1
                continue
            accepted.append(observation)
        return accepted, rejected

    def _remap_naabu_observations(self, observations: List[dict], approved: Dict[str, List[str]]) -> tuple[List[dict], int]:
        hosts_by_address: Dict[str, List[str]] = {}
        for host, addresses in approved.items():
            for address in addresses:
                hosts_by_address.setdefault(address, []).append(host)
        remapped: List[dict] = []
        rejected = 0
        for observation in observations:
            raw_address = observation.get("ip") or observation.get("host")
            try:
                address = normalize_host(str(raw_address or ""))
            except ValueError:
                rejected += 1
                continue
            mapped_hosts = hosts_by_address.get(address, [])
            if not mapped_hosts:
                rejected += 1
                continue
            for host in mapped_hosts:
                remapped.append({**observation, "host": host, "ip": address})
        return remapped, rejected

    def _materialize_input(self, tool: str, hosts: List[object], approved_addresses: Dict[str, List[str]]) -> Optional[InputBundle]:
        if tool not in self.INPUT_TOOLS or not hosts:
            return None
        temporary_directory = tempfile.TemporaryDirectory(prefix="react-recon-")
        root = Path(temporary_directory.name)
        root.chmod(0o700)
        values = sorted({address for addresses in approved_addresses.values() for address in addresses}) if tool == "discover_ports" else [normalize_host(str(host)) for host in hosts]
        input_path = root / "targets.txt"
        write_private_text(input_path, "\n".join(values) + "\n")
        allow_file = ""
        if tool in {"probe_http", "probe_permutation_http"}:
            allow_path = root / "approved-ips.txt"
            allowed = sorted({address for addresses in approved_addresses.values() for address in addresses})
            write_private_text(allow_path, "\n".join(allowed) + "\n")
            allow_file = str(allow_path)
        config_file = ""
        if tool == "generate_permutations":
            source = Path(__file__).with_name("data") / "alterx-conservative.yaml"
            config_path = root / "alterx-conservative.yaml"
            write_private_text(config_path, source.read_text(encoding="utf-8"))
            config_file = str(config_path)
        return InputBundle(temporary_directory, str(input_path), allow_file, config_file)

    def _docker_command(self, image: str, command: List[str], bundle: Optional[InputBundle], docker_binary: str = "docker") -> List[str]:
        executable = Path(command[0]).name if command else ""
        image_name = image.split("@", 1)[0]
        image_entrypoint = (
            image_name == f"projectdiscovery/{executable}"
            or (image_name == "instrumentisto/nmap" and executable == "nmap")
        )
        container_command = command[1:] if image_entrypoint else command
        runtime = [docker_binary, "run", "--rm", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--env", "HOME=/tmp"]
        if not bundle:
            return [*runtime, image, *container_command]
        rewritten: List[str] = []
        for item in container_command:
            try:
                candidate = Path(item).resolve()
            except (OSError, ValueError):
                candidate = Path("/")
            rewritten.append(f"/workspace/{candidate.name}" if candidate.parent == bundle.root else item)
        return [*runtime, "-v", f"{bundle.root}:/workspace:ro", "-w", "/workspace", image, *rewritten]

    def _command(self, tool: str, arguments: Dict[str, object]) -> List[str]:
        binary = self.COMMANDS[tool]
        if tool == "discover_subdomains":
            return [binary, "-d", str(arguments["root_fqdn"]), "-json", "-silent"]
        if tool in {"resolve_dns", "resolve_permutations"}:
            return self._dnsx_command(binary, str(arguments.get("input_file", "")))
        if tool in {"probe_http", "probe_permutation_http"}:
            response_limit = str(min(self.config.max_output_bytes, 1024 * 1024))
            return [binary, "-l", str(arguments.get("input_file", "")), "-allow", str(arguments.get("allow_file", "")), "-j", "-silent", "-no-stdin", "-duc", "-no-fallback", "-title", "-sc", "-cl", "-ct", "-location", "-server", "-td", "-rt", "-ip", "-cname", "-asn", "-tls-grab", "-favicon", "-jarm", "-hash", "sha256", "-rstr", response_limit, "-rsts", response_limit, "-rl", str(self.config.rate_limit)]
        if tool == "generate_permutations":
            return [binary, "-l", str(arguments.get("input_file", "")), "-ac", str(arguments.get("config_file", "")), "-limit", str(self.config.max_permutations), "-silent"]
        if tool == "discover_ports":
            return [binary, "-list", str(arguments.get("input_file", "")), "-json", "-silent", "-no-stdin", "-duc", "-verify", "-cdn", "-rate", str(self.config.rate_limit)]
        return [binary, str(arguments["root_fqdn"]), "--json"]

    def _dnsx_command(self, binary: str, input_file: str) -> List[str]:
        return [binary, "-l", input_file, "-a", "-aaaa", "-cname", "-cdn", "-asn", "-auto-wildcard", "-j", "-omit-raw", "-silent", "-retry", str(self.config.max_retries), "-t", str(self.config.concurrency), "-rl", str(self.config.dns_rate_limit)]
