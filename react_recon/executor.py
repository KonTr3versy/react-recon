from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from urllib.error import HTTPError, URLError
from pathlib import Path
from typing import Callable, Dict, List

from .models import RunConfig, ToolResult, utc_now
from .parsers import parse_crtsh, parse_dnsx, parse_gau, parse_httpx, parse_naabu, parse_nmap, parse_subfinder
from .scope import in_scope, normalize_host


Parser = Callable[[str], List[dict]]


class Executor:
    # These registries are the only route from a planner decision to an
    # external program. They make the execution boundary auditable.
    COMMANDS: Dict[str, str] = {"discover_subdomains": "subfinder", "resolve_dns": "dnsx", "probe_http": "httpx", "discover_ports": "naabu", "retrieve_passive_urls": "gau"}
    PARSERS: Dict[str, Parser] = {"discover_subdomains": parse_subfinder, "resolve_dns": parse_dnsx, "probe_http": parse_httpx, "discover_ports": parse_naabu, "retrieve_passive_urls": parse_gau}

    def __init__(self, config: RunConfig) -> None:
        self.config = config

    def execute(self, tool: str, arguments: Dict[str, object]) -> ToolResult:
        # crt.sh is a fixed HTTPS collector, not an arbitrary network or shell
        # tool exposed to the model.
        if tool == "crtsh_search":
            return self._crtsh_search(str(arguments.get("root_fqdn", "")))
        if tool == "fingerprint_services":
            return self._fingerprint_services(arguments)
        if tool not in self.COMMANDS:
            raise ValueError(f"unknown tool: {tool}")
        if tool == "discover_ports" and self.config.mode != "active":
            return ToolResult(tool, "skipped", str(arguments), limitations=["active port discovery is disabled in passive mode"])
        hosts = arguments.get("hosts") or []
        target = str(arguments.get("target") or arguments.get("root_fqdn") or (hosts[0] if isinstance(hosts, list) and hosts else ""))
        if tool in {"resolve_dns", "probe_http", "discover_ports"} and (not isinstance(hosts, list) or not hosts):
            return ToolResult(tool, "skipped", target, limitations=["no eligible hosts were available for this baseline step"])
        if tool in {"probe_http", "discover_ports"}:
            # Passive scope allows discovery candidates; active execution also
            # requires each target to appear in the explicit authorization list.
            hosts = hosts or [target]
            for host in hosts if isinstance(hosts, list) else [hosts]:
                normalized_host = normalize_host(str(host))
                explicitly_authorized = normalized_host in {normalize_host(item) for item in self.config.authorized_hosts}
                if not in_scope(normalized_host, self.config.root_fqdn, self.config.authorized_hosts) or (self.config.mode == "active" and not explicitly_authorized):
                    return ToolResult(tool, "skipped", str(host), limitations=[f"out-of-scope target: {host}"])
        # The controller creates input files from normalized state; planner
        # supplied paths are never trusted.
        temporary_input = self._materialize_input(tool, arguments)
        command = self._command(tool, {**arguments, **({"input_file": temporary_input} if temporary_input else {})})
        binary = shutil.which(command[0])
        runner = "host"
        # Prefer host-installed tools, then use Docker as a reproducible
        # fallback when the host binary is unavailable.
        if binary is None:
            if shutil.which("docker") is None:
                if temporary_input:
                    Path(temporary_input).unlink(missing_ok=True)
                return ToolResult(tool, "failed", target, command=" ".join(command), stderr=f"missing executable: {command[0]} and docker fallback unavailable")
            image = self.config.docker_image
            if image == "projectdiscovery/recon:latest":
                # gau is not a ProjectDiscovery image. Fail clearly instead of
                # attempting to pull a misleading projectdiscovery/gau image.
                if tool == "retrieve_passive_urls":
                    return ToolResult(tool, "failed", target, command=" ".join(command), stderr="missing executable: gau; install gau on the host")
                image = f"projectdiscovery/{self.COMMANDS[tool]}:latest"
            command = self._docker_command(image, command, temporary_input)
            runner = "docker"
        started = utc_now()
        start_time = time.monotonic()
        try:
            # Direct argv execution avoids a shell. Preserve both streams and
            # classify timeouts as collection failures, not security results.
            completed = subprocess.run(command, capture_output=True, text=True, timeout=self.config.max_duration_seconds, check=False)
            status = "success" if completed.returncode == 0 else "failed"
            stdout, stderr, code = completed.stdout, completed.stderr, completed.returncode
        except subprocess.TimeoutExpired as exc:
            status, stdout, stderr, code = "failed", exc.stdout or "", "timeout", None
        finished = utc_now()
        observations = self.PARSERS[tool](stdout) if status == "success" else []
        if temporary_input:
            try:
                Path(temporary_input).unlink()
            except OSError:
                pass
        return ToolResult(tool, status, target, stdout, stderr, code, " ".join(command), started, finished, observations, [f"duration_seconds={time.monotonic()-start_time:.3f}"], runner)

    def _crtsh_search(self, root_fqdn: str) -> ToolResult:
        # Certificate Transparency names are discovery candidates; DNS and
        # HTTP validation determine whether they are currently live.
        if not root_fqdn:
            raise ValueError("crt.sh search requires root_fqdn")
        # urlencode performs the percent-encoding. Supplying "%25." here
        # would double-encode crt.sh's wildcard and produce a 404 response.
        url = "https://crt.sh/?" + urllib.parse.urlencode({"q": "%." + root_fqdn, "output": "json"})
        started = utc_now()
        attempts = 0
        stdout, status, code, stderr = "", "failed", None, ""
        for attempt in range(self.config.max_retries + 1):
            attempts = attempt + 1
            try:
                request = urllib.request.Request(url, headers={"User-Agent": "react-recon/0.1"})
                with urllib.request.urlopen(request, timeout=30) as response:
                    stdout = response.read().decode("utf-8", errors="replace")
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
                time.sleep(min(2 ** attempt, 4))
        observations = parse_crtsh(stdout) if status == "success" else []
        observations = [item for item in observations if in_scope(str(item.get("value", "")), root_fqdn, [])]
        return ToolResult("crtsh_search", status, root_fqdn, stdout, stderr, code, "GET " + url, started, utc_now(), observations, ["Certificate Transparency names are candidates and require DNS/HTTP validation.", f"attempts={attempts}"], "host")

    def _fingerprint_services(self, arguments: Dict[str, object]) -> ToolResult:
        """Run version-light Nmap only against already discovered host/ports."""
        targets = arguments.get("targets") or []
        if self.config.mode != "active":
            return ToolResult("fingerprint_services", "skipped", str(targets), limitations=["service fingerprinting is disabled in passive mode"])
        if not isinstance(targets, list) or not targets:
            return ToolResult("fingerprint_services", "skipped", "", limitations=["no normalized open ports available for service fingerprinting"])

        authorized = {normalize_host(item) for item in self.config.authorized_hosts}
        normalized_targets = []
        for item in targets:
            if not isinstance(item, dict):
                continue
            try:
                host = normalize_host(str(item.get("host", "")))
            except ValueError:
                continue
            raw_ports = item.get("ports", [])
            if not isinstance(raw_ports, list):
                continue
            ports = sorted({int(port) for port in raw_ports if str(port).isdigit() and 1 <= int(port) <= 65535})
            if host not in authorized or not ports:
                continue
            normalized_targets.append((host, ports))
        if not normalized_targets:
            return ToolResult("fingerprint_services", "skipped", "", limitations=["no explicitly authorized host/port pairs available"])

        binary = shutil.which("nmap")
        docker = shutil.which("docker")
        if binary is None and docker is None:
            return ToolResult("fingerprint_services", "failed", ",".join(host for host, _ in normalized_targets), stderr="missing executable: nmap and docker fallback unavailable")

        started = utc_now()
        started_monotonic = time.monotonic()
        outputs: List[str] = []
        errors: List[str] = []
        observations: List[dict] = []
        commands: List[str] = []
        runner = "host" if binary else "docker"
        successes = 0
        for host, ports in normalized_targets:
            nmap_args = ["-Pn", "-sV", "--version-light", "-oX", "-", "-p", ",".join(str(port) for port in ports), host]
            command = ["nmap"] + nmap_args if binary else ["docker", "run", "--rm", "instrumentisto/nmap:latest"] + nmap_args
            commands.append(" ".join(command))
            remaining = max(1, self.config.max_duration_seconds - int(time.monotonic() - started_monotonic))
            try:
                completed = subprocess.run(command, capture_output=True, text=True, timeout=remaining, check=False)
            except subprocess.TimeoutExpired:
                errors.append(f"{host}: timeout")
                break
            outputs.append(completed.stdout)
            if completed.stderr:
                errors.append(f"{host}: {completed.stderr.strip()}")
            if completed.returncode == 0:
                successes += 1
                observations.extend(parse_nmap(completed.stdout))
        status = "success" if successes else "failed"
        return ToolResult(
            "fingerprint_services",
            status,
            ",".join(host for host, _ in normalized_targets),
            "\n".join(outputs),
            "\n".join(errors),
            0 if status == "success" else 1,
            " ; ".join(commands),
            started,
            utc_now(),
            observations,
            [f"fingerprinted_targets={successes}/{len(normalized_targets)}", f"duration_seconds={time.monotonic()-started_monotonic:.3f}"],
            runner,
        )

    def _materialize_input(self, tool: str, arguments: Dict[str, object]) -> str:
        # Short-lived line-delimited files bridge normalized state to tools that
        # require an input list and are deleted after execution.
        if tool not in {"resolve_dns", "probe_http", "discover_ports"} or arguments.get("input_file"):
            return ""
        hosts = arguments.get("hosts") or []
        if not isinstance(hosts, list) or not hosts:
            return ""
        handle = tempfile.NamedTemporaryFile(mode="w", prefix="react-recon-", suffix=".txt", delete=False)
        with handle:
            handle.write("\n".join(str(host) for host in hosts) + "\n")
        return handle.name

    def _docker_command(self, image: str, command: List[str], temporary_input: str) -> List[str]:
        # Expose only the temporary input directory to the fallback container.
        if not temporary_input:
            return ["docker", "run", "--rm", image] + command
        path = Path(temporary_input).resolve()
        container_path = f"/workspace/{path.name}"
        rewritten = [container_path if item == str(path) else item for item in command]
        return ["docker", "run", "--rm", "-v", f"{path.parent}:/workspace", "-w", "/workspace", image] + rewritten

    def _command(self, tool: str, arguments: Dict[str, object]) -> List[str]:
        # These explicit flags match the installed tool interfaces; re-check
        # each tool's --help output when upgrading versions.
        binary = self.COMMANDS[tool]
        if tool == "discover_subdomains":
            return [binary, "-d", str(arguments["root_fqdn"]), "-json", "-silent"]
        if tool == "resolve_dns":
            return [binary, "-l", str(arguments.get("input_file", "")), "-j", "-silent"]
        if tool == "probe_http":
            return [binary, "-l", str(arguments.get("input_file", "")), "-j", "-silent", "-title", "-sc", "-location", "-server", "-td", "-rt", "-cname", "-asn", "-tls-grab", "-favicon", "-jarm", "-rl", str(self.config.rate_limit)]
        if tool == "discover_ports":
            return [binary, "-list", str(arguments.get("input_file", "")), "-json", "-silent", "-verify", "-sD", "-sV", "-cdn", "-rate", str(self.config.rate_limit)]
        return [binary, str(arguments["root_fqdn"]), "--json"]
