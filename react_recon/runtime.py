from __future__ import annotations

import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Dict, List, Optional


MODEL_SECRET_ENV_VARS = {
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
}


@dataclass(frozen=True)
class BoundedProcessResult:
    returncode: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool = False
    output_limited: bool = False


def sanitized_subprocess_env() -> Dict[str, str]:
    """Copy the environment without model credentials unrelated to collectors."""
    environment = dict(os.environ)
    for name in MODEL_SECRET_ENV_VARS:
        environment.pop(name, None)
    return environment


def run_bounded_process(command: List[str], timeout: int, max_output_bytes: int) -> BoundedProcessResult:
    """Run direct argv while bounding memory, disk growth, and wall-clock time.

    stdout and stderr are redirected to anonymous temporary files rather than
    accumulated by subprocess. The process is terminated when either stream
    exceeds the configured ceiling; truncated output is never classified as a
    successful negative result.
    """
    effective_command = list(command)
    docker_directory: Optional[tempfile.TemporaryDirectory[str]] = None
    docker_cidfile: Optional[Path] = None
    if len(command) >= 2 and Path(command[0]).name == "docker" and command[1] == "run":
        docker_directory = tempfile.TemporaryDirectory(prefix="react-recon-docker-")
        Path(docker_directory.name).chmod(0o700)
        docker_cidfile = Path(docker_directory.name) / "container.cid"
        effective_command[2:2] = ["--cidfile", str(docker_cidfile)]

    try:
        with tempfile.TemporaryFile(mode="w+b") as stdout_file, tempfile.TemporaryFile(mode="w+b") as stderr_file:
            process = subprocess.Popen(
                effective_command,
                stdout=stdout_file,
                stderr=stderr_file,
                env=sanitized_subprocess_env(),
                shell=False,
                start_new_session=(os.name == "posix"),
                preexec_fn=(
                    (lambda: _set_file_size_limit(max_output_bytes + 1))
                    if os.name == "posix"
                    else None
                ),
            )
            deadline = time.monotonic() + timeout
            timed_out = False
            output_limited = False
            try:
                while process.poll() is None:
                    if stdout_file.tell() > max_output_bytes or stderr_file.tell() > max_output_bytes:
                        output_limited = True
                        _kill_process_group(process)
                        break
                    if time.monotonic() >= deadline:
                        timed_out = True
                        _kill_process_group(process)
                        break
                    time.sleep(0.01)
                process.wait()
            except BaseException:
                # Collectors run in their own session, so terminal interrupts
                # received by the controller do not automatically reach them.
                # Always tear down that complete process group before allowing
                # cancellation or another controller exception to propagate.
                _kill_process_group(process)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    _kill_process_group(process)
                    process.wait()
                if docker_cidfile is not None:
                    _remove_docker_container(command[0], docker_cidfile)
                raise
            # A short-lived child can finish between polling intervals. Re-check
            # the final stream sizes so a fast oversized response is still treated
            # as a failed, truncated execution rather than a successful result.
            if stdout_file.tell() > max_output_bytes or stderr_file.tell() > max_output_bytes:
                output_limited = True
            if os.name == "posix" and process.returncode == -signal.SIGXFSZ:
                output_limited = True
            if (timed_out or output_limited) and docker_cidfile is not None:
                _remove_docker_container(command[0], docker_cidfile)
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read(max_output_bytes).decode("utf-8", errors="replace")
            stderr = stderr_file.read(max_output_bytes).decode("utf-8", errors="replace")
            return BoundedProcessResult(process.returncode, stdout, stderr, timed_out, output_limited)
    finally:
        if docker_directory is not None:
            docker_directory.cleanup()


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    """Terminate the collector and descendants without touching our process."""
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass
    except PermissionError:
        # Some constrained runtimes disallow process-group signaling even for
        # a child-created session. Fall back to terminating the direct client;
        # Docker CID cleanup still removes daemon-owned containers below.
        try:
            process.kill()
        except ProcessLookupError:
            pass


def _set_file_size_limit(maximum_bytes: int) -> None:
    """Apply an OS-enforced ceiling before an untrusted collector starts."""
    import resource

    _, hard_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
    target = maximum_bytes
    if hard_limit != resource.RLIM_INFINITY:
        target = min(target, hard_limit)
    resource.setrlimit(resource.RLIMIT_FSIZE, (target, hard_limit))


def _remove_docker_container(docker_binary: str, cidfile: Path) -> None:
    """Remove a daemon-owned container if its client was killed by a budget."""
    # Docker may create the container and CID file just after the client hits
    # its output limit. Wait up to two seconds before giving up cleanup.
    for _ in range(40):
        try:
            container_id = cidfile.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            container_id = ""
        if container_id:
            try:
                subprocess.run(
                    [docker_binary, "rm", "-f", container_id],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=sanitized_subprocess_env(),
                    shell=False,
                    timeout=10,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                pass
            return
        time.sleep(0.05)
