from __future__ import annotations

import hashlib
import subprocess
import stat
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "install-kali.sh"
CONFIGURATOR = ROOT / "scripts" / "configure-provider.sh"


def run_installer(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(INSTALLER), *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_kali_installer_has_valid_shell_syntax() -> None:
    result = subprocess.run(["bash", "-n", str(INSTALLER)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_kali_installer_help_documents_safe_options() -> None:
    result = run_installer("--help")
    assert result.returncode == 0
    assert "--dry-run" in result.stdout
    assert "--force" in result.stdout
    assert "--configure" in result.stdout
    assert "openai, anthropic, both, or none" in result.stdout


def test_kali_installer_dry_run_is_non_mutating_and_pinned() -> None:
    result = run_installer("--dry-run", "--provider", "none")
    assert result.returncode == 0, result.stderr
    assert "apt-get install" in result.stdout
    assert "verify go 1.25 or newer" in result.stdout
    assert "subfinder@v2.16.0" in result.stdout
    assert "dnsx@v1.3.0" in result.stdout
    assert "httpx@v1.10.0" in result.stdout
    assert "alterx@v0.1.0" in result.stdout
    assert "uv 0.12.7 release archive" in result.stdout
    assert "verify archive SHA-256" in result.stdout
    assert "astral.sh/uv/install.sh" not in result.stdout
    assert "uv sync --extra test" in result.stdout
    assert "--extra openai" not in result.stdout


def test_kali_installer_sanitizes_keys_and_configures_only_after_validation() -> None:
    script = INSTALLER.read_text(encoding="utf-8")
    assert "unset OPENAI_API_KEY ANTHROPIC_API_KEY" in script
    assert script.index("run uv run pytest") < script.index("Configuring optional LLM analysis")


def test_kali_installer_rejects_unknown_provider() -> None:
    result = run_installer("--provider", "unknown")
    assert result.returncode != 0
    assert "unsupported provider" in result.stderr


def test_kali_installer_reports_missing_go() -> None:
    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; PATH=""; require_command go "Install Go and ensure go is available in PATH."',
            "bash",
            str(INSTALLER),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "go is required" in result.stderr
    assert "Install Go" in result.stderr
    assert "PATH" in result.stderr


def test_kali_installer_rejects_go_that_is_too_old(tmp_path: Path) -> None:
    shim = tmp_path / "go"
    shim.write_text("#!/bin/sh\nprintf '%s\\n' 'go version go1.24.7 linux/amd64'\n")
    shim.chmod(0o755)
    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; PATH="$2"; require_go_version',
            "bash",
            str(INSTALLER),
            str(tmp_path),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "Go 1.25+ is required" in result.stderr
    assert "found Go 1.24" in result.stderr


def test_kali_installer_accepts_matching_sha256(tmp_path: Path) -> None:
    artifact = tmp_path / "uv-release.tar.gz"
    artifact.write_bytes(b"known release bytes")
    expected = hashlib.sha256(artifact.read_bytes()).hexdigest()

    result = subprocess.run(
        ["bash", "-c", 'source "$1"; verify_sha256 "$2" "$3"', "bash", str(INSTALLER), str(artifact), expected],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_kali_installer_rejects_mismatched_sha256(tmp_path: Path) -> None:
    artifact = tmp_path / "uv-release.tar.gz"
    artifact.write_bytes(b"tampered release bytes")

    result = subprocess.run(
        ["bash", "-c", 'source "$1"; verify_sha256 "$2" "$3"', "bash", str(INSTALLER), str(artifact), "0" * 64],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "SHA-256 verification failed" in result.stderr


def test_kali_installer_ignores_path_shadowed_sha256sum(tmp_path: Path) -> None:
    artifact = tmp_path / "uv-release.tar.gz"
    artifact.write_bytes(b"tampered release bytes")
    shim_dir = tmp_path / "bin"
    shim_dir.mkdir()
    shim = shim_dir / "sha256sum"
    shim.write_text("#!/bin/sh\nprintf '%064d  %s\\n' 0 \"$2\"\n")
    shim.chmod(0o755)

    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; PATH="$2:$PATH"; verify_sha256 "$3" "$4"',
            "bash",
            str(INSTALLER),
            str(shim_dir),
            str(artifact),
            "0" * 64,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "SHA-256 verification failed" in result.stderr


def test_kali_installer_rejects_unknown_uv_architecture() -> None:
    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; select_uv_release mips64',
            "bash",
            str(INSTALLER),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "unsupported architecture" in result.stderr


def test_kali_installer_rejects_configuration_without_provider() -> None:
    result = run_installer("--provider", "none", "--configure", "--dry-run")
    assert result.returncode != 0
    assert "--configure requires" in result.stderr


def test_provider_configurator_writes_protected_env_without_echoing_key(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    test_key = "test-key-not-a-secret"
    result = subprocess.run(
        ["bash", str(CONFIGURATOR), "--provider", "openai", "--env-file", str(env_file)],
        cwd=ROOT,
        input=f"\n{test_key}\n",
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert test_key not in result.stdout
    assert test_key not in result.stderr
    assert "REACT_RECON_AI_PROVIDER=openai" in env_file.read_text()
    assert "REACT_RECON_AI_MODEL=gpt-5.6-luna" in env_file.read_text()
    assert f"OPENAI_API_KEY={test_key}" in env_file.read_text()
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600


def test_provider_configurator_preserves_existing_env_when_declined(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("PRESERVE_ME=yes\n")

    result = subprocess.run(
        ["bash", str(CONFIGURATOR), "--provider", "anthropic", "--env-file", str(env_file)],
        cwd=ROOT,
        input="n\n",
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert env_file.read_text() == "PRESERVE_ME=yes\n"
