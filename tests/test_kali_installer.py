from __future__ import annotations

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
    assert "subfinder@v2.16.0" in result.stdout
    assert "httpx@v1.10.0" in result.stdout
    assert "uv sync --extra test" in result.stdout
    assert "--extra openai" not in result.stdout


def test_kali_installer_rejects_unknown_provider() -> None:
    result = run_installer("--provider", "unknown")
    assert result.returncode != 0
    assert "unsupported provider" in result.stderr


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
