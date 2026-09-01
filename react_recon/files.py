from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path
from typing import Dict


SQLITE_SIDECAR_SUFFIXES = ("-journal", "-wal", "-shm")


def _validate_no_symlink_components(path: Path) -> None:
    """Reject symlinks in the final path or any existing parent component."""
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            details = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(details.st_mode):
            # macOS exposes its system temporary hierarchy through the
            # root-owned /var -> /private/var alias. Permit only symlinks owned
            # by root whose parent is also root-owned and not group/other
            # writable; operator-created links remain rejected.
            parent = current.parent.stat()
            trusted_system_alias = (
                hasattr(os, "getuid")
                and details.st_uid == 0
                and parent.st_uid == 0
                and not (stat.S_IMODE(parent.st_mode) & 0o022)
            )
            if not trusted_system_alias:
                raise ValueError(f"refusing symlinked sensitive path: {current}")


def _validate_owned_path(path: Path) -> None:
    _validate_no_symlink_components(path)
    details = path.stat()
    if hasattr(os, "getuid") and details.st_uid != os.getuid():
        raise PermissionError(f"sensitive path is owned by another user: {path}")


def ensure_private_directory(path: Path, *, enforce_mode: bool = True) -> Path:
    """Create a private directory and reject symlink/foreign-owner paths."""
    _validate_no_symlink_components(path)
    created = not path.exists()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    _validate_owned_path(path)
    if created or enforce_mode:
        path.chmod(0o700)
    return path


def ensure_private_file(path: Path) -> Path:
    """Create or restrict a sensitive regular file without following symlinks."""
    _validate_no_symlink_components(path)
    if path.exists() or path.is_symlink():
        _validate_owned_path(path)
        if not stat.S_ISREG(path.stat().st_mode):
            raise ValueError(f"sensitive path is not a regular file: {path}")
    else:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        os.close(descriptor)
    path.chmod(0o600)
    return path


def write_private_text(path: Path, text: str, *, encoding: str = "utf-8") -> Path:
    """Atomically write a mode-0600 text file in an owned directory."""
    # Do not unexpectedly chmod an existing operator-selected parent such as a
    # repository root; newly created report directories are still mode 0700.
    ensure_private_directory(path.parent, enforce_mode=False)
    if path.exists() or path.is_symlink():
        _validate_owned_path(path)
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
            raise ValueError(f"refusing non-regular output path: {path}")
    temporary_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding=encoding,
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            os.chmod(temporary_name, 0o600)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        path.chmod(0o600)
        return path
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)


def truncate_utf8(value: str, maximum_bytes: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= maximum_bytes:
        return value, False
    return encoded[:maximum_bytes].decode("utf-8", errors="ignore"), True


def harden_evidence_tree(root: Path) -> int:
    """Restrict recognized legacy run directories and JSONL evidence files."""
    _reject_broad_artifact_root(root)
    if not root.exists() and not root.is_symlink():
        return 0
    ensure_private_directory(root)
    hardened = 1
    for run_directory in root.glob("run-*"):
        if run_directory.is_symlink() or not run_directory.is_dir():
            raise ValueError(f"invalid legacy evidence run path: {run_directory}")
        ensure_private_directory(run_directory)
        hardened += 1
        for evidence_file in run_directory.glob("evidence-*.jsonl"):
            ensure_private_file(evidence_file)
            hardened += 1
    return hardened


def harden_report_tree(root: Path, *, enforce_root_mode: bool = False) -> int:
    """Restrict recognized run reports at the root and one dated level down."""
    if not root.exists() and not root.is_symlink():
        return 0
    _validate_no_symlink_components(root)
    # A normal run may intentionally write its dated output beneath the current
    # directory. Do not walk or chmod that shared parent while migrating legacy
    # reports; newly rendered files are secured by write_private_text instead.
    if _is_broad_artifact_root(root):
        if enforce_root_mode:
            raise ValueError(f"artifact directory must be a dedicated child path: {root}")
        return 0
    if enforce_root_mode:
        _reject_broad_artifact_root(root)
    ensure_private_directory(root, enforce_mode=enforce_root_mode)
    hardened = 1 if enforce_root_mode else 0
    directories = [root]
    for child in root.iterdir():
        if child.is_symlink() or not child.is_dir():
            continue
        recognized = [
            report_file
            for pattern in ("run-*.json", "run-*.html")
            for report_file in child.glob(pattern)
        ]
        if recognized:
            ensure_private_directory(child)
            directories.append(child)
            hardened += 1
    for directory in directories:
        for pattern in ("run-*.json", "run-*.html"):
            for report_file in directory.glob(pattern):
                ensure_private_file(report_file)
                hardened += 1
    return hardened


def harden_artifacts(
    database: Path,
    evidence_root: Path,
    reports_root: Path,
    env_file: Path,
    *,
    harden_reports_root: bool = False,
) -> Dict[str, int]:
    """Apply owner-only modes to recognized current and legacy artifacts."""
    counts = {"database": 0, "evidence_paths": 0, "report_paths": 0, "env_file": 0}
    counts["database"] = harden_sqlite_files(database)
    counts["evidence_paths"] = harden_evidence_tree(evidence_root)
    counts["report_paths"] = harden_report_tree(
        reports_root, enforce_root_mode=harden_reports_root
    )
    if env_file.exists() or env_file.is_symlink():
        ensure_private_file(env_file)
        counts["env_file"] = 1
    return counts


def harden_sqlite_files(database: Path) -> int:
    """Restrict an existing SQLite database and any persistent sidecar files."""
    hardened = 0
    candidates = (database,) + tuple(
        Path(f"{database}{suffix}") for suffix in SQLITE_SIDECAR_SUFFIXES
    )
    for candidate in candidates:
        if candidate.exists() or candidate.is_symlink():
            ensure_private_file(candidate)
            hardened += 1
    return hardened


def _is_broad_artifact_root(path: Path) -> bool:
    resolved = path.resolve(strict=False)
    return resolved in {
        Path("/").resolve(),
        Path.home().resolve(),
        Path.cwd().resolve(),
        Path(tempfile.gettempdir()).resolve(),
    }


def _reject_broad_artifact_root(path: Path) -> None:
    """Prevent a configuration mistake from chmodding a shared broad root."""
    _validate_no_symlink_components(path)
    if _is_broad_artifact_root(path):
        raise ValueError(f"artifact directory must be a dedicated child path: {path}")
