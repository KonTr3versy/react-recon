import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_ci_actions_use_full_commit_shas_and_tooling_is_versioned():
    workflow = (ROOT / ".github" / "workflows" / "test.yml").read_text(
        encoding="utf-8"
    )
    action_refs = re.findall(r"uses:\s*[^@\s]+@([^\s#]+)", workflow)
    assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs)
    assert "runs-on: ubuntu-24.04" in workflow
    assert 'version: "0.12.7"' in workflow


def test_runtime_and_install_docs_do_not_use_mutable_latest_references():
    paths = [
        ROOT / "react_recon" / "executor.py",
        ROOT / "docs" / "INSTALLATION.md",
        ROOT / ".github" / "workflows" / "test.yml",
    ]
    content = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    assert ":latest" not in content
    assert "@latest" not in content
