from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

from .agent import ReconAgent
from .analysis import analyze_run
from .executor import Executor
from .models import RunConfig
from .reporting import write_report
from .reprocess import reprocess_run
from .storage import Store


def build_parser() -> argparse.ArgumentParser:
    # Keep the CLI thin: components below own policy, state, execution, and
    # orchestration rather than duplicating that logic here.
    parser = argparse.ArgumentParser(prog="react-recon", description="Evidence-backed reconnaissance and pentester target prioritization.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create an example environment file")
    sub.add_parser("preflight", help="show model, binary, and Docker readiness")
    run = sub.add_parser("run", help="collect passive or authorized-active reconnaissance")
    _add_run_args(run)
    resume = sub.add_parser("resume", help="resume a persisted collection run")
    resume.add_argument("run_id")
    analyze = sub.add_parser("analyze", help="create a concise evidence-backed targeting brief")
    analyze.add_argument("run_id")
    analyze.add_argument("--provider", choices=["openai", "anthropic"], help="AI provider override (defaults to REACT_RECON_AI_PROVIDER)")
    analyze.add_argument("--model", help="model override (defaults to REACT_RECON_AI_MODEL or the provider default)")
    analyze.add_argument("--max-targets", type=int, default=10, help="maximum target groups in the main brief (1-25)")
    reprocess = sub.add_parser("reprocess", help="rebuild normalized state from preserved evidence without network access")
    reprocess.add_argument("run_id")
    report = sub.add_parser("report", help="render complete JSON or concise HTML from SQLite state")
    report.add_argument("run_id")
    report.add_argument("--format", choices=["json", "html"], default="json")
    report.add_argument("--output")
    return parser


def _add_run_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root-fqdn", required=True)
    parser.add_argument("--mode", choices=["passive", "active"], default="passive")
    parser.add_argument("--authorized-host", action="append", default=[])
    parser.add_argument("--database", default="react-recon.db")
    parser.add_argument("--evidence-dir", default="evidence")
    parser.add_argument("--max-tool-calls", type=int, default=25)
    parser.add_argument("--max-duration-seconds", type=int, default=1800)
    parser.add_argument("--max-assets", type=int, default=500)
    parser.add_argument("--rate-limit", type=int, default=10)
    parser.add_argument("--concurrency", type=int, default=2)


def _config(args: argparse.Namespace) -> RunConfig:
    return RunConfig(root_fqdn=args.root_fqdn.lower().rstrip("."), mode=args.mode, authorized_hosts=args.authorized_host, database=args.database, evidence_dir=args.evidence_dir, max_tool_calls=args.max_tool_calls, max_duration_seconds=args.max_duration_seconds, max_assets=args.max_assets, rate_limit=args.rate_limit, concurrency=args.concurrency)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "init":
        destination = Path(".env.example")
        if destination.exists():
            print(f"already exists: {destination}")
            return 0
        destination.write_text(
            "REACT_RECON_AI_PROVIDER=openai\nREACT_RECON_AI_MODEL=gpt-5.6-luna\n"
            "OPENAI_API_KEY=\nANTHROPIC_API_KEY=\n"
            "REACT_RECON_DATABASE=react-recon.db\nREACT_RECON_EVIDENCE_DIR=evidence\n",
            encoding="utf-8",
        )
        print(f"created {destination}")
        return 0
    if args.command == "preflight":
        # Report availability only; never print the API key itself.
        tools = Executor(RunConfig("example.com")).COMMANDS
        detected = {name: shutil.which(binary) for name, binary in tools.items()}
        detected["crtsh_search"] = "built-in HTTPS collector"
        nmap_path = shutil.which("nmap")
        nmap_image = subprocess.run(["docker", "image", "inspect", "instrumentisto/nmap:latest"], capture_output=True, check=False).returncode == 0 if shutil.which("docker") else False
        detected["fingerprint_services"] = nmap_path or ("Docker image: instrumentisto/nmap:latest" if nmap_image else None)
        print(json.dumps({
            "python": os.sys.version.split()[0],
            "ai_provider": os.environ.get("REACT_RECON_AI_PROVIDER", "openai"),
            "providers": {
                "openai": {"sdk": importlib.util.find_spec("openai") is not None, "api_key": bool(os.environ.get("OPENAI_API_KEY"))},
                "anthropic": {"sdk": importlib.util.find_spec("anthropic") is not None, "api_key": bool(os.environ.get("ANTHROPIC_API_KEY"))},
            },
            "docker": shutil.which("docker") is not None,
            "tools": detected,
        }, indent=2, sort_keys=True))
        return 0
    if args.command == "run":
        config = _config(args)
        store = Store(config.database, config.evidence_dir)
        try:
            run_id = ReconAgent(store, config).run()
            print(run_id)
            return 0
        finally:
            store.close()
    if args.command == "resume":
        # Reconstruct the original policy from SQLite so resume cannot silently
        # change the run's scope or budgets.
        database = os.environ.get("REACT_RECON_DATABASE", "react-recon.db")
        evidence_dir = os.environ.get("REACT_RECON_EVIDENCE_DIR", "evidence")
        store = Store(database, evidence_dir)
        try:
            row = store.get_run(args.run_id)
            config = RunConfig(**json.loads(row["config_json"]))
            print(ReconAgent(store, config).run(args.run_id))
            return 0
        finally:
            store.close()
    if args.command == "analyze":
        database = os.environ.get("REACT_RECON_DATABASE", "react-recon.db")
        evidence_dir = os.environ.get("REACT_RECON_EVIDENCE_DIR", "evidence")
        store = Store(database, evidence_dir)
        try:
            print(analyze_run(store, args.run_id, provider=args.provider, model=args.model, max_targets=args.max_targets))
            return 0
        finally:
            store.close()
    if args.command == "reprocess":
        database = os.environ.get("REACT_RECON_DATABASE", "react-recon.db")
        evidence_dir = os.environ.get("REACT_RECON_EVIDENCE_DIR", "evidence")
        store = Store(database, evidence_dir)
        try:
            print(json.dumps(reprocess_run(store, args.run_id), indent=2, sort_keys=True))
            return 0
        finally:
            store.close()
    if args.command == "report":
        # Reporting is read-only with respect to run state and repeatable.
        database = os.environ.get("REACT_RECON_DATABASE", "react-recon.db")
        store = Store(database, os.environ.get("REACT_RECON_EVIDENCE_DIR", "evidence"))
        try:
            output = args.output or f"reports/{args.run_id}.{args.format}"
            print(write_report(store, args.run_id, output, args.format))
            return 0
        finally:
            store.close()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
