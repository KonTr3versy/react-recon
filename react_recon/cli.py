from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .agent import ReconAgent
from .analysis import analyze_run
from .executor import Executor
from .files import harden_artifacts
from .models import RunConfig
from .providers import redact_provider_error, resolve_provider_model
from .reporting import write_report
from .reprocess import reprocess_run
from .runtime import run_bounded_process
from .storage import Store


def build_parser() -> argparse.ArgumentParser:
    # Keep the CLI thin: components below own policy, state, execution, and
    # orchestration rather than duplicating that logic here.
    parser = argparse.ArgumentParser(prog="react-recon", description="Evidence-backed reconnaissance and pentester target prioritization.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create an example environment file")
    sub.add_parser("preflight", help="show model, binary, and Docker readiness")
    run = sub.add_parser("run", help="collect, analyze, and report passive or authorized-active reconnaissance")
    _add_run_args(run)
    run.add_argument("--provider", choices=["openai", "anthropic"], help="AI provider override (defaults to REACT_RECON_AI_PROVIDER)")
    run.add_argument("--model", help="model override (defaults to REACT_RECON_AI_MODEL or the provider default)")
    run.add_argument(
        "--planning-mode",
        choices=["hybrid", "deterministic"],
        default="hybrid",
        help="hybrid permits up to three model-prioritized typed actions before deterministic fallback",
    )
    run.add_argument(
        "--max-adaptive-actions",
        type=int,
        default=3,
        help="maximum model-prioritized collection actions (0-3)",
    )
    run.add_argument("--max-targets", type=int, default=10, help="maximum target groups in the analyst brief (1-25)")
    run.add_argument("--reports-dir", default="reports", help="parent directory for the dated domain report folder")
    run.add_argument("--collection-only", action="store_true", help="stop after collection and print only the run ID")
    resume = sub.add_parser("resume", help="resume a persisted collection run")
    resume.add_argument("run_id")
    analyze = sub.add_parser("analyze", help="create a concise evidence-backed targeting brief")
    analyze.add_argument("run_id")
    analyze.add_argument("--provider", choices=["openai", "anthropic"], help="AI provider override (defaults to REACT_RECON_AI_PROVIDER)")
    analyze.add_argument("--model", help="model override (defaults to REACT_RECON_AI_MODEL or the provider default)")
    analyze.add_argument("--max-targets", type=int, default=10, help="maximum target groups in the main brief (1-25)")
    reprocess = sub.add_parser("reprocess", help="rebuild normalized state from preserved evidence without network access")
    reprocess.add_argument("run_id")
    harden = sub.add_parser("harden-artifacts", help="apply owner-only modes to recognized databases, evidence, reports, and .env")
    harden.add_argument("--database", default="react-recon.db")
    harden.add_argument("--evidence-dir", default="evidence")
    harden.add_argument("--reports-dir", default="reports")
    harden.add_argument("--env-file", default=".env")
    report = sub.add_parser("report", help="render complete JSON or concise HTML from SQLite state")
    report.add_argument("run_id")
    report.add_argument("--format", choices=["json", "html"], default="json")
    report.add_argument("--output")
    return parser


def _add_run_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root-fqdn", required=True)
    parser.add_argument("--mode", choices=["passive", "active"], default="passive")
    parser.add_argument("--authorized-host", action="append", default=[])
    parser.add_argument(
        "--authorized-network",
        action="append",
        default=[],
        help=(
            "optional strict IP/CIDR restriction for active port/service probing; "
            "also permits matching non-global destinations (repeatable)"
        ),
    )
    parser.add_argument("--database", default="react-recon.db")
    parser.add_argument("--evidence-dir", default="evidence")
    parser.add_argument("--max-tool-calls", type=int, default=25)
    parser.add_argument("--max-duration-seconds", type=int, default=1800)
    parser.add_argument("--max-assets", type=int, default=500)
    parser.add_argument("--max-permutations", type=int, default=2000)
    parser.add_argument("--max-output-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--max-evidence-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--max-observations", type=int, default=20_000)
    parser.add_argument("--max-observation-bytes", type=int, default=256 * 1024)
    parser.add_argument("--max-normalized-bytes", type=int, default=32 * 1024 * 1024)
    parser.add_argument("--max-dns-binding-age-seconds", type=int, default=3600)
    parser.add_argument("--rate-limit", type=int, default=10)
    parser.add_argument("--dns-rate-limit", type=int, default=50)
    parser.add_argument("--concurrency", type=int, default=2)


def _config(args: argparse.Namespace) -> RunConfig:
    provider, model = resolve_provider_model(args.provider, args.model)
    return RunConfig(
        root_fqdn=args.root_fqdn.lower().rstrip("."),
        mode=args.mode,
        authorized_hosts=args.authorized_host,
        authorized_networks=args.authorized_network,
        database=args.database,
        evidence_dir=args.evidence_dir,
        max_tool_calls=args.max_tool_calls,
        max_duration_seconds=args.max_duration_seconds,
        max_assets=args.max_assets,
        max_permutations=args.max_permutations,
        max_output_bytes=args.max_output_bytes,
        max_evidence_bytes=args.max_evidence_bytes,
        max_observations=args.max_observations,
        max_observation_bytes=args.max_observation_bytes,
        max_normalized_bytes=args.max_normalized_bytes,
        max_dns_binding_age_seconds=args.max_dns_binding_age_seconds,
        rate_limit=args.rate_limit,
        dns_rate_limit=args.dns_rate_limit,
        concurrency=args.concurrency,
        ai_provider=provider,
        ai_model=model,
        planning_mode=args.planning_mode,
        max_adaptive_actions=args.max_adaptive_actions,
    )


def _run_report_directory(parent: str, root_fqdn: str, created_at: str) -> Path:
    """Return a stable, filesystem-safe report directory for a run."""
    safe_domain = re.sub(r"[^a-zA-Z0-9._-]+", "-", root_fqdn).strip(".-") or "unknown-domain"
    try:
        run_date = datetime.fromisoformat(created_at.replace("Z", "+00:00")).date().isoformat()
    except (TypeError, ValueError):
        run_date = str(created_at)[:10]
    return Path(parent) / f"{safe_domain}-{run_date}"


def _binary_version(binary: str) -> Optional[str]:
    path = shutil.which(binary)
    if not path:
        return None
    flag = "--version" if binary in {"gau", "nmap"} else "-version"
    try:
        completed = run_bounded_process([path, flag], timeout=5, max_output_bytes=64 * 1024)
    except OSError:
        return "version check failed"
    if completed.timed_out or completed.output_limited:
        return "version check failed"
    output = (completed.stdout or completed.stderr).strip()
    return output.splitlines()[0][:240] if output else f"exit {completed.returncode}"


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
        detected = {
            binary: {"path": shutil.which(binary), "version": _binary_version(binary)}
            for binary in Executor.BINARIES
        }
        detected["crtsh_search"] = "built-in HTTPS collector"
        nmap_path = shutil.which("nmap")
        docker_path = shutil.which("docker")
        nmap_image_ref = Executor.DOCKER_IMAGES["fingerprint_services"]
        nmap_image = False
        if docker_path:
            try:
                inspection = run_bounded_process(
                    [docker_path, "image", "inspect", nmap_image_ref],
                    timeout=5,
                    max_output_bytes=64 * 1024,
                )
                nmap_image = inspection.returncode == 0
            except OSError:
                nmap_image = False
        detected["nmap"] = {"path": nmap_path, "docker_fallback": nmap_image_ref if nmap_image else None, "version": _binary_version("nmap") if nmap_path else None}
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
    if args.command == "harden-artifacts":
        print(
            json.dumps(
                harden_artifacts(
                    Path(args.database),
                    Path(args.evidence_dir),
                    Path(args.reports_dir),
                    Path(args.env_file),
                    harden_reports_root=True,
                ),
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.command == "run":
        try:
            config = _config(args)
            config.validate()
        except ValueError as exc:
            print(f"error: {exc}", file=os.sys.stderr)
            return 2
        # A normal run also migrates recognized legacy artifacts in its active
        # output roots before opening or writing sensitive assessment data.
        harden_artifacts(
            Path(config.database),
            Path(config.evidence_dir),
            Path(args.reports_dir),
            Path(".env"),
        )
        store = Store(config.database, config.evidence_dir)
        try:
            run_id = ReconAgent(store, config).run()
            if args.collection_only:
                print(run_id)
                return 0

            # A normal run is the complete operator workflow. The standalone
            # analyze/report commands remain useful for recovery and rerenders.
            analysis_id = None
            analysis_error = None
            try:
                analysis_id = analyze_run(
                    store,
                    run_id,
                    provider=config.ai_provider,
                    model=config.ai_model,
                    max_targets=args.max_targets,
                )
            except Exception as exc:
                # Collection evidence remains useful even when the external
                # model or analysis validation fails. Always render both reports.
                analysis_error = redact_provider_error(exc)
            run = store.get_run(run_id)
            report_dir = _run_report_directory(args.reports_dir, run["root_fqdn"], run["created_at"])
            html_path = write_report(store, run_id, str(report_dir / f"{run_id}.html"), "html")
            json_path = write_report(store, run_id, str(report_dir / f"{run_id}.json"), "json")
            print(json.dumps({
                "run_id": run_id,
                "analysis_id": analysis_id,
                "analysis_error": analysis_error,
                "report_directory": str(report_dir),
                "html_report": str(html_path),
                "json_report": str(json_path),
            }, indent=2, sort_keys=True))
            return 2 if analysis_error else 0
        finally:
            store.close()
    if args.command == "resume":
        # Reconstruct the original policy from SQLite so resume cannot silently
        # change the run's scope or budgets.
        database = os.environ.get("REACT_RECON_DATABASE", "react-recon.db")
        evidence_dir = os.environ.get("REACT_RECON_EVIDENCE_DIR", "evidence")
        store = Store(database, evidence_dir)
        try:
            config = store.run_config(args.run_id)
            try:
                config.validate()
            except ValueError as exc:
                print(f"error: cannot resume {args.run_id}: {exc}", file=os.sys.stderr)
                return 2
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
