from __future__ import annotations

import html
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from .coverage import build_coverage
from .files import write_private_text
from .profiles import HTTP_RESPONSE_PRIORITY, build_target_profiles
from .storage import Store


def build_report(store: Store, run_id: str) -> Dict[str, Any]:
    # JSON is the complete machine-readable record; HTML presents this same
    # SQLite-derived data for human review.
    snapshot = store.snapshot(run_id)
    profiles = build_target_profiles(snapshot)
    responsive_web_targets = _responsive_web_targets(profiles)
    return {
        "run": snapshot["run"],
        "assets": snapshot["assets"],
        "observations": snapshot["observations"],
        "executions": snapshot["executions"],
        "tasks": snapshot["tasks"],
        "coverage": {"execution_count": len(snapshot["executions"]), "observation_count": len(snapshot["observations"]), "asset_count": len(snapshot["assets"]), "responsive_web_endpoint_count": len(responsive_web_targets), "baseline": build_coverage(store, run_id)},
        "responsive_web_targets": responsive_web_targets,
        "analysis": store.latest_analysis(run_id),
        "analysis_attempt": store.latest_analysis_attempt(run_id),
        "limitations": ["Recon observations are not vulnerability confirmations.", "Only executed tools and their captured evidence are represented."],
    }


def write_report(store: Store, run_id: str, output: str, fmt: str) -> Path:
    report = build_report(store, run_id)
    path = Path(output)
    if fmt == "json":
        write_private_text(path, json.dumps(report, indent=2, sort_keys=True))
    elif fmt == "html":
        # Evidence paths are stored relative to the working directory. Record
        # the HTML destination only for rendering so links remain correct when
        # reports live in a nested domain/date directory.
        report["_html_output_dir"] = str(path.parent.resolve())
        write_private_text(path, render_html(report, run_id))
    else:
        raise ValueError("format must be json or html")
    return path


def render_html(report: Dict[str, Any], run_id: str) -> str:
    # Collapsible groups keep detailed observations reviewable without dropping
    # facts or their evidence links.
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for observation in report["observations"]:
        grouped.setdefault(str(observation.get("type", "unknown")), []).append(observation)
    assets = "".join(f"<tr><td>{esc(item.get('host'))}</td><td>{esc(item.get('in_scope'))}</td><td>{esc(item.get('created_at'))}</td></tr>" for item in report["assets"])
    executions = "".join(f"<tr><td>{esc(item.get('tool'))}</td><td class='{status_class(item.get('status'))}'>{esc(item.get('status'))}</td><td>{esc(item.get('target'))}</td><td>{esc(item.get('return_code'))}</td><td>{esc(item.get('runner'))}</td><td>{esc(item.get('started_at'))}</td><td><a href='{evidence_link(item.get('raw_output_path'), report)}'>raw evidence</a></td></tr>" for item in report["executions"])
    tasks = "".join(f"<tr><td>{esc(item.get('tool'))}</td><td>{esc(item.get('status'))}</td><td><pre>{html.escape(item.get('arguments_json', ''))}</pre></td><td>{esc(item.get('attempts'))}</td></tr>" for item in report["tasks"])
    observation_sections = "".join(observation_group(kind, items, report) for kind, items in sorted(grouped.items()))
    limitations = "".join(f"<li>{html.escape(str(item))}</li>" for item in report["limitations"])
    run = report["run"]
    analyst_brief = render_analyst_brief(report)
    responsive_web = render_responsive_web_targets(report)
    baseline = report["coverage"]["baseline"]
    baseline_label = "Complete" if baseline["baseline_successful"] else "Attempted with gaps" if baseline["baseline_attempted"] else "Incomplete"
    coverage_rows = "".join(f"<tr><td>{esc(step['tool'])}</td><td class='{status_class(step['state'])}'>{esc(step['state'])}</td><td>{esc(step['attempts'])}</td><td>{esc(step['attempted_target_count'])} / {esc(step['expected_target_count'])}</td></tr>" for step in baseline["steps"])
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>Recon report {html.escape(run_id)}</title>
<style>body{{font:15px -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:1250px;margin:2rem auto;padding:0 1rem;color:#202124;line-height:1.45}}h1{{margin-bottom:.25rem}}h2{{border-bottom:1px solid #ddd;padding-bottom:.35rem;margin-top:2rem}}h3{{margin-bottom:.3rem}}table{{border-collapse:collapse;width:100%;margin:.75rem 0 1rem}}td,th{{border:1px solid #d9dce1;padding:.55rem;text-align:left;vertical-align:top}}th{{background:#f4f6f8}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;margin:0;font:12px ui-monospace,monospace}}.summary{{display:flex;gap:1rem;flex-wrap:wrap}}.card{{background:#f4f6f8;border-radius:6px;padding:.75rem 1rem}}.success,.completed{{color:#137333}}.failed{{color:#b3261e}}.skipped{{color:#8a5a00}}details{{margin:.6rem 0}}summary{{cursor:pointer;font-weight:600;padding:.6rem;background:#f8f9fa}}a{{color:#175cd3}}.brief{{border:1px solid #d9dce1;border-left:5px solid #175cd3;border-radius:5px;padding:1rem;margin:1rem 0}}.brief.P1{{border-left-color:#b3261e}}.brief.P2{{border-left-color:#d97706}}.brief.P3{{border-left-color:#175cd3}}.badge{{display:inline-block;border-radius:4px;padding:.15rem .45rem;font-weight:700;background:#e8eef9}}.badge.P1{{background:#fce8e6;color:#b3261e}}.badge.P2{{background:#fff4dc;color:#8a5a00}}.badge.P3{{background:#e8eef9;color:#175cd3}}.muted{{color:#5f6368}}.notice{{background:#fff8e1;border-left:4px solid #d97706;padding:.8rem 1rem}}ul.compact li{{margin:.25rem 0}}code{{font-size:.9em}}</style></head><body>
<h1>Pentester recon brief</h1><p class='muted'>Run {html.escape(run_id)} · Status: <strong class='{status_class(run.get('status'))}'>{esc(run.get('status'))}</strong></p>
<div class='summary'><div class='card'>Root: {esc(run.get('root_fqdn'))}</div><div class='card'>Mode: {esc(run.get('mode'))}</div><div class='card'>Coverage: {esc(baseline_label)}</div><div class='card'>Assets: {report['coverage']['asset_count']}</div><div class='card'>Responding web endpoints: {report['coverage']['responsive_web_endpoint_count']}</div><div class='card'>Observations: {report['coverage']['observation_count']}</div><div class='card'>Executions: {report['coverage']['execution_count']}</div></div>
{analyst_brief}
{responsive_web}
<h2>Collection coverage</h2><table><tr><th>Step</th><th>State</th><th>Attempts</th><th>Targets attempted / expected</th></tr>{coverage_rows}</table>
<h2>Coverage and limitations</h2><ul class='compact'>{limitations}</ul>
<h2>Evidence appendix</h2>
<details><summary>Asset inventory ({len(report['assets'])})</summary><table><tr><th>Host</th><th>In scope</th><th>Captured</th></tr>{assets}</table></details>
<details><summary>Execution timeline ({len(report['executions'])})</summary><table><tr><th>Tool</th><th>Status</th><th>Target</th><th>Return code</th><th>Runner</th><th>Started</th><th>Evidence</th></tr>{executions}</table></details>
<details><summary>Normalized observations ({len(report['observations'])})</summary>{observation_sections}</details>
<details><summary>Planner tasks ({len(report['tasks'])})</summary><table><tr><th>Tool</th><th>Status</th><th>Arguments</th><th>Attempts</th></tr>{tasks}</table></details>
</body></html>"""


def render_analyst_brief(report: Dict[str, Any]) -> str:
    analysis_record = report.get("analysis")
    if not analysis_record:
        attempt = report.get("analysis_attempt") or {}
        detail = f" Latest attempt: {esc(attempt.get('status'))}; {esc(attempt.get('error'))}." if attempt else ""
        return f"<div class='notice'><strong>No analyst brief generated.</strong>{detail} Collection evidence and coverage remain available below.</div>"
    analysis = analysis_record["output"]
    leads = analysis.get("priority_targets", [])[:10]
    queue = "".join(
        f"<tr><td><span class='badge {esc(lead.get('priority'))}'>{esc(lead.get('priority'))}</span></td><td><strong>{esc(lead.get('host'))}</strong>{_related_hosts(lead)}</td><td>{esc(lead.get('interesting_exposure'))}</td><td>{esc(lead.get('why_interesting'))}</td><td>{esc(lead.get('confidence'))}</td></tr>"
        for lead in leads
    ) or "<tr><td colspan='5'>No priority targets were supported by the collected evidence.</td></tr>"
    briefs = "".join(_render_target_brief(lead, report) for lead in leads)
    patterns = "".join(
        f"<li><strong>{esc(item.get('title'))}:</strong> {esc(item.get('analysis'))} <span class='muted'>({esc(', '.join(item.get('hosts', [])))})</span></li>"
        for item in analysis.get("cross_asset_patterns", [])[:5]
    ) or "<li>No material cross-asset pattern was supported.</li>"
    opportunities = "".join(
        f"<li><strong>{esc(item.get('title'))}:</strong> {esc(item.get('reason'))} <em>Next: {esc(item.get('next_step'))}</em></li>"
        for item in analysis.get("information_opportunities", [])[:5]
    ) or "<li>No separate information-gathering opportunity was prioritized.</li>"
    active_follow_up = render_active_follow_up(analysis, report)
    gaps = "".join(f"<li>{esc(item)}</li>" for item in analysis.get("collection_gaps", [])[:8]) or "<li>No material collection gap was reported.</li>"
    return f"""
<h2>Analyst assessment</h2><p class='muted'>Provider: {esc(analysis_record.get('provider'))} · Model: {esc(analysis_record.get('model'))} · Prompt: {esc(analysis_record.get('prompt_version'))}</p><p>{esc(analysis.get('run_assessment'))}</p>
<h2>Priority target queue</h2><table><tr><th>Priority</th><th>Target</th><th>Exposure</th><th>Why it matters</th><th>Confidence</th></tr>{queue}</table>
<h2>Target briefs</h2>{briefs}
<h2>Cross-asset intelligence</h2><ul class='compact'>{patterns}</ul>
<h2>Information-gathering opportunities</h2><ul class='compact'>{opportunities}</ul>
{active_follow_up}
<h2>Collection gaps</h2><ul class='compact'>{gaps}</ul>
"""


def render_active_follow_up(analysis: Dict[str, Any], report: Dict[str, Any]) -> str:
    if str(report.get("run", {}).get("mode")) != "passive":
        return ""
    candidates = analysis.get("active_follow_up_candidates", [])[:10]
    rows = "".join(
        f"<tr><td>{esc(item.get('rank'))}</td><td><strong>{esc(item.get('host'))}</strong></td>"
        f"<td><code>{esc(item.get('observed_url') or 'hostname only')}</code></td>"
        f"<td>{esc(item.get('why_active'))}</td><td>{esc(item.get('active_objective'))}</td>"
        f"<td>{esc(item.get('confidence'))}</td><td>{_reference_links(item.get('evidence_ids', []), report)}</td></tr>"
        for item in candidates
    ) or "<tr><td colspan='7'>The analyst did not identify a sufficiently supported active-mode candidate.</td></tr>"
    return f"""
<h2>Recommended for active follow-up</h2>
<p class='muted'>Passive-run candidates worth validating in a separately authorized active run. Hostname-only entries are not claims that a live service was observed.</p>
<table><tr><th>Rank</th><th>Host</th><th>Observed URL</th><th>Why</th><th>Active objective</th><th>Confidence</th><th>Evidence</th></tr>{rows}</table>
"""


def render_responsive_web_targets(report: Dict[str, Any]) -> str:
    targets = report.get("responsive_web_targets", [])
    rows = "".join(
        f"<tr><td><strong>{esc(item.get('host'))}</strong></td><td>{esc(item.get('status_code'))}</td><td><code>{esc(item.get('url'))}</code></td><td>{esc(item.get('title'))}</td><td>{esc(item.get('location'))}</td><td>{esc(', '.join(item.get('tech', [])) if isinstance(item.get('tech'), list) else item.get('tech'))}</td></tr>"
        for item in targets[:50]
    ) or "<tr><td colspan='6'>httpx did not verify a responding web endpoint.</td></tr>"
    note = f"Showing the first 50 of {len(targets)} prioritized endpoints; the JSON report contains the complete inventory." if len(targets) > 50 else f"{len(targets)} endpoint(s) returned an HTTP response."
    return f"""
<h2>Confirmed responding web endpoints</h2><p class='muted'>{esc(note)} Successful, access-controlled, and redirecting responses are ordered ahead of lower-signal responses.</p>
<table><tr><th>Host</th><th>Status</th><th>URL</th><th>Title</th><th>Redirect</th><th>Technology</th></tr>{rows}</table>
"""


def _render_target_brief(lead: Dict[str, Any], report: Dict[str, Any]) -> str:
    facts = "".join(
        f"<li>{esc(fact.get('statement'))} <span class='muted'>{_reference_links(fact.get('evidence_ids', []), report)}</span></li>"
        for fact in lead.get("observed_facts", [])
    )
    next_steps = "".join(f"<li>{esc(item)}</li>" for item in lead.get("next_steps", []))
    caveats = "".join(f"<li>{esc(item)}</li>" for item in lead.get("caveats", [])) or "<li>None beyond the run-level collection limitations.</li>"
    priority = str(lead.get("priority", "P3"))
    return f"""<article class='brief {esc(priority)}'>
<h3><span class='badge {esc(priority)}'>{esc(priority)}</span> {esc(lead.get('host'))}</h3>
{_related_hosts(lead)}
<p><strong>Why it is interesting:</strong> {esc(lead.get('why_interesting'))}</p>
<p><strong>Pentester objective:</strong> {esc(lead.get('pentester_objective'))}</p>
<p><strong>Observed:</strong></p><ul class='compact'>{facts}</ul>
<p><strong>Suggested human follow-up:</strong></p><ul class='compact'>{next_steps}</ul>
<p><strong>Caveats:</strong></p><ul class='compact'>{caveats}</ul>
<p class='muted'>Confidence: {esc(lead.get('confidence'))}</p>
</article>"""


def _reference_links(evidence_ids: List[str], report: Dict[str, Any]) -> str:
    return " ".join(f"<a href='{evidence_link(item, report)}'>{esc(item)}</a>" for item in evidence_ids)


def _related_hosts(lead: Dict[str, Any]) -> str:
    related = lead.get("related_hosts", [])
    return f"<div class='muted'>Related: {esc(', '.join(related))}</div>" if related else ""


def observation_group(kind: str, items: List[Dict[str, Any]], report: Dict[str, Any]) -> str:
    rows = "".join(f"<tr><td>{esc(item.get('id'))}</td><td><pre>{html.escape(format_value(item.get('value_json')))}</pre></td><td>{esc(item.get('source_tool'))}</td><td><a href='{evidence_link(item.get('evidence_id'), report)}'>evidence</a></td><td>{esc(item.get('created_at'))}</td></tr>" for item in items)
    return f"<details><summary>{html.escape(kind)} ({len(items)})</summary><table><tr><th>ID</th><th>Value</th><th>Source</th><th>Evidence</th><th>Captured</th></tr>{rows}</table></details>"


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def format_value(value: Any) -> str:
    try:
        return json.dumps(json.loads(value), indent=2, sort_keys=True)
    except (TypeError, json.JSONDecodeError):
        return str(value or "")


def status_class(value: Any) -> str:
    value = str(value or "").lower()
    return value if value in {"success", "completed", "failed", "skipped"} else ""


def evidence_link(value: Any, report: Optional[Dict[str, Any]] = None) -> str:
    if report:
        for execution in report.get("executions", []):
            if execution.get("id") == value:
                return evidence_link(execution.get("raw_output_path"), report)
    if value:
        evidence_path = Path(str(value))
        if evidence_path.is_absolute() or str(value).startswith("evidence/"):
            output_dir = Path(str(report.get("_html_output_dir"))) if report and report.get("_html_output_dir") else Path.cwd()
            absolute_evidence = evidence_path if evidence_path.is_absolute() else (Path.cwd() / evidence_path)
            relative = os.path.relpath(absolute_evidence, start=output_dir)
            return html.escape(Path(relative).as_posix(), quote=True)
    return "#"


def _responsive_web_targets(profiles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    targets: List[Dict[str, Any]] = []
    for profile in profiles:
        for service in profile.get("http_services", []):
            targets.append({
                "host": profile["host"],
                "url": service.get("url"),
                "status_code": service.get("status_code"),
                "response_priority": profile.get("http_response_priority", "none"),
                "title": service.get("title"),
                "location": service.get("location"),
                "tech": service.get("tech", []),
                "server": service.get("webserver") or service.get("server"),
                "content_type": service.get("content_type"),
                "content_length": service.get("content_length"),
                "body_hash": service.get("hash"),
                "deterministic_priority": profile.get("deterministic_priority"),
                "internal_score": profile.get("internal_score", 0),
                "observation_id": service.get("observation_id"),
                "evidence_id": service.get("evidence_id"),
            })
    return sorted(
        targets,
        key=lambda item: (
            HTTP_RESPONSE_PRIORITY.get(str(item.get("response_priority")), 99),
            -int(item.get("internal_score", 0)),
            str(item.get("host", "")),
            str(item.get("url", "")),
        ),
    )
