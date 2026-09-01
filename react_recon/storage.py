from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlsplit

from .files import (
    ensure_private_directory,
    ensure_private_file,
    harden_evidence_tree,
    harden_sqlite_files,
    truncate_utf8,
    write_private_text,
)
from .models import RunConfig, ToolResult, utc_now
from .scope import address_in_authorized_networks, address_is_authorized, in_scope, normalize_host


def _serialize_evidence(record: Dict[str, Any], stdout: str, stderr: str) -> str:
    """Serialize one complete JSONL record for an execution."""
    return json.dumps(
        {**record, "stdout": stdout, "stderr": stderr}, sort_keys=True
    ) + "\n"


def _fit_evidence_payload(
    record: Dict[str, Any], stdout: str, stderr: str, maximum_bytes: int
) -> Optional[tuple[str, str, str]]:
    """Shrink raw streams until JSON escaping and metadata fit exactly."""
    while True:
        payload = _serialize_evidence(record, stdout, stderr)
        if len(payload.encode("utf-8")) <= maximum_bytes:
            return payload, stdout, stderr
        stdout_size = len(stdout.encode("utf-8"))
        stderr_size = len(stderr.encode("utf-8"))
        if stdout_size == 0 and stderr_size == 0:
            return None
        if stdout_size >= stderr_size and stdout_size:
            stdout = truncate_utf8(stdout, stdout_size // 2)[0]
        elif stderr_size:
            stderr = truncate_utf8(stderr, stderr_size // 2)[0]


class Store:
    def __init__(self, database: str, evidence_dir: str) -> None:
        database_path = Path(database)
        if not database_path.parent.exists():
            raise ValueError(f"database parent directory does not exist: {database_path.parent}")
        ensure_private_file(database_path)
        harden_sqlite_files(database_path)
        self.database = str(database_path)
        self.evidence_dir = Path(evidence_dir)
        self._harden_existing_evidence()
        ensure_private_directory(self.evidence_dir)
        self.conn = sqlite3.connect(self.database)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()
        harden_sqlite_files(database_path)

    def _harden_existing_evidence(self) -> None:
        """Tighten legacy files only inside recognized run/evidence paths."""
        harden_evidence_tree(self.evidence_dir)

    def _init_schema(self) -> None:
        # SQLite is durable controller memory. Raw stdout/stderr is kept in
        # append-only JSONL evidence so the database stays easy to query.
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, root_fqdn TEXT, mode TEXT, config_json TEXT, status TEXT, created_at TEXT, updated_at TEXT);
        CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, run_id TEXT, tool TEXT, arguments_json TEXT, status TEXT, attempts INTEGER DEFAULT 0, created_at TEXT, updated_at TEXT);
        CREATE TABLE IF NOT EXISTS assets (id TEXT PRIMARY KEY, run_id TEXT, host TEXT, in_scope INTEGER, created_at TEXT, UNIQUE(run_id, host));
        CREATE TABLE IF NOT EXISTS observations (id TEXT PRIMARY KEY, run_id TEXT, type TEXT, value_json TEXT, source_tool TEXT, evidence_id TEXT, created_at TEXT, UNIQUE(run_id, type, value_json));
        CREATE TABLE IF NOT EXISTS executions (id TEXT PRIMARY KEY, run_id TEXT, tool TEXT, target TEXT, status TEXT, return_code INTEGER, command TEXT, runner TEXT, started_at TEXT, finished_at TEXT, raw_output_path TEXT, stderr TEXT);
        CREATE TABLE IF NOT EXISTS analysis_runs (id TEXT PRIMARY KEY, run_id TEXT, provider TEXT NOT NULL DEFAULT 'openai', model TEXT, prompt_version TEXT, status TEXT, input_digest TEXT, input_json TEXT, output_json TEXT, error TEXT, created_at TEXT, updated_at TEXT);
        CREATE TABLE IF NOT EXISTS target_profiles (id TEXT PRIMARY KEY, analysis_id TEXT, run_id TEXT, host TEXT, priority TEXT, internal_score INTEGER, profile_json TEXT, created_at TEXT, UNIQUE(analysis_id, host));
        CREATE TABLE IF NOT EXISTS target_leads (id TEXT PRIMARY KEY, analysis_id TEXT, run_id TEXT, rank INTEGER, priority TEXT, host TEXT, lead_json TEXT, created_at TEXT, UNIQUE(analysis_id, rank), UNIQUE(analysis_id, host));
        """)
        columns = {row["name"] for row in self.conn.execute("PRAGMA table_info(analysis_runs)")}
        if "provider" not in columns:
            # Existing local databases predate provider selection. Their saved
            # analyses were OpenAI-backed, so the migration records that fact.
            self.conn.execute("ALTER TABLE analysis_runs ADD COLUMN provider TEXT NOT NULL DEFAULT 'openai'")
        self.conn.commit()

    def create_run(self, config: RunConfig) -> str:
        config.validate()
        run_id = "run-" + uuid.uuid4().hex[:12]
        now = utc_now()
        self.conn.execute("INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?)", (run_id, config.root_fqdn, config.mode, json.dumps(config.__dict__), "running", now, now))
        self.conn.commit()
        return run_id

    def get_run(self, run_id: str) -> sqlite3.Row:
        row = self.conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        if row is None:
            raise ValueError(f"unknown run: {run_id}")
        return row

    def finish_run(self, run_id: str, status: str) -> None:
        self.conn.execute("UPDATE runs SET status = ?, updated_at = ? WHERE id = ?", (status, utc_now(), run_id))
        self.conn.commit()

    def add_task(self, run_id: str, tool: str, arguments: Dict[str, Any]) -> str:
        task_id = "task-" + uuid.uuid4().hex[:12]
        now = utc_now()
        self.conn.execute("INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (task_id, run_id, tool, json.dumps(arguments), "pending", 0, now, now))
        self.conn.commit()
        return task_id

    def complete_task(self, task_id: str, status: str = "completed") -> None:
        self.conn.execute("UPDATE tasks SET status=?, updated_at=? WHERE id=?", (status, utc_now(), task_id))
        self.conn.commit()

    def record_result(self, run_id: str, result: ToolResult) -> str:
        # Persist raw evidence and then link normalized observations to the
        # execution, preserving provenance even when parsing returns nothing.
        config = self.run_config(run_id)
        observation_error = self._observation_budget_error(
            run_id, result.observations, config
        )
        if observation_error:
            result.status = "failed"
            result.observations = []
            result.limitations.append(observation_error)

        evidence_id = "evidence-" + uuid.uuid4().hex[:12]
        directory = self.evidence_dir / run_id
        ensure_private_directory(directory)
        raw_path = directory / f"{evidence_id}.jsonl"

        used_evidence_bytes = sum(
            path.stat().st_size
            for path in directory.glob("evidence-*.jsonl")
            if path.is_file() and not path.is_symlink()
        )
        remaining_evidence_bytes = max(0, config.max_evidence_bytes - used_evidence_bytes)
        stdout, stdout_truncated = truncate_utf8(result.stdout, config.max_output_bytes)
        stderr, stderr_truncated = truncate_utf8(result.stderr, config.max_output_bytes)
        if stdout_truncated or stderr_truncated:
            result.status = "failed"
            result.observations = []
            result.limitations.append(
                f"raw evidence limit exceeded: per-stream={config.max_output_bytes} bytes, run={config.max_evidence_bytes} bytes"
            )

        target, _ = truncate_utf8(result.target, 4096)
        command, _ = truncate_utf8(result.command, 16 * 1024)
        limitations = [truncate_utf8(str(item), 1024)[0] for item in result.limitations[:32]]
        record = {
            "run_id": run_id,
            "tool": result.tool,
            "target": target,
            "started_at": result.started_at,
            "finished_at": result.finished_at,
            "status": result.status,
            "return_code": result.return_code,
            "raw_output_path": str(raw_path),
            "normalized_observation_ids": ["obs-" + "0" * 12] * len(result.observations),
            "limitations": limitations,
        }
        payload = _serialize_evidence(record, stdout, stderr)
        if len(payload.encode("utf-8")) > remaining_evidence_bytes:
            result.status = "failed"
            result.observations = []
            message = (
                f"raw evidence limit exceeded: per-stream={config.max_output_bytes} bytes, "
                f"run={config.max_evidence_bytes} bytes"
            )
            if message not in result.limitations:
                result.limitations.append(message)
            record["status"] = "failed"
            record["normalized_observation_ids"] = []
            record["limitations"] = [
                truncate_utf8(str(item), 1024)[0] for item in result.limitations[:32]
            ]
            fitted = _fit_evidence_payload(
                record, stdout, stderr, remaining_evidence_bytes
            )
            if fitted is None:
                record["raw_output_path"] = ""
                fitted = _fit_evidence_payload(
                    record, "", "", remaining_evidence_bytes
                )
            if fitted is None:
                raw_output_path = ""
                payload = ""
                stdout = ""
                stderr = ""
            else:
                payload, stdout, stderr = fitted
                raw_output_path = str(raw_path)
        else:
            raw_output_path = str(raw_path)

        execution_stderr = result.stderr
        if not raw_output_path and result.limitations:
            execution_stderr = "\n".join(
                [execution_stderr, *[str(item) for item in result.limitations]]
            ).strip()
        try:
            self.conn.execute(
                "INSERT INTO executions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    evidence_id,
                    run_id,
                    result.tool,
                    target,
                    result.status,
                    result.return_code,
                    command,
                    result.runner,
                    result.started_at,
                    result.finished_at,
                    raw_output_path,
                    truncate_utf8(execution_stderr, 4000)[0],
                ),
            )
            observation_ids: List[str] = []
            for observation in result.observations:
                obs_id = self._insert_observation(
                    run_id, observation, result.tool, evidence_id
                )
                observation_ids.append(obs_id)
            record["normalized_observation_ids"] = observation_ids
            record["raw_output_path"] = raw_output_path
            if raw_output_path:
                payload = _serialize_evidence(record, stdout, stderr)
                if len(payload.encode("utf-8")) > remaining_evidence_bytes:
                    raise RuntimeError("final evidence serialization exceeded its reserved budget")
                write_private_text(raw_path, payload)
            self.conn.commit()
            return evidence_id
        except Exception:
            self.conn.rollback()
            raise

    def snapshot(self, run_id: str, compact: bool = False) -> Dict[str, Any]:
        # Reports use the full snapshot; the planner receives a bounded version
        # so long scans do not consume the model context window.
        run = dict(self.get_run(run_id))
        assets_query = "SELECT * FROM assets WHERE run_id=? ORDER BY host" + (" LIMIT 50" if compact else "")
        observations_query = "SELECT * FROM observations WHERE run_id=? ORDER BY created_at DESC" + (" LIMIT 20" if compact else "")
        assets = [dict(row) for row in self.conn.execute(assets_query, (run_id,))]
        observations = [dict(row) for row in self.conn.execute(observations_query, (run_id,))]
        executions_query = "SELECT * FROM executions WHERE run_id=? ORDER BY started_at" + (" DESC LIMIT 20" if compact else "")
        tasks_query = "SELECT * FROM tasks WHERE run_id=? ORDER BY created_at" + (" DESC LIMIT 20" if compact else "")
        result = {"run": run, "assets": assets, "observations": observations, "executions": [dict(row) for row in self.conn.execute(executions_query, (run_id,))], "tasks": [dict(row) for row in self.conn.execute(tasks_query, (run_id,))]}
        if compact:
            result["observations"] = [{"id": row["id"], "type": row["type"], "source_tool": row["source_tool"], "evidence_id": row["evidence_id"], "value": row["value_json"][:240]} for row in observations]
            result["executions"] = [{key: row.get(key) for key in ("id", "tool", "target", "status", "return_code", "started_at")} for row in result["executions"]]
            result["tasks"] = [{"id": row["id"], "tool": row["tool"], "status": row["status"], "arguments": row["arguments_json"][:500], "created_at": row["created_at"]} for row in result["tasks"]]
            result["observation_counts"] = {row["type"]: row["count"] for row in self.conn.execute("SELECT type, count(*) AS count FROM observations WHERE run_id=? GROUP BY type", (run_id,))}
            result["asset_count"] = self.conn.execute("SELECT count(*) FROM assets WHERE run_id=?", (run_id,)).fetchone()[0]
            result["execution_count"] = self.conn.execute("SELECT count(*) FROM executions WHERE run_id=?", (run_id,)).fetchone()[0]
            result["task_count"] = self.conn.execute("SELECT count(*) FROM tasks WHERE run_id=?", (run_id,)).fetchone()[0]
        return result

    def open_port_targets(self, run_id: str, eligible_targets: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return the exact hostname/IP/port tuples observed by Naabu."""
        eligible: Dict[str, set[str]] = {}
        for item in eligible_targets:
            if not isinstance(item, dict):
                continue
            try:
                host = normalize_host(str(item.get("host", "")))
            except ValueError:
                continue
            addresses = {
                str(address)
                for address in item.get("addresses", [])
                if isinstance(address, str)
            }
            if addresses:
                eligible[host] = addresses
        grouped: Dict[tuple[str, str], set[int]] = {}
        rows = self.conn.execute("SELECT value_json FROM observations WHERE run_id=? AND type='open_port'", (run_id,))
        for row in rows:
            try:
                value = json.loads(row["value_json"])
                host = normalize_host(str(value.get("host", "")))
                address = str(value.get("ip", ""))
                port = int(value.get("port", 0))
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if address in eligible.get(host, set()) and 1 <= port <= 65535:
                grouped.setdefault((host, address), set()).add(port)
        return [
            {"host": host, "ip": address, "ports": sorted(ports)}
            for (host, address), ports in sorted(grouped.items())
        ]

    def candidate_hosts(self, run_id: str, limit: Optional[int] = None) -> List[str]:
        # Always include the configured apex even when passive sources return no
        # subdomains; an operator-provided FQDN is itself a valid recon target.
        root = str(self.get_run(run_id)["root_fqdn"]).lower().rstrip(".")
        hosts = [root]
        rows = self.conn.execute(
            "SELECT type, value_json FROM observations WHERE run_id=? AND type IN ('hostname','ct_hostname','url_candidate') ORDER BY created_at",
            (run_id,),
        )
        for row in rows:
            try:
                value = json.loads(row["value_json"]).get("value", "")
                raw_host = urlsplit(value).hostname if row["type"] == "url_candidate" else value
                host = normalize_host(str(raw_host or ""))
            except (ValueError, json.JSONDecodeError):
                continue
            try:
                if in_scope(host, root, []):
                    hosts.append(host)
            except ValueError:
                continue
        result = sorted(set(hosts))
        return result[:limit] if limit is not None else result

    def resolved_hosts(self, run_id: str, limit: Optional[int] = None, source_tool: Optional[str] = None) -> List[str]:
        hosts = set()
        query = "SELECT value_json FROM observations WHERE run_id=? AND type IN ('dns_a','dns_aaaa','dns_cname')"
        parameters: List[Any] = [run_id]
        if source_tool:
            query += " AND source_tool=?"
            parameters.append(source_tool)
        rows = self.conn.execute(query, parameters)
        for row in rows:
            try:
                host = json.loads(row["value_json"]).get("host")
            except (AttributeError, json.JSONDecodeError):
                continue
            if isinstance(host, str) and host:
                hosts.add(host.lower().rstrip("."))
        result = sorted(hosts)
        return result[:limit] if limit is not None else result

    def approved_targets(
        self,
        run_id: str,
        config: RunConfig,
        *,
        source_tool: Optional[str] = None,
        active: bool = False,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Build fail-closed hostname/address tuples from current DNS evidence."""
        explicit = {normalize_host(item) for item in config.authorized_hosts}
        addresses: Dict[str, set[str]] = {}
        rejected: set[str] = set()
        excluded: set[str] = set()
        query = "SELECT type, value_json, created_at FROM observations WHERE run_id=? AND type IN ('dns_a','dns_aaaa','dns_cname','dns_cdn')"
        parameters: List[Any] = [run_id]
        if source_tool:
            query += " AND source_tool=?"
            parameters.append(source_tool)
        for row in self.conn.execute(query, parameters):
            try:
                value = json.loads(row["value_json"])
                host = normalize_host(str(value.get("host", "")))
            except (ValueError, json.JSONDecodeError):
                continue
            if not in_scope(host, config.root_fqdn, config.authorized_hosts):
                continue
            if row["type"] in {"dns_a", "dns_aaaa"}:
                try:
                    captured = datetime.fromisoformat(
                        str(row["created_at"]).replace("Z", "+00:00")
                    )
                    age = (datetime.now(timezone.utc) - captured).total_seconds()
                except (TypeError, ValueError):
                    rejected.add(host)
                    continue
                if age < 0 or age > config.max_dns_binding_age_seconds:
                    rejected.add(host)
                    continue
                try:
                    address = normalize_host(str(value.get("value", "")))
                except ValueError:
                    rejected.add(host)
                    continue
                destination_allowed = (
                    address_in_authorized_networks(address, config.authorized_networks)
                    if active
                    else address_is_authorized(address, config.authorized_networks)
                )
                if destination_allowed:
                    addresses.setdefault(host, set()).add(address)
                else:
                    # Mixed safe/unsafe answer sets fail closed for the host.
                    rejected.add(host)
            elif active and host not in explicit and row["type"] == "dns_cdn":
                excluded.add(host)
            elif active and host not in explicit and row["type"] == "dns_cname":
                try:
                    cname = normalize_host(str(value.get("value", "")))
                except ValueError:
                    excluded.add(host)
                    continue
                if not in_scope(cname, config.root_fqdn, config.authorized_hosts):
                    excluded.add(host)
        targets = [
            {"host": host, "addresses": sorted(host_addresses)}
            for host, host_addresses in sorted(addresses.items())
            if host_addresses and host not in rejected and host not in excluded
        ]
        return targets[:limit] if limit is not None else targets

    def permutation_candidates(self, run_id: str, limit: Optional[int] = None) -> List[str]:
        """Return unique in-scope AlterX names that were not already seed assets."""
        known = set(self.candidate_hosts(run_id))
        values = []
        rows = self.conn.execute("SELECT value_json FROM observations WHERE run_id=? AND type='permutation_candidate' ORDER BY created_at", (run_id,))
        for row in rows:
            try:
                value = json.loads(row["value_json"]).get("value")
                host = normalize_host(str(value))
            except (AttributeError, ValueError, json.JSONDecodeError):
                continue
            if host not in known:
                values.append(host)
        result = list(dict.fromkeys(values))
        return result[:limit] if limit is not None else result

    def active_scan_hosts(self, run_id: str, config: RunConfig, limit: Optional[int] = None) -> List[str]:
        """Select verified in-scope hosts while avoiding inferred shared infrastructure."""
        return [
            item["host"]
            for item in self.approved_targets(run_id, config, active=True, limit=limit)
        ]

    def execution_count(self, run_id: str) -> int:
        return int(self.conn.execute("SELECT count(*) FROM executions WHERE run_id=?", (run_id,)).fetchone()[0])

    def has_execution_failures(self, run_id: str) -> bool:
        return self.conn.execute("SELECT 1 FROM executions WHERE run_id=? AND status='failed' LIMIT 1", (run_id,)).fetchone() is not None

    def attempted_hosts(self, run_id: str, tool: str) -> List[str]:
        hosts = set()
        rows = self.conn.execute("SELECT arguments_json FROM tasks WHERE run_id=? AND tool=?", (run_id, tool))
        for row in rows:
            try:
                arguments = json.loads(row["arguments_json"])
            except json.JSONDecodeError:
                continue
            for host in arguments.get("hosts", []):
                if isinstance(host, str):
                    hosts.add(host.lower().rstrip("."))
            for target in arguments.get("targets", []):
                if isinstance(target, dict) and isinstance(target.get("host"), str):
                    hosts.add(target["host"].lower().rstrip("."))
        return sorted(hosts)

    def replace_execution_observations(self, run_id: str, evidence_id: str, observations: List[Dict[str, Any]]) -> int:
        execution = self.conn.execute("SELECT tool FROM executions WHERE id=? AND run_id=?", (evidence_id, run_id)).fetchone()
        if execution is None:
            raise ValueError(f"unknown execution evidence: {evidence_id}")
        error = self._observation_budget_error(
            run_id,
            observations,
            self.run_config(run_id),
            replacing_evidence_ids=[evidence_id],
        )
        if error:
            raise ValueError(error)
        self.conn.execute("DELETE FROM observations WHERE run_id=? AND evidence_id=?", (run_id, evidence_id))
        for observation in observations:
            self._insert_observation(run_id, observation, execution["tool"], evidence_id)
        self.conn.commit()
        return len(observations)

    def reprocess_observations(self, run_id: str, replacements: Dict[str, List[Dict[str, Any]]]) -> Dict[str, int]:
        """Atomically replace normalized rows for a set of preserved executions."""
        self.get_run(run_id)
        executions = {
            row["id"]: row["tool"]
            for row in self.conn.execute("SELECT id, tool FROM executions WHERE run_id=?", (run_id,))
        }
        unknown = set(replacements) - set(executions)
        if unknown:
            raise ValueError(f"unknown execution evidence IDs: {sorted(unknown)}")
        replacement_observations = [
            observation
            for observations in replacements.values()
            for observation in observations
        ]
        error = self._observation_budget_error(
            run_id,
            replacement_observations,
            self.run_config(run_id),
            replacing_evidence_ids=list(replacements),
        )
        if error:
            raise ValueError(error)
        try:
            self.conn.execute("BEGIN")
            for evidence_id in replacements:
                self.conn.execute("DELETE FROM observations WHERE run_id=? AND evidence_id=?", (run_id, evidence_id))
            for evidence_id, observations in replacements.items():
                for observation in observations:
                    self._insert_observation(run_id, observation, executions[evidence_id], evidence_id)

            run = self.get_run(run_id)
            try:
                config = json.loads(run["config_json"])
            except json.JSONDecodeError:
                config = {}
            root = str(run["root_fqdn"])
            authorized = {str(item).lower().rstrip(".") for item in config.get("authorized_hosts", [])}
            hosts = set()
            rows = self.conn.execute("SELECT type, value_json FROM observations WHERE run_id=?", (run_id,))
            for row in rows:
                try:
                    observation = json.loads(row["value_json"])
                except json.JSONDecodeError:
                    continue
                host = observation.get("host") or (observation.get("value") if row["type"] in {"hostname", "ct_hostname"} else None)
                if isinstance(host, str) and host:
                    hosts.add(host.lower().rstrip("."))
            self.conn.execute("DELETE FROM assets WHERE run_id=?", (run_id,))
            for host in sorted(hosts):
                in_scope = int(host == root or host.endswith("." + root) or host in authorized)
                self.conn.execute("INSERT INTO assets VALUES (?, ?, ?, ?, ?)", ("asset-" + uuid.uuid4().hex[:12], run_id, host, in_scope, utc_now()))
            stale = self.conn.execute(
                "UPDATE analysis_runs SET status='stale', updated_at=? WHERE run_id=? AND status='completed'",
                (utc_now(), run_id),
            ).rowcount
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return {
            "executions_reprocessed": len(replacements),
            "observations_written": sum(len(items) for items in replacements.values()),
            "assets_rebuilt": len(hosts),
            "analyses_marked_stale": stale,
        }

    def rebuild_assets(self, run_id: str) -> int:
        run = self.get_run(run_id)
        try:
            config = json.loads(run["config_json"])
        except json.JSONDecodeError:
            config = {}
        root = str(run["root_fqdn"])
        authorized = {str(item).lower().rstrip(".") for item in config.get("authorized_hosts", [])}
        hosts = set()
        rows = self.conn.execute("SELECT type, value_json FROM observations WHERE run_id=?", (run_id,))
        for row in rows:
            try:
                observation = json.loads(row["value_json"])
            except json.JSONDecodeError:
                continue
            host = observation.get("host") or (observation.get("value") if row["type"] in {"hostname", "ct_hostname"} else None)
            if isinstance(host, str) and host:
                hosts.add(host.lower().rstrip("."))
        self.conn.execute("DELETE FROM assets WHERE run_id=?", (run_id,))
        for host in sorted(hosts):
            in_scope = int(host == root or host.endswith("." + root) or host in authorized)
            self.conn.execute("INSERT INTO assets VALUES (?, ?, ?, ?, ?)", ("asset-" + uuid.uuid4().hex[:12], run_id, host, in_scope, utc_now()))
        self.conn.commit()
        return len(hosts)

    def mark_analyses_stale(self, run_id: str) -> int:
        cursor = self.conn.execute(
            "UPDATE analysis_runs SET status='stale', updated_at=? WHERE run_id=? AND status='completed'",
            (utc_now(), run_id),
        )
        self.conn.commit()
        return cursor.rowcount

    def create_analysis(
        self,
        run_id: str,
        model: str,
        prompt_version: str,
        input_digest: str,
        input_payload: Dict[str, Any],
        profiles: List[Dict[str, Any]],
        provider: str = "fixture",
    ) -> str:
        """Create an immutable analysis attempt and persist its deterministic input."""
        self.get_run(run_id)
        analysis_id = "analysis-" + uuid.uuid4().hex[:12]
        now = utc_now()
        self.conn.execute(
            "INSERT INTO analysis_runs (id, run_id, provider, model, prompt_version, status, input_digest, input_json, output_json, error, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (analysis_id, run_id, provider, model, prompt_version, "running", input_digest, json.dumps(input_payload, sort_keys=True), None, None, now, now),
        )
        for profile in profiles:
            self.conn.execute(
                "INSERT INTO target_profiles VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "profile-" + uuid.uuid4().hex[:12],
                    analysis_id,
                    run_id,
                    profile["host"],
                    profile["deterministic_priority"],
                    profile["internal_score"],
                    json.dumps(profile, sort_keys=True),
                    now,
                ),
            )
        self.conn.commit()
        return analysis_id

    def complete_analysis(self, analysis_id: str, output: Dict[str, Any]) -> None:
        row = self.conn.execute("SELECT run_id FROM analysis_runs WHERE id=?", (analysis_id,)).fetchone()
        if row is None:
            raise ValueError(f"unknown analysis: {analysis_id}")
        now = utc_now()
        self.conn.execute(
            "UPDATE analysis_runs SET status='completed', output_json=?, error=NULL, updated_at=? WHERE id=?",
            (json.dumps(output, sort_keys=True), now, analysis_id),
        )
        for lead in output.get("priority_targets", []):
            self.conn.execute(
                "INSERT INTO target_leads VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "lead-" + uuid.uuid4().hex[:12],
                    analysis_id,
                    row["run_id"],
                    int(lead["rank"]),
                    lead["priority"],
                    lead["host"],
                    json.dumps(lead, sort_keys=True),
                    now,
                ),
            )
        self.conn.commit()

    def fail_analysis(self, analysis_id: str, error: str) -> None:
        self.conn.execute(
            "UPDATE analysis_runs SET status='failed', error=?, updated_at=? WHERE id=?",
            (error[-4000:], utc_now(), analysis_id),
        )
        self.conn.commit()

    def latest_analysis(self, run_id: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            "SELECT * FROM analysis_runs WHERE run_id=? AND status='completed' ORDER BY created_at DESC LIMIT 1",
            (run_id,),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["input"] = json.loads(result.pop("input_json"))
        result["output"] = json.loads(result.pop("output_json"))
        result["profiles"] = [
            json.loads(profile["profile_json"])
            for profile in self.conn.execute("SELECT profile_json FROM target_profiles WHERE analysis_id=? ORDER BY internal_score DESC, host", (result["id"],))
        ]
        return result

    def latest_analysis_attempt(self, run_id: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            "SELECT id, run_id, provider, model, prompt_version, status, error, created_at, updated_at FROM analysis_runs WHERE run_id=? ORDER BY created_at DESC LIMIT 1",
            (run_id,),
        ).fetchone()
        return dict(row) if row is not None else None

    def _insert_observation(self, run_id: str, observation: Dict[str, Any], source_tool: str, evidence_id: str) -> str:
        # The uniqueness check makes repeated runs and evidence reprocessing
        # idempotent while preserving a single normalized fact per run.
        value_json = json.dumps(observation, sort_keys=True)
        kind = observation.get("type", "unknown")
        existing = self.conn.execute(
            "SELECT id FROM observations WHERE run_id=? AND type=? AND value_json=?",
            (run_id, kind, value_json),
        ).fetchone()
        obs_id = existing["id"] if existing else "obs-" + uuid.uuid4().hex[:12]
        captured_at = utc_now()
        if not existing:
            self.conn.execute(
                "INSERT INTO observations VALUES (?, ?, ?, ?, ?, ?, ?)",
                (obs_id, run_id, kind, value_json, source_tool, evidence_id, captured_at),
            )
        elif kind in {"dns_a", "dns_aaaa", "dns_cname", "dns_cdn"}:
            # DNS bindings are intentionally deduplicated by value, but a
            # repeated resolution is fresh evidence. Renew both timestamp and
            # provenance so an expired row cannot poison a later verification.
            self.conn.execute(
                "UPDATE observations SET source_tool=?, evidence_id=?, created_at=? "
                "WHERE id=?",
                (source_tool, evidence_id, captured_at, obs_id),
            )
        host = observation.get("host") or (observation.get("value") if kind in {"hostname", "ct_hostname"} else None)
        if host and isinstance(host, str):
            run = self.get_run(run_id)
            try:
                config = json.loads(run["config_json"])
            except json.JSONDecodeError:
                config = {}
            authorized = config.get("authorized_hosts", [])
            try:
                normalized = normalize_host(host)
                scoped = int(in_scope(normalized, str(run["root_fqdn"]), authorized))
            except ValueError:
                normalized, scoped = host.lower().rstrip("."), 0
            self.conn.execute(
                "INSERT OR IGNORE INTO assets VALUES (?, ?, ?, ?, ?)",
                ("asset-" + uuid.uuid4().hex[:12], run_id, normalized, scoped, utc_now()),
            )
        return obs_id

    def run_config(self, run_id: str) -> RunConfig:
        run = self.get_run(run_id)
        try:
            config = RunConfig(**json.loads(run["config_json"]))
            config.validate()
            return config
        except (TypeError, ValueError, json.JSONDecodeError):
            # Preserve evidence even for a legacy row with incomplete config;
            # current defaults still impose bounded, private storage.
            # Storage/reprocessing need conservative limits even when a legacy
            # active row predates mandatory destination CIDRs. Passive fallback
            # cannot authorize active port execution.
            fallback_mode = "passive" if run["mode"] == "active" else run["mode"]
            config = RunConfig(root_fqdn=run["root_fqdn"], mode=fallback_mode)
            config.validate()
            return config

    def _observation_budget_error(
        self,
        run_id: str,
        observations: List[Dict[str, Any]],
        config: RunConfig,
        *,
        replacing_evidence_ids: Optional[List[str]] = None,
    ) -> Optional[str]:
        """Validate count, individual size, and total normalized-byte budgets."""
        sizes: List[int] = []
        try:
            for observation in observations:
                size = len(
                    json.dumps(observation, sort_keys=True).encode("utf-8")
                )
                if size > config.max_observation_bytes:
                    return (
                        "observation size limit exceeded: configured per-observation "
                        f"ceiling is {config.max_observation_bytes} bytes"
                    )
                sizes.append(size)
        except (TypeError, ValueError):
            return "observation serialization failed"

        conditions = ["run_id=?"]
        parameters: List[Any] = [run_id]
        if replacing_evidence_ids:
            placeholders = ",".join("?" for _ in replacing_evidence_ids)
            conditions.append(f"evidence_id NOT IN ({placeholders})")
            parameters.extend(replacing_evidence_ids)
        row = self.conn.execute(
            "SELECT count(*) AS count, "
            "coalesce(sum(length(CAST(value_json AS BLOB))), 0) AS bytes "
            "FROM observations WHERE " + " AND ".join(conditions),
            parameters,
        ).fetchone()
        if int(row["count"]) + len(observations) > config.max_observations:
            return (
                "observation limit exceeded: configured run ceiling is "
                f"{config.max_observations}"
            )
        if int(row["bytes"]) + sum(sizes) > config.max_normalized_bytes:
            return (
                "normalized observation byte limit exceeded: configured run "
                f"ceiling is {config.max_normalized_bytes} bytes"
            )
        return None

    def close(self) -> None:
        self.conn.close()
        harden_sqlite_files(Path(self.database))
