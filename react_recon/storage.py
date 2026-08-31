from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .models import RunConfig, ToolResult, utc_now


class Store:
    def __init__(self, database: str, evidence_dir: str) -> None:
        self.database = database
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(database)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

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
        evidence_id = "evidence-" + uuid.uuid4().hex[:12]
        directory = self.evidence_dir / run_id
        directory.mkdir(parents=True, exist_ok=True)
        raw_path = directory / f"{evidence_id}.jsonl"
        record = {"run_id": run_id, "tool": result.tool, "target": result.target, "started_at": result.started_at, "finished_at": result.finished_at, "status": result.status, "return_code": result.return_code, "raw_output_path": str(raw_path), "normalized_observation_ids": []}
        with raw_path.open("w", encoding="utf-8") as handle:
            handle.write(json.dumps({**record, "stdout": result.stdout, "stderr": result.stderr}, sort_keys=True) + "\n")
        self.conn.execute("INSERT INTO executions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (evidence_id, run_id, result.tool, result.target, result.status, result.return_code, result.command, result.runner, result.started_at, result.finished_at, str(raw_path), result.stderr[-4000:]))
        observation_ids: List[str] = []
        for observation in result.observations:
            obs_id = self._insert_observation(run_id, observation, result.tool, evidence_id)
            observation_ids.append(obs_id)
        record["normalized_observation_ids"] = observation_ids
        with raw_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        self.conn.commit()
        return evidence_id

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

    def open_port_targets(self, run_id: str, authorized_hosts: Iterable[str]) -> List[Dict[str, Any]]:
        """Return authorized host/port pairs derived only from normalized evidence."""
        authorized = {item.lower().rstrip(".") for item in authorized_hosts}
        grouped: Dict[str, set] = {}
        rows = self.conn.execute("SELECT value_json FROM observations WHERE run_id=? AND type='open_port'", (run_id,))
        for row in rows:
            try:
                value = json.loads(row["value_json"])
                host = str(value.get("host", "")).lower().rstrip(".")
                port = int(value.get("port", 0))
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if host in authorized and 1 <= port <= 65535:
                grouped.setdefault(host, set()).add(port)
        return [{"host": host, "ports": sorted(ports)} for host, ports in sorted(grouped.items())]

    def candidate_hosts(self, run_id: str, limit: Optional[int] = None) -> List[str]:
        query = "SELECT host FROM assets WHERE run_id=? AND in_scope=1 ORDER BY host"
        parameters: List[Any] = [run_id]
        if limit is not None:
            query += " LIMIT ?"
            parameters.append(limit)
        return [row["host"] for row in self.conn.execute(query, parameters)]

    def resolved_hosts(self, run_id: str, limit: Optional[int] = None) -> List[str]:
        hosts = set()
        rows = self.conn.execute("SELECT value_json FROM observations WHERE run_id=? AND type LIKE 'dns_%'", (run_id,))
        for row in rows:
            try:
                host = json.loads(row["value_json"]).get("host")
            except (AttributeError, json.JSONDecodeError):
                continue
            if isinstance(host, str) and host:
                hosts.add(host.lower().rstrip("."))
        result = sorted(hosts)
        return result[:limit] if limit is not None else result

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
        if not existing:
            self.conn.execute(
                "INSERT INTO observations VALUES (?, ?, ?, ?, ?, ?, ?)",
                (obs_id, run_id, kind, value_json, source_tool, evidence_id, utc_now()),
            )
        host = observation.get("host") or (observation.get("value") if kind in {"hostname", "ct_hostname"} else None)
        if host and isinstance(host, str):
            self.conn.execute(
                "INSERT OR IGNORE INTO assets VALUES (?, ?, ?, ?, ?)",
                ("asset-" + uuid.uuid4().hex[:12], run_id, host.lower().rstrip("."), 1, utc_now()),
            )
        return obs_id

    def close(self) -> None:
        self.conn.close()
