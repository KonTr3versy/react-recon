from __future__ import annotations

import time
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

from .coverage import ACTIVE_EXPANSION, PASSIVE_BASELINE, CoveragePlanner, build_coverage
from .executor import Executor
from .models import Decision, RunConfig, ToolResult
from .planning import (
    TARGET_TOOLS,
    AdaptivePlanner,
    arguments_for_candidates,
    build_action_catalog,
    evaluate_progress,
    expected_tool_candidates,
    progress_metrics,
    task_candidate_keys,
)
from .storage import Store
from .providers import redact_provider_error


# Every executable action is a registered operation, not a shell interface.
# Target files, network bindings, commands, flags, and Docker arguments remain
# controller/executor-owned regardless of which model provider is selected.
TOOLS = {
    "crtsh_search": {"root_fqdn": {"type": "string"}},
    "discover_subdomains": {"root_fqdn": {"type": "string"}},
    "resolve_dns": {"hosts": {"type": "array", "items": {"type": "string"}}},
    "probe_http": {"hosts": {"type": "array", "items": {"type": "string"}}},
    "generate_permutations": {"hosts": {"type": "array", "items": {"type": "string"}}},
    "resolve_permutations": {"hosts": {"type": "array", "items": {"type": "string"}}},
    "probe_permutation_http": {"hosts": {"type": "array", "items": {"type": "string"}}},
    "discover_ports": {"hosts": {"type": "array", "items": {"type": "string"}}},
    "fingerprint_services": {},
    "retrieve_passive_urls": {"root_fqdn": {"type": "string"}},
    "finish_recon": {"summary": {"type": "string"}},
}


class ReconAgent:
    def __init__(
        self,
        store: Store,
        config: RunConfig,
        planner: Any = None,
        executor: Any = None,
        adaptive_planner: Any = None,
        progress: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        config.validate()
        self.store = store
        self.config = config
        # A supplied legacy planner still controls the complete loop for test
        # fixtures and API compatibility. Normal CLI runs use the hybrid flow.
        self.custom_planner = planner
        self.executor = executor or Executor(config)
        self._adaptive_planner = adaptive_planner
        self._progress = progress or (lambda event: None)

    def run(self, run_id: Optional[str] = None) -> str:
        run_id = run_id or self.store.create_run(self.config)
        calls = self.store.execution_count(run_id)
        started = time.monotonic()
        try:
            if self.custom_planner is not None:
                return self._run_custom(run_id, calls, started)

            baseline_complete, calls = self._run_coverage_phase(
                run_id,
                calls,
                started,
                PASSIVE_BASELINE,
                phase="baseline",
            )
            if not baseline_complete:
                self.store.finish_run(run_id, "stopped")
                return run_id

            if (
                self.config.mode == "active"
                and self.config.planning_mode == "hybrid"
                and self.config.max_adaptive_actions > 0
            ):
                calls = self._run_adaptive_phase(run_id, calls, started)

            if self.config.mode == "active":
                active_complete, calls = self._run_coverage_phase(
                    run_id,
                    calls,
                    started,
                    (*ACTIVE_EXPANSION, "fingerprint_services"),
                    phase="fallback",
                )
                if not active_complete:
                    self.store.finish_run(run_id, "stopped")
                    return run_id

            self._finish_completed_run(run_id)
            return run_id
        except KeyboardInterrupt:
            self.store.finish_run(run_id, "stopped")
            self._emit_progress("run_interrupted", run_id=run_id)
            raise
        except Exception:
            # Keep failure state durable so the operator can inspect evidence
            # and resume rather than losing the last controller state.
            self.store.finish_run(run_id, "failed")
            self._emit_progress("run_failed", run_id=run_id)
            raise

    def _run_coverage_phase(
        self,
        run_id: str,
        calls: int,
        started: float,
        stages: Sequence[str],
        *,
        phase: str,
    ) -> Tuple[bool, int]:
        planner = CoveragePlanner(self.store, stages=stages)
        while self._within_run_budget(calls, started):
            decision = planner.choose(
                self.store.snapshot(run_id, compact=True), self.config
            )
            if decision.tool == "finish_recon":
                return True, calls
            self._execute_decision(
                run_id,
                decision,
                phase=phase,
                decision_record={
                    "rationale": decision.rationale,
                    "expected_observation": decision.expected_observation,
                    "stop_condition": decision.stop_condition,
                },
            )
            calls += 1
        return False, calls

    def _run_adaptive_phase(
        self, run_id: str, calls: int, started: float
    ) -> int:
        # A durable stop marker prevents resume from re-opening a completed or
        # failed adaptive phase. Deterministic fallback remains resumable.
        if self.store.adaptive_stop_reason(run_id):
            return calls
        action_count = self.store.adaptive_action_count(run_id)
        no_progress_streak = self.store.adaptive_no_progress_streak(run_id)
        while (
            action_count < self.config.max_adaptive_actions
            and self._within_run_budget(calls, started)
        ):
            catalog = build_action_catalog(self.store, run_id, self.config)
            if not catalog.entries:
                self._record_adaptive_stop(run_id, "no_eligible_actions")
                break
            planner = self._get_adaptive_planner()
            coverage = build_coverage(self.store, run_id)
            payload = {
                "run": {
                    "id": run_id,
                    "root_fqdn": self.config.root_fqdn,
                    "mode": self.config.mode,
                },
                "remaining_budgets": {
                    "adaptive_actions": self.config.max_adaptive_actions
                    - action_count,
                    "tool_calls": self.config.max_tool_calls - calls,
                    "seconds": max(
                        0,
                        int(
                            self.config.max_duration_seconds
                            - (time.monotonic() - started)
                        ),
                    ),
                },
                "coverage_gaps": coverage["gaps"][:12],
                "available_actions": catalog.cards,
                "previous_adaptive_actions": self.store.adaptive_history(run_id)[
                    -6:
                ],
            }
            try:
                adaptive = planner.choose(payload)
                arguments = catalog.resolve(adaptive)
            except Exception as exc:
                reason = (
                    "invalid_decision" if isinstance(exc, ValueError) else "provider_error"
                )
                self._record_adaptive_stop(
                    run_id,
                    reason,
                    provider=getattr(planner, "provider", self.config.ai_provider),
                    model=getattr(planner, "model", self.config.ai_model),
                    error=redact_provider_error(exc),
                )
                break

            decision_record = adaptive.as_record(
                getattr(planner, "provider", self.config.ai_provider),
                getattr(planner, "model", self.config.ai_model),
            )
            if adaptive.tool == "finish_recon":
                task_id = self.store.add_task(
                    run_id,
                    "finish_recon",
                    {},
                    phase="adaptive",
                    decision=decision_record,
                )
                self.store.complete_task(
                    task_id,
                    "completed",
                    progress={
                        "made_progress": False,
                        "progress_basis": "none",
                        "stop_reason": "explicit_finish",
                    },
                )
                break

            before = progress_metrics(
                self.store, run_id, self.config, adaptive.tool
            )
            task_id, result = self._execute_decision(
                run_id,
                Decision(
                    adaptive.tool,
                    arguments,
                    rationale=adaptive.rationale,
                    expected_observation=adaptive.expected_observation,
                    stop_condition=adaptive.stop_condition,
                ),
                phase="adaptive",
                decision_record=decision_record,
            )
            calls += 1
            action_count += 1
            after = progress_metrics(
                self.store, run_id, self.config, adaptive.tool
            )
            progress = evaluate_progress(before, after, result.status)
            if progress["made_progress"]:
                no_progress_streak = 0
            else:
                no_progress_streak += 1

            if no_progress_streak >= 2:
                progress["stop_reason"] = "no_progress_or_repeated_failure"
            elif action_count >= self.config.max_adaptive_actions:
                progress["stop_reason"] = "adaptive_action_limit"
            elif not self._within_run_budget(calls, started):
                progress["stop_reason"] = "run_budget_exhausted"
            self.store.update_task_progress(task_id, progress)
            self._emit_progress(
                "adaptive_progress",
                phase="adaptive",
                completed=action_count,
                total=self.config.max_adaptive_actions,
                tool=adaptive.tool,
                status=result.status,
            )
            if progress.get("stop_reason"):
                break
        return calls

    def _run_custom(self, run_id: str, calls: int, started: float) -> str:
        while self._within_run_budget(calls, started):
            snapshot = self.store.snapshot(run_id, compact=True)
            decision = self.custom_planner.choose(snapshot, self.config)
            if decision.tool == "finish_recon":
                self._finish_completed_run(run_id)
                return run_id
            decision.arguments = self._legacy_controller_arguments(
                run_id, decision.tool
            )
            self._execute_decision(
                run_id,
                decision,
                phase="custom",
                decision_record={"rationale": decision.rationale},
            )
            calls += 1
        self.store.finish_run(run_id, "stopped")
        return run_id

    def _execute_decision(
        self,
        run_id: str,
        decision: Decision,
        *,
        phase: str,
        decision_record: Dict[str, Any],
    ) -> Tuple[str, ToolResult]:
        self._validate_decision(decision)
        # Adapters may create their own temporary files, but neither a model nor
        # a custom planner can point one at an arbitrary local path.
        arguments = dict(decision.arguments)
        arguments.pop("input_file", None)
        task_id = self.store.add_task(
            run_id,
            decision.tool,
            arguments,
            phase=phase,
            decision=decision_record,
        )
        collector = Executor.collector_name(decision.tool)
        timeout_seconds = (
            self.executor.tool_timeout_seconds(decision.tool)
            if hasattr(self.executor, "tool_timeout_seconds")
            else max(
                1,
                min(
                    Executor.TOOL_TIMEOUT_SECONDS.get(
                        decision.tool, self.config.max_duration_seconds
                    ),
                    self.config.max_duration_seconds,
                ),
            )
        )
        execution_started = time.monotonic()
        self._emit_progress(
            "tool_started",
            phase=phase,
            tool=decision.tool,
            collector=collector,
            timeout_seconds=timeout_seconds,
        )
        try:
            result: ToolResult = self.executor.execute(decision.tool, arguments)
            self.store.record_result(run_id, result)
            coverage_progress = self._target_coverage_progress(
                decision.tool, arguments, result
            )
            self.store.complete_task(
                task_id,
                "completed"
                if result.status in {"success", "skipped"}
                else "failed",
                progress=coverage_progress,
            )
            self._emit_progress(
                "tool_completed",
                phase=phase,
                tool=decision.tool,
                collector=collector,
                status=result.status,
                duration_seconds=round(time.monotonic() - execution_started, 3),
                observations=len(result.observations),
                timed_out=any("timed out" in item for item in result.limitations),
            )
            return task_id, result
        except BaseException as exc:
            self.store.complete_task(task_id, "failed")
            self._emit_progress(
                "tool_interrupted"
                if isinstance(exc, KeyboardInterrupt)
                else "tool_failed",
                phase=phase,
                tool=decision.tool,
                collector=collector,
                duration_seconds=round(time.monotonic() - execution_started, 3),
            )
            raise

    def _emit_progress(self, event: str, **details: Any) -> None:
        self._progress({"event": event, **details})

    @staticmethod
    def _target_coverage_progress(
        tool: str, arguments: Dict[str, Any], result: ToolResult
    ) -> Optional[Dict[str, Any]]:
        """Map trusted adapter outcomes back to the task's canonical keys."""
        if not result.target_outcomes:
            return None
        allowed = task_candidate_keys(tool, arguments)
        attempted: set[str] = set()
        completed: set[str] = set()
        failed: set[str] = set()
        approved = arguments.get("approved_addresses", {})
        if not isinstance(approved, dict):
            approved = {}
        for outcome in result.target_outcomes:
            if not isinstance(outcome, dict):
                continue
            status = outcome.get("status")
            if status not in {"completed", "failed", "unattempted"}:
                continue
            if tool == "fingerprint_services":
                outcome_arguments = {"targets": [outcome]}
            else:
                host = outcome.get("host")
                if not isinstance(host, str):
                    continue
                outcome_arguments = {
                    "hosts": [host],
                    "approved_addresses": {host: approved.get(host, [])},
                }
            keys = task_candidate_keys(tool, outcome_arguments) & allowed
            if status == "completed":
                attempted.update(keys)
                completed.update(keys)
            elif status == "failed":
                attempted.update(keys)
                failed.update(keys)
        # A conflicting completion/failure is treated as a failure.
        completed.difference_update(failed)
        return {
            "coverage": {
                "attempted_keys": sorted(attempted),
                "completed_keys": sorted(completed),
                "failed_keys": sorted(failed),
            }
        }

    def _legacy_controller_arguments(
        self, run_id: str, tool: str
    ) -> Dict[str, Any]:
        if tool in {
            "crtsh_search",
            "discover_subdomains",
            "retrieve_passive_urls",
        }:
            return {"root_fqdn": self.config.root_fqdn}
        if tool in TARGET_TOOLS:
            candidates = expected_tool_candidates(
                self.store, run_id, self.config, tool
            )
            return arguments_for_candidates(tool, candidates)
        return {}

    def _get_adaptive_planner(self) -> Any:
        if self._adaptive_planner is None:
            self._adaptive_planner = AdaptivePlanner(
                self.config.ai_provider, self.config.ai_model or None
            )
        return self._adaptive_planner

    def _record_adaptive_stop(
        self,
        run_id: str,
        reason: str,
        *,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        error: Optional[str] = None,
    ) -> None:
        decision = {
            "provider": provider or self.config.ai_provider,
            "model": model or self.config.ai_model,
            "candidate_ids": [],
            "error": error,
        }
        tool = "adaptive_planner" if error else "finish_recon"
        task_id = self.store.add_task(
            run_id,
            tool,
            {},
            phase="adaptive",
            decision=decision,
        )
        self.store.complete_task(
            task_id,
            "failed" if error else "completed",
            progress={
                "made_progress": False,
                "progress_basis": "none",
                "stop_reason": reason,
            },
        )

    def _within_run_budget(self, calls: int, started: float) -> bool:
        return (
            calls < self.config.max_tool_calls
            and time.monotonic() - started < self.config.max_duration_seconds
        )

    def _finish_completed_run(self, run_id: str) -> None:
        status = (
            "completed_with_gaps"
            if self.store.has_execution_failures(run_id)
            else "completed"
        )
        self.store.finish_run(run_id, status)

    def _validate_decision(self, decision: Decision) -> None:
        if decision.tool not in TOOLS or decision.tool == "finish_recon":
            raise ValueError(f"invalid planner tool: {decision.tool}")
        if decision.tool in {
            "crtsh_search",
            "discover_subdomains",
            "retrieve_passive_urls",
        } and decision.arguments.get("root_fqdn") != self.config.root_fqdn:
            raise ValueError(
                f"{decision.tool} must use the configured root FQDN"
            )
        if decision.tool in TARGET_TOOLS - {"fingerprint_services"}:
            hosts = decision.arguments.get("hosts", [])
            if not isinstance(hosts, list) or not all(
                isinstance(item, str) for item in hosts
            ):
                raise ValueError(f"{decision.tool} hosts must be a list of strings")
        if decision.tool == "fingerprint_services" and not isinstance(
            decision.arguments.get("targets", []), list
        ):
            raise ValueError("fingerprint_services targets must be a list")
