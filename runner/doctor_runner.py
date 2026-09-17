"""
AI Doctor Autonomous Runner.
Executes the autonomous troubleshooting and recovery loop:
DETECT -> DIAGNOSE -> FIX -> VERIFY -> RETRY
"""

import time
from typing import Dict, Any, List, Optional
from datetime import datetime
from .timeutil import now_iso

from .tool_registry import diagnostic_registry
from .remediation_registry import remediation_registry
from .diagnostics import record_log
from .diagnosis import diagnose
from .ollama_runtime import OLLAMA_NOT_INSTALLED, OLLAMA_RUNNING, OLLAMA_UNHEALTHY


class DoctorRunner:
    """Orchestrates autonomous failure detection, evidence collection, and remediation."""

    def __init__(self):
        self.diagnostic_registry = diagnostic_registry
        self.remediation_registry = remediation_registry

    def collect_evidence(self) -> Dict[str, Any]:
        """
        Executes safe diagnostic tools to gather verifiable system evidence.
        """
        port_data = self.diagnostic_registry.execute("check_port", port=11434)
        process_data = self.diagnostic_registry.execute("check_process", process_name="ollama")
        ollama_data = self.diagnostic_registry.execute("check_ollama")
        runtime_data = self.diagnostic_registry.execute("check_ollama_runtime")
        logs_data = self.diagnostic_registry.execute("get_recent_logs", limit=10)

        return {
            "collected_at": now_iso(),
            # Authoritative runtime state. Lets the engine report
            # OLLAMA_NOT_INSTALLED instead of mistaking an absent binary for an
            # outage - both look identical on a port/API probe.
            "runtime": runtime_data.get("result", {}),
            "port_11434": port_data.get("result", {}),
            "process_ollama": process_data.get("result", {}),
            "ollama_api": ollama_data.get("result", {}),
            "recent_logs": logs_data.get("result", {}).get("logs", []),
        }

    def diagnose_root_cause(self, evidence: Dict[str, Any], initial_error: str) -> Dict[str, Any]:
        """
        Analyzes collected evidence to deduce the root cause and select an
        allowlisted remediation.

        Delegates to runner.diagnosis, which is the single source of truth for
        the decision table. This method used to carry its own copy of that
        table while agent/strands_agent.py carried a second, already-diverged
        copy; both now resolve through the same engine.

        Returns the historical keys (root_cause, recommended_remediation,
        confidence) plus additive fields describing which probes corroborated
        the conclusion. Confidence is evidence-derived, not a constant.
        """
        return diagnose(evidence, initial_error).as_dict()

    def diagnose_incident(
        self,
        incident_data: Dict[str, Any],
        evidence: Dict[str, Any],
        detected_error: str,
        incident_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Chooses the diagnosis engine according to `AI_DOCTOR_AGENT_MODE`.

        In deterministic mode this is `diagnose_root_cause` plus two labelling
        fields, so the offline behaviour and every existing assertion are
        unchanged. In bedrock mode it performs a real Amazon Bedrock invocation
        through the AWS Strands Agents SDK and returns a schema-validated,
        policy-gated report.

        The returned dict always carries `agent_mode`, `agent_status`,
        `agent_note` and `agent_telemetry`, so no consumer can mistake a rule
        engine conclusion for a model conclusion.

        The agent package is imported here rather than at module scope: it
        depends on `runner.redaction`, `runner.tool_registry` and
        `runner.remediation_registry`, and a deferred import keeps that
        relationship one-directional.
        """
        from agent.diagnosis_agent import run_diagnosis as run_agent_diagnosis

        payload = dict(incident_data or {})
        payload.setdefault("detected_error", detected_error)
        outcome = run_agent_diagnosis(payload, evidence, incident_id=incident_id)

        report = dict(outcome.report)
        report["agent_telemetry"] = outcome.telemetry.as_dict()
        report["policy_decision"] = outcome.policy_event
        report["bedrock_failure"] = outcome.bedrock_failure
        report["used_llm"] = outcome.used_llm
        return report

    def run_remediation_and_verify(
        self,
        remediation_action: str,
        failed_request_context: Optional[Dict[str, Any]] = None,
        incident_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Safely executes remediation from allowlist, verifies service health, and retries the original request.
        """
        record_log("INFO", f"Initiating remediation action: {remediation_action}", service="doctor_runner")

        # "none" means the diagnosis layer approved no action at all - a
        # requires_human escalation, a refused model recommendation, or an
        # exhausted iteration budget. It is handled here rather than pushed
        # through the registry: the allowlist would reject it and log
        # "SECURITY ALERT: Remediation action 'none' was BLOCKED", which is a
        # false alarm for a deliberate no-op and would send an on-call engineer
        # looking for an attack that did not happen. The incident still ends
        # unresolved, which is the point.
        if remediation_action in (None, "", "none"):
            record_log(
                "INFO",
                "No remediation attempted: the diagnosis approved no action "
                "(requires_human or refused recommendation).",
                service="doctor_runner",
            )
            return {
                "success": False,
                "stage": "FIX",
                "action": "none",
                "no_action_taken": True,
                "error": (
                    "No remediation was attempted: the diagnosis did not approve an "
                    "allowlisted action for this incident."
                ),
            }

        ctx = failed_request_context or {}
        # When the diagnosis is retry_request, the remediation *is* the replay
        # of the original transaction. That has to be recognised here, or the
        # action gets invoked with no arguments (raising TypeError, which the
        # registry reports as a FIX failure) and then replayed a second time.
        is_retry_action = remediation_action == "retry_request"

        # 1. Execute safe remediation via allowlist
        kwargs: Dict[str, Any] = {}
        if is_retry_action:
            if not ctx.get("url"):
                return {
                    "success": False,
                    "stage": "FIX",
                    "action": remediation_action,
                    "error": (
                        "retry_request requires a captured request URL, but this incident "
                        "has no request context to replay."
                    ),
                }
            kwargs = {
                "url": ctx["url"],
                "method": ctx.get("method", "GET"),
                "payload": ctx.get("payload"),
                "headers": ctx.get("headers"),
            }

        remediation_result = self.remediation_registry.execute(
            remediation_action, incident_id=incident_id, **kwargs
        )
        if not remediation_result.get("success", False):
            return {
                "success": False,
                "stage": "FIX",
                "action": remediation_action,
                "error": remediation_result.get("error", "Remediation failed"),
                # Preserve the action's own output so the timeline can show
                # what the remediation actually reported.
                "remediation_result": remediation_result.get("result"),
            }

        # 2. VERIFY: poll the authoritative runtime state.
        #
        # Port-open plus an HTTP answer is not sufficient: any process listening
        # on 11434 satisfies both, which is how a dead daemon used to be
        # reported as a successful recovery (defect D1). OLLAMA_RUNNING requires
        # a live process whose identity matches, an open port, and a healthy API.
        verified = False
        verification_details = None
        last_state = None
        for attempt in range(15):
            time.sleep(0.3)
            runtime_check = self.diagnostic_registry.execute("check_ollama_runtime").get("result", {})
            last_state = runtime_check.get("state")

            if last_state == OLLAMA_RUNNING:
                verified = True
                verification_details = {
                    "runtime_state": OLLAMA_RUNNING,
                    "pid": runtime_check.get("pid"),
                    "executable": runtime_check.get("executable"),
                    "ollama_version": runtime_check.get("version"),
                    "port_open": True,
                    "api_available": True,
                    "api_status_code": runtime_check.get("api_status_code"),
                    "verification_time": now_iso(),
                }
                break

            # The API answers and the port is open, but no process matched the
            # ollama identity. That is a blind process probe (container or
            # namespace boundary, insufficient permission), not an outage -
            # record it as verified with the caveat made explicit.
            if (
                last_state == OLLAMA_UNHEALTHY
                and runtime_check.get("api_healthy")
                and runtime_check.get("port_open")
            ):
                verified = True
                verification_details = {
                    "runtime_state": last_state,
                    "pid": None,
                    "port_open": True,
                    "api_available": True,
                    "api_status_code": runtime_check.get("api_status_code"),
                    "process_probe_blind": True,
                    "verification_time": now_iso(),
                }
                record_log(
                    "WARN",
                    "Verification: the Ollama API answered on 11434 but no process matched "
                    "the ollama identity; the process probe is likely blind here.",
                    service="doctor_runner",
                )
                break

        if not verified:
            return {
                "success": False,
                "stage": "VERIFY",
                "action": remediation_action,
                "runtime_state": last_state,
                "error": (
                    "Service verification failed: the Ollama runtime never reached the RUNNING "
                    f"state after '{remediation_action}' (last observed state: {last_state}). "
                    "A listener on port 11434 is not accepted as proof of recovery."
                ),
            }

        record_log("INFO", "Service verification succeeded. Ollama is healthy on port 11434.", service="doctor_runner")

        # 3. RETRY: Re-issue original request if context was preserved
        retry_result = None
        if is_retry_action:
            # The remediation already replayed the transaction. Report that
            # outcome instead of issuing the same request a second time.
            retry_result = remediation_result.get("result", {})
        elif ctx.get("url"):
            retry_res = self.remediation_registry.execute(
                "retry_request",
                incident_id=incident_id,
                url=ctx["url"],
                method=ctx.get("method", "GET"),
                payload=ctx.get("payload"),
                headers=ctx.get("headers"),
            )
            retry_result = retry_res.get("result", {})

        return {
            "success": True,
            "remediation_result": remediation_result.get("result"),
            "verification": verification_details,
            "retry_result": retry_result,
        }

    def heal_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Full end-to-end healing loop for an incident:
        DETECTED -> INVESTIGATING -> ROOT CAUSE FOUND -> REMEDIATION -> VERIFYING -> RESOLVED
        """
        timeline = []
        now = now_iso

        incident_id = incident_data.get("incident_id") or incident_data.get("id")

        # Mark the audit log so this incident records exactly the remediation
        # entries its own actions produced, rather than a shared global tail.
        audit_mark = self.remediation_registry.audit_snapshot()

        # The Incident model stores the failure message as "detected_error";
        # callers building an ad-hoc dict may use "error". Reading only the
        # latter made every DETECTED entry read "Unknown error" on the live
        # path, discarding the one detail an on-call engineer reads first.
        detected_error = (
            incident_data.get("detected_error")
            or incident_data.get("error")
            or "Unknown error"
        )

        # 1. DETECTED
        timeline.append({"stage": "DETECTED", "timestamp": now(), "description": "Failure detected: " + detected_error})

        # 2. INVESTIGATING
        timeline.append({"stage": "INVESTIGATING", "timestamp": now(), "description": "Collecting system evidence via diagnostic tools"})
        evidence = self.collect_evidence()

        # 3. ROOT CAUSE FOUND
        # Which engine answered is decided by AI_DOCTOR_AGENT_MODE and recorded
        # on the incident: a deterministic rule-engine conclusion is never
        # presented as a Bedrock diagnosis, and vice versa.
        diagnosis = self.diagnose_incident(
            incident_data, evidence, detected_error, incident_id=incident_id
        )
        agent_mode = diagnosis.get("agent_mode") or "deterministic"
        agent_status = diagnosis.get("agent_status")
        engine_label = (
            f"Amazon Bedrock model {diagnosis.get('agent_telemetry', {}).get('model_id')}"
            if agent_mode == "bedrock"
            else "deterministic offline rule engine"
        )
        timeline.append({
            "stage": "ROOT CAUSE FOUND",
            "timestamp": now(),
            "description": f"[{engine_label}] {diagnosis['root_cause']}",
            "details": diagnosis,
        })

        # 4. REMEDIATION
        remediation_action = diagnosis["recommended_remediation"]
        remediation_started_at = now()

        # 5. VERIFYING & RETRY
        recovery_outcome = self.run_remediation_and_verify(
            remediation_action=remediation_action,
            failed_request_context=incident_data.get("request_context"),
            incident_id=incident_id,
        )

        # First-class record of what the allowlisted action itself reported, and
        # the audit trail of every allowlist decision taken for this incident.
        action_result = recovery_outcome.get("remediation_result")
        audit_log = self.remediation_registry.audit_since(audit_mark)

        # Which stage actually failed. "FIX" means the allowlisted action
        # itself reported failure; "VERIFY" means it ran but the service never
        # came back. Previously both were recorded against VERIFYING, so a
        # broken remediation looked like a verification timeout.
        failed_stage = recovery_outcome.get("stage")
        fix_succeeded = failed_stage != "FIX"

        timeline.append({
            "stage": "REMEDIATION",
            "timestamp": remediation_started_at,
            "description": (
                f"Executing allowlisted action: {remediation_action}"
                if fix_succeeded
                else f"Allowlisted action '{remediation_action}' failed: {recovery_outcome.get('error')}"
            ),
            "details": {
                "action": remediation_action,
                "allowlisted": self.remediation_registry.is_allowed(remediation_action),
                "fix_succeeded": fix_succeeded,
                "result": action_result,
                "audit_entries": len(audit_log),
                "error": None if fix_succeeded else recovery_outcome.get("error"),
            },
        })

        timeline.append({
            "stage": "VERIFYING",
            "timestamp": now(),
            "description": (
                "Verifying port 11434 and Ollama HTTP endpoint availability"
                if fix_succeeded
                else "Skipped: the remediation action itself failed, so there was no restored service to verify."
            ),
            "verified": recovery_outcome["success"],
            "details": recovery_outcome.get("verification") if fix_succeeded else None,
        })

        # 6. RESOLVED / FAILED
        if recovery_outcome["success"]:
            retry_result = recovery_outcome.get("retry_result")
            retried = isinstance(retry_result, dict)
            retry_ok = bool(retried and retry_result.get("success"))
            if not retried:
                replay_note = "No captured request context was available to replay."
            elif retry_ok:
                replay_note = "The original operation was replayed and succeeded."
            else:
                replay_note = (
                    "Service health was restored, but the replayed request did not succeed "
                    f"({retry_result.get('error') or retry_result.get('status_code')})."
                )
            timeline.append({
                "stage": "RESOLVED",
                "timestamp": now(),
                "description": f"All services healthy. {replay_note}",
                "details": {"retry_succeeded": retry_ok, "request_replayed": retried},
            })
            final_status = "RESOLVED"
        else:
            timeline.append({
                "stage": "FAILED",
                "timestamp": now(),
                "description": (
                    f"Recovery failed at the {failed_stage} stage: {recovery_outcome.get('error')}"
                ),
                "details": {"failed_stage": failed_stage},
            })
            final_status = "FAILED"

        return {
            # The Incident model keys this field "incident_id"; the previous
            # lookup used "id" and therefore always returned None.
            "incident_id": incident_id,
            "status": final_status,
            "root_cause": diagnosis["root_cause"],
            "confidence": diagnosis.get("confidence"),
            # Additive: the runtime state and whether a human must intervene.
            "runtime_state": diagnosis.get("runtime_state") or (evidence.get("runtime") or {}).get("state"),
            "requires_human": bool(diagnosis.get("requires_human")),
            # Which engine produced this diagnosis, so a rule-based answer can
            # never be read as a model answer.
            "agent_mode": agent_mode,
            "agent_status": agent_status,
            "agent_note": diagnosis.get("agent_note"),
            "agent_telemetry": diagnosis.get("agent_telemetry"),
            "policy_decision": diagnosis.get("policy_decision"),
            "bedrock_failure": diagnosis.get("bedrock_failure"),
            "model_id": (diagnosis.get("agent_telemetry") or {}).get("model_id"),
            "aws_region": (diagnosis.get("agent_telemetry") or {}).get("aws_region"),
            "diagnosis_confidence": diagnosis.get("confidence"),
            "evidence": evidence,
            "action_taken": remediation_action,
            # First-class outcome of the allowlisted action, distinct from the
            # overall recovery verdict: an action can report success=False while
            # the loop still records why.
            "action_result": action_result,
            # Every allowlist decision taken for this incident: timestamp,
            # incident_id, action, allowed/blocked, result, error. Sanitised by
            # the registry before it is stored.
            "audit_log": audit_log,
            "verification": recovery_outcome.get("verification"),
            "retry_result": recovery_outcome.get("retry_result"),
            # Present only on failure: "FIX" or "VERIFY".
            "failed_stage": recovery_outcome.get("stage"),
            "error": recovery_outcome.get("error"),
            "timeline": timeline,
            "resolved_at": now() if final_status == "RESOLVED" else None,
        }


doctor_runner = DoctorRunner()
