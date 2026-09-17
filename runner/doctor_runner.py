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
        logs_data = self.diagnostic_registry.execute("get_recent_logs", limit=10)

        return {
            "collected_at": now_iso(),
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

    def run_remediation_and_verify(
        self,
        remediation_action: str,
        failed_request_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Safely executes remediation from allowlist, verifies service health, and retries the original request.
        """
        record_log("INFO", f"Initiating remediation action: {remediation_action}", service="doctor_runner")

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

        remediation_result = self.remediation_registry.execute(remediation_action, **kwargs)
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

        # 2. VERIFY: Poll health check
        verified = False
        verification_details = None
        for attempt in range(15):
            time.sleep(0.3)
            port_check = self.diagnostic_registry.execute("check_port", port=11434).get("result", {})
            api_check = self.diagnostic_registry.execute("check_ollama").get("result", {})
            if port_check.get("is_open") and api_check.get("is_available"):
                verified = True
                verification_details = {
                    "port_open": True,
                    "api_available": True,
                    "models_detected": api_check.get("response"),
                    "verification_time": now_iso(),
                }
                break

        if not verified:
            return {
                "success": False,
                "stage": "VERIFY",
                "action": remediation_action,
                "error": "Service verification failed: Port 11434 or Ollama API remained unavailable after restart.",
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
        diagnosis = self.diagnose_root_cause(evidence, detected_error)
        timeline.append({
            "stage": "ROOT CAUSE FOUND",
            "timestamp": now(),
            "description": diagnosis["root_cause"],
            "details": diagnosis,
        })

        # 4. REMEDIATION
        remediation_action = diagnosis["recommended_remediation"]
        remediation_started_at = now()

        # 5. VERIFYING & RETRY
        recovery_outcome = self.run_remediation_and_verify(
            remediation_action=remediation_action,
            failed_request_context=incident_data.get("request_context"),
        )

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
                "result": recovery_outcome.get("remediation_result"),
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
            "incident_id": incident_data.get("incident_id") or incident_data.get("id"),
            "status": final_status,
            "root_cause": diagnosis["root_cause"],
            "confidence": diagnosis.get("confidence"),
            "evidence": evidence,
            "action_taken": remediation_action,
            "verification": recovery_outcome.get("verification"),
            "retry_result": recovery_outcome.get("retry_result"),
            # Present only on failure: "FIX" or "VERIFY".
            "failed_stage": recovery_outcome.get("stage"),
            "error": recovery_outcome.get("error"),
            "timeline": timeline,
            "resolved_at": now() if final_status == "RESOLVED" else None,
        }


doctor_runner = DoctorRunner()
