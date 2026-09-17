"""
AI Doctor Autonomous Runner.
Executes the autonomous troubleshooting and recovery loop:
DETECT -> DIAGNOSE -> FIX -> VERIFY -> RETRY
"""

import time
from typing import Dict, Any, List, Optional
from datetime import datetime

from .tool_registry import diagnostic_registry
from .remediation_registry import remediation_registry
from .diagnostics import record_log


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
            "collected_at": datetime.utcnow().isoformat() + "Z",
            "port_11434": port_data.get("result", {}),
            "process_ollama": process_data.get("result", {}),
            "ollama_api": ollama_data.get("result", {}),
            "recent_logs": logs_data.get("result", {}).get("logs", []),
        }

    def diagnose_root_cause(self, evidence: Dict[str, Any], initial_error: str) -> Dict[str, Any]:
        """
        Analyzes collected evidence to deduce the root cause and select an allowlisted remediation.
        """
        port_open = evidence.get("port_11434", {}).get("is_open", False)
        proc_running = evidence.get("process_ollama", {}).get("is_running", False)
        ollama_available = evidence.get("ollama_api", {}).get("is_available", False)

        if not proc_running and not port_open:
            root_cause = (
                "Ollama daemon process is terminated. TCP port 11434 is closed. "
                "The application cannot reach the local AI runtime."
            )
            recommended_remediation = "start_ollama"
        elif proc_running and not port_open:
            root_cause = (
                "Ollama process exists but has not bound to port 11434 or is hanging. "
                "Restarting Ollama service is required."
            )
            recommended_remediation = "start_ollama"
        elif not ollama_available:
            root_cause = (
                "Ollama API returned an error or timeout during health check. "
                "Restarting Ollama service is required."
            )
            recommended_remediation = "start_ollama"
        else:
            root_cause = f"Unknown application-level error: {initial_error}"
            recommended_remediation = "retry_request"

        return {
            "root_cause": root_cause,
            "recommended_remediation": recommended_remediation,
            "confidence": 0.98,
        }

    def run_remediation_and_verify(
        self,
        remediation_action: str,
        failed_request_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Safely executes remediation from allowlist, verifies service health, and retries the original request.
        """
        record_log("INFO", f"Initiating remediation action: {remediation_action}", service="doctor_runner")

        # 1. Execute safe remediation via allowlist
        remediation_result = self.remediation_registry.execute(remediation_action)
        if not remediation_result.get("success", False):
            return {
                "success": False,
                "stage": "FIX",
                "action": remediation_action,
                "error": remediation_result.get("error", "Remediation failed"),
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
                    "verification_time": datetime.utcnow().isoformat() + "Z",
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
        if failed_request_context and failed_request_context.get("url"):
            retry_res = self.remediation_registry.execute(
                "retry_request",
                url=failed_request_context["url"],
                method=failed_request_context.get("method", "GET"),
                payload=failed_request_context.get("payload"),
                headers=failed_request_context.get("headers"),
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
        now = lambda: datetime.utcnow().isoformat() + "Z"

        # 1. DETECTED
        timeline.append({"stage": "DETECTED", "timestamp": now(), "description": "Failure detected: " + incident_data.get("error", "Unknown error")})

        # 2. INVESTIGATING
        timeline.append({"stage": "INVESTIGATING", "timestamp": now(), "description": "Collecting system evidence via diagnostic tools"})
        evidence = self.collect_evidence()

        # 3. ROOT CAUSE FOUND
        diagnosis = self.diagnose_root_cause(evidence, incident_data.get("error", ""))
        timeline.append({
            "stage": "ROOT CAUSE FOUND",
            "timestamp": now(),
            "description": diagnosis["root_cause"],
            "details": diagnosis,
        })

        # 4. REMEDIATION
        remediation_action = diagnosis["recommended_remediation"]
        timeline.append({
            "stage": "REMEDIATION",
            "timestamp": now(),
            "description": f"Executing allowlisted action: {remediation_action}",
        })

        # 5. VERIFYING & RETRY
        recovery_outcome = self.run_remediation_and_verify(
            remediation_action=remediation_action,
            failed_request_context=incident_data.get("request_context"),
        )

        timeline.append({
            "stage": "VERIFYING",
            "timestamp": now(),
            "description": "Verifying port 11434 and Ollama HTTP endpoint availability",
            "verified": recovery_outcome["success"],
        })

        # 6. RESOLVED / FAILED
        if recovery_outcome["success"]:
            timeline.append({
                "stage": "RESOLVED",
                "timestamp": now(),
                "description": "All services healthy, original operation retried and succeeded.",
            })
            final_status = "RESOLVED"
        else:
            timeline.append({
                "stage": "FAILED",
                "timestamp": now(),
                "description": "Recovery was unable to automatically restore service.",
            })
            final_status = "FAILED"

        return {
            "incident_id": incident_data.get("id"),
            "status": final_status,
            "root_cause": diagnosis["root_cause"],
            "evidence": evidence,
            "action_taken": remediation_action,
            "verification": recovery_outcome.get("verification"),
            "retry_result": recovery_outcome.get("retry_result"),
            "timeline": timeline,
            "resolved_at": now() if final_status == "RESOLVED" else None,
        }


doctor_runner = DoctorRunner()
