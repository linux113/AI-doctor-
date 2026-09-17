"""
Safe Remediation Registry & Allowlist Enforcement.
Guarantees that ONLY explicitly allowlisted remediation actions can ever be executed.
Arbitrary command execution, shell injection, eval, and exec are strictly prohibited.
"""

from typing import Callable, Dict, Any, List
from datetime import datetime
from .timeutil import now_iso
from .remediation import start_ollama, retry_request, stop_ollama
from .diagnostics import record_log

# Strict allowlist of permitted remediation actions
REMEDIATION_ALLOWLIST = frozenset([
    "start_ollama",
    "retry_request",
    "stop_ollama",  # Permitted for intentional failure testing
])


class RemediationRegistry:
    """Registry managing allowlisted remediation actions with audit logging."""

    def __init__(self):
        self._actions: Dict[str, Dict[str, Any]] = {}
        self._audit_log: List[Dict[str, Any]] = []
        self._register_default_actions()

    def _register_default_actions(self):
        self.register(
            action_name="start_ollama",
            fn=start_ollama,
            description="Launches the local Ollama daemon service on port 11434.",
        )
        self.register(
            action_name="retry_request",
            fn=retry_request,
            description="Retries the originally failed HTTP request against the restored service.",
        )
        self.register(
            action_name="stop_ollama",
            fn=stop_ollama,
            description="Terminates the Ollama service to trigger intentional failure testing.",
        )

    def register(self, action_name: str, fn: Callable[..., Dict[str, Any]], description: str):
        if action_name not in REMEDIATION_ALLOWLIST:
            raise PermissionError(
                f"Security Violation: Action '{action_name}' is not in REMEDIATION_ALLOWLIST. "
                "Only pre-approved actions can be registered."
            )
        self._actions[action_name] = {
            "name": action_name,
            "fn": fn,
            "description": description,
        }

    def is_allowed(self, action_name: str) -> bool:
        """Checks if an action is present in the remediation allowlist."""
        return action_name in REMEDIATION_ALLOWLIST and action_name in self._actions

    def execute(self, action_name: str, **kwargs) -> Dict[str, Any]:
        """
        Executes a registered remediation action if it passes allowlist verification.
        Logs every invocation to the audit log.
        """
        audit_entry = {
            "action": action_name,
            "timestamp": now_iso(),
            "allowed": self.is_allowed(action_name),
            "status": "PENDING",
            "result": None,
            "error": None,
        }

        # Security boundary: Block anything not strictly in the allowlist
        if not self.is_allowed(action_name):
            error_msg = f"SECURITY ALERT: Remediation action '{action_name}' was BLOCKED by allowlist."
            audit_entry["status"] = "BLOCKED"
            audit_entry["error"] = error_msg
            self._audit_log.append(audit_entry)
            record_log("SECURITY", error_msg, service="remediation_registry")
            return {
                "success": False,
                "action": action_name,
                "error": error_msg,
                "blocked": True,
            }

        fn = self._actions[action_name]["fn"]
        try:
            result = fn(**kwargs)
        except Exception as e:
            audit_entry["status"] = "FAILED"
            audit_entry["error"] = str(e)
            self._audit_log.append(audit_entry)
            record_log(
                "ERROR",
                f"Remediation '{action_name}' raised {type(e).__name__}: {e}",
                service="remediation_registry",
            )
            return {"success": False, "action": action_name, "error": str(e)}

        # A callable that returns without raising can still have failed on its
        # own terms: start_ollama returns {"success": False, ...} when the
        # daemon starts but never binds port 11434. Honouring the action's own
        # verdict is what lets the runner attribute the failure to the FIX
        # stage instead of misreporting it as a VERIFY failure.
        #
        # Actions that report no "success" key (e.g. stop_ollama) are treated
        # as successful if they returned at all.
        inner_success = True
        if isinstance(result, dict) and "success" in result:
            inner_success = bool(result.get("success"))

        audit_entry["result"] = result

        if inner_success:
            audit_entry["status"] = "SUCCESS"
            self._audit_log.append(audit_entry)
            return {"success": True, "action": action_name, "result": result}

        inner_error = (result.get("error") if isinstance(result, dict) else None) or (
            f"Action '{action_name}' reported failure without an error message."
        )
        audit_entry["status"] = "FAILED"
        audit_entry["error"] = inner_error
        self._audit_log.append(audit_entry)
        record_log(
            "ERROR",
            f"Remediation '{action_name}' reported failure: {inner_error}",
            service="remediation_registry",
        )
        # "result" is preserved so callers can inspect the action's own output.
        return {"success": False, "action": action_name, "error": inner_error, "result": result}

    def get_audit_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns recent remediation audit records."""
        return self._audit_log[-limit:]


# Global singleton instance
remediation_registry = RemediationRegistry()
