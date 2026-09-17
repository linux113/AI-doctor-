"""
Safe Remediation Registry & Allowlist Enforcement.
Guarantees that ONLY explicitly allowlisted remediation actions can ever be executed.
Arbitrary command execution, shell injection, eval, and exec are strictly prohibited.
"""

from typing import Callable, Dict, Any, List
from datetime import datetime
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
            "timestamp": datetime.utcnow().isoformat() + "Z",
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
            audit_entry["status"] = "SUCCESS"
            audit_entry["result"] = result
            self._audit_log.append(audit_entry)
            return {"success": True, "action": action_name, "result": result}
        except Exception as e:
            audit_entry["status"] = "FAILED"
            audit_entry["error"] = str(e)
            self._audit_log.append(audit_entry)
            return {"success": False, "action": action_name, "error": str(e)}

    def get_audit_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns recent remediation audit records."""
        return self._audit_log[-limit:]


# Global singleton instance
remediation_registry = RemediationRegistry()
