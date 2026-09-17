"""
Safe Diagnostic Tool Registry.
Enforces read-only tool contracts, parameter validation, and execution logging.
"""

from typing import Callable, Dict, Any, List
from .diagnostics import (
    check_ollama,
    check_ollama_runtime,
    check_port,
    check_process,
    get_recent_logs,
    health_check,
)
from .redaction import redact_sensitive_data


class DiagnosticToolRegistry:
    """Registry managing read-only diagnostic tools."""

    def __init__(self):
        self._tools: Dict[str, Dict[str, Any]] = {}
        self._register_default_tools()

    def _register_default_tools(self):
        self.register(
            name="check_ollama",
            fn=check_ollama,
            description="Checks if Ollama HTTP API endpoint is reachable on port 11434 and returns model metadata.",
            read_only=True,
        )
        self.register(
            name="check_port",
            fn=check_port,
            description="Checks if a target TCP port (e.g. 11434) is currently open and listening.",
            read_only=True,
        )
        self.register(
            name="check_process",
            fn=check_process,
            description="Inspects the OS process table for running instances of a named service (e.g. 'ollama').",
            read_only=True,
        )
        self.register(
            name="get_recent_logs",
            fn=get_recent_logs,
            description="Retrieves sanitized and credential-redacted recent application/service log lines.",
            read_only=True,
        )
        self.register(
            name="check_ollama_runtime",
            fn=check_ollama_runtime,
            description=(
                "Reports the real Ollama runtime state (NOT_INSTALLED / STOPPED / UNHEALTHY / RUNNING), "
                "the resolved executable path and its version. Read-only."
            ),
            read_only=True,
        )
        self.register(
            name="health_check",
            fn=health_check,
            description="Performs an integrated health check across the local application and Ollama service.",
            read_only=True,
        )

    def register(self, name: str, fn: Callable[..., Dict[str, Any]], description: str, read_only: bool = True):
        if not read_only:
            raise ValueError(f"Diagnostic tool '{name}' must be strictly read-only.")
        self._tools[name] = {
            "name": name,
            "fn": fn,
            "description": description,
            "read_only": read_only,
        }

    def get_tool(self, name: str) -> Callable[..., Dict[str, Any]]:
        if name not in self._tools:
            raise KeyError(f"Tool '{name}' is not registered in the Diagnostic Tool Registry.")
        return self._tools[name]["fn"]

    def list_tools(self) -> List[Dict[str, Any]]:
        return [
            {"name": t["name"], "description": t["description"], "read_only": t["read_only"]}
            for t in self._tools.values()
        ]

    def execute(self, tool_name: str, **kwargs) -> Dict[str, Any]:
        """Safely executes a registered diagnostic tool."""
        if tool_name not in self._tools:
            return {
                "success": False,
                "error": f"Tool '{tool_name}' is not in the Safe Diagnostic Tool Registry.",
            }
        fn = self._tools[tool_name]["fn"]
        try:
            result = fn(**kwargs)
            return {"success": True, "result": result}
        except Exception as e:
            # Exception text may embed arguments containing credentials.
            return {"success": False, "error_class": type(e).__name__, "error": redact_sensitive_data(str(e))}


# Global singleton instance
diagnostic_registry = DiagnosticToolRegistry()
