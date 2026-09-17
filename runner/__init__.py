"""
AI Doctor Local Runner Package.
"""

from .diagnostics import (
    check_ollama,
    check_port,
    check_process,
    get_recent_logs,
    health_check,
    record_log,
)
from .tool_registry import diagnostic_registry
from .remediation_registry import remediation_registry, REMEDIATION_ALLOWLIST
from .remediation import start_ollama, stop_ollama, retry_request
from .doctor_runner import doctor_runner

__all__ = [
    "check_ollama",
    "check_port",
    "check_process",
    "get_recent_logs",
    "health_check",
    "record_log",
    "diagnostic_registry",
    "remediation_registry",
    "REMEDIATION_ALLOWLIST",
    "start_ollama",
    "stop_ollama",
    "retry_request",
    "doctor_runner",
]
