"""
AI Doctor Local Runner Package.

Read-only diagnostics, an allowlisted remediation registry, and the
autonomous DETECT -> DIAGNOSE -> FIX -> VERIFY -> RETRY orchestrator.
"""

from .diagnostics import (
    check_ollama,
    check_port,
    check_process,
    get_recent_logs,
    health_check,
    record_log,
    redact_sensitive_data,
)
from .diagnosis import Diagnosis, diagnose
from .pidfile import (
    DEFAULT_PID_FILE,
    is_trusted_ollama_pid,
    read_trusted_pid,
)
from .procmatch import OLLAMA_IDENTITIES, default_identities, matches_process
from .remediation import retry_request, start_ollama, stop_ollama
from .remediation_registry import REMEDIATION_ALLOWLIST, remediation_registry
from .security import ALLOWED_RETRY_HOSTS, validate_retry_url
from .timeutil import now_iso
from .tool_registry import diagnostic_registry
from .doctor_runner import doctor_runner

__all__ = [
    # diagnostics (read-only)
    "check_ollama",
    "check_port",
    "check_process",
    "get_recent_logs",
    "health_check",
    "record_log",
    "redact_sensitive_data",
    # root-cause engine (single source of truth)
    "Diagnosis",
    "diagnose",
    # registries
    "diagnostic_registry",
    "remediation_registry",
    "REMEDIATION_ALLOWLIST",
    # remediation (allowlisted)
    "start_ollama",
    "stop_ollama",
    "retry_request",
    # security helpers
    "ALLOWED_RETRY_HOSTS",
    "validate_retry_url",
    "OLLAMA_IDENTITIES",
    "default_identities",
    "matches_process",
    "DEFAULT_PID_FILE",
    "is_trusted_ollama_pid",
    "read_trusted_pid",
    # misc
    "now_iso",
    "doctor_runner",
]
