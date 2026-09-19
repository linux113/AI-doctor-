"""
Safe Diagnostic Tools for AI Doctor.
All tools are strictly read-only and inspect system/service state without mutations.
Sensitive credentials and tokens are redacted before returning log data.
"""

import socket
import urllib.request
import urllib.error
import json
import psutil
from typing import Dict, Any, List, Optional, Sequence
from datetime import datetime
from .timeutil import now_iso
from .procmatch import default_identities, matches_process
from .redaction import CREDENTIAL_PATTERNS, redact_sensitive_data, sanitize_deep
from .ollama_runtime import OLLAMA_NOT_INSTALLED, get_runtime

# Secret redaction now lives in runner/redaction.py, the single authoritative
# sanitisation path. `redact_sensitive_data`, `sanitize_deep` and
# `CREDENTIAL_PATTERNS` are re-exported above so existing imports from this
# module continue to work.


def check_port(port: int = 11434, host: str = "127.0.0.1", timeout: float = 1.0) -> Dict[str, Any]:
    """
    Checks if a TCP port is open and listening.
    Read-only network probe.
    """
    is_open = False
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        is_open = (result == 0)
    except Exception as e:
        is_open = False
    finally:
        sock.close()

    return {
        "tool": "check_port",
        "host": host,
        "port": port,
        "is_open": is_open,
        "status": "OPEN" if is_open else "CLOSED",
        "timestamp": now_iso(),
    }


def check_process(
    process_name: str = "ollama",
    identities: Optional[Sequence[str]] = None,
    strict: bool = True,
) -> Dict[str, Any]:
    """
    Checks whether the Ollama runtime (or another named process) is running.
    Read-only inspection via the process table.

    Matching is by *identity*, not by mention. The previous implementation did a
    substring search over the joined command line, so any process whose argv
    merely contained the word "ollama" - a wrapper shell, an editor, a `tail -f`
    - was reported as the running daemon, which corrupted root-cause
    attribution. See runner/procmatch.py for the observed failure.

    `strict=False` restores the legacy substring behaviour for callers that
    genuinely want a fuzzy search. It is never used on a kill path.
    """
    targets = tuple(identities) if identities is not None else default_identities(process_name)

    matching_pids = []
    process_details = []

    for proc in psutil.process_iter(["pid", "name", "cmdline", "status"]):
        try:
            name = proc.info["name"] or ""
            argv = proc.info["cmdline"] or []
            matched, reason = matches_process(name, argv, targets, strict=strict)
            if not matched:
                continue

            # Redact any accidental tokens in command lines
            safe_cmdline = redact_sensitive_data(" ".join(argv))
            matching_pids.append(proc.info["pid"])
            process_details.append({
                "pid": proc.info["pid"],
                "name": name,
                "cmdline": safe_cmdline[:120],
                "status": proc.info["status"],
                "match_reason": reason,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    is_running = len(matching_pids) > 0
    return {
        "tool": "check_process",
        "process_name": process_name,
        "identities": list(targets),
        "strict": strict,
        "is_running": is_running,
        "pid_count": len(matching_pids),
        "pids": matching_pids,
        "details": process_details,
        "timestamp": now_iso(),
    }


def check_ollama(host: str = "127.0.0.1", port: int = 11434, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Checks availability and health of the Ollama HTTP API service.
    Probes root endpoint and version/tags endpoints.
    """
    url = f"http://{host}:{port}/api/tags"
    root_url = f"http://{host}:{port}/"

    available = False
    status_code = None
    response_body = None
    error_message = None

    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = resp.getcode()
            raw = resp.read().decode("utf-8")
            data = json.loads(raw)
            available = (status_code == 200)
            response_body = data
    except urllib.error.URLError as e:
        error_message = str(e.reason) if hasattr(e, "reason") else str(e)
    except Exception as e:
        error_message = str(e)

    # Distinguish "Ollama is absent" from "Ollama is down". Without this the
    # two look identical to the caller - both present as a refused connection.
    runtime_state = get_runtime().health()
    if error_message:
        error_message = redact_sensitive_data(error_message)

    return {
        "tool": "check_ollama",
        "endpoint": url,
        "is_available": available,
        "status_code": status_code,
        "response": response_body,
        "error": error_message,
        "runtime_state": runtime_state.state,
        "installed": runtime_state.installed,
        "timestamp": now_iso(),
    }


def check_ollama_runtime() -> Dict[str, Any]:
    """
    Reports the real Ollama runtime state: OLLAMA_NOT_INSTALLED, OLLAMA_STOPPED,
    OLLAMA_UNHEALTHY or OLLAMA_RUNNING, plus the resolved executable and version.

    Read-only. Does not start, stop or probe beyond HTTP GET /api/tags.
    """
    status = get_runtime().health()
    out = status.as_dict()
    out["tool"] = "check_ollama_runtime"
    return out


# In-memory application log buffer for local runner
_APPLICATION_LOGS: List[Dict[str, Any]] = []


def record_log(level: str, message: str, service: str = "application") -> None:
    """Appends a log record to the local buffer with timestamps."""
    _APPLICATION_LOGS.append({
        "timestamp": now_iso(),
        "level": level.upper(),
        "service": service,
        "message": message,
    })
    # Keep last 500 lines
    if len(_APPLICATION_LOGS) > 500:
        _APPLICATION_LOGS.pop(0)


def get_recent_logs(limit: int = 20, service: Optional[str] = None) -> Dict[str, Any]:
    """
    Retrieves recent application log records.
    Automatically scrubs and redacts sensitive credentials/tokens.
    """
    logs = _APPLICATION_LOGS
    if service:
        logs = [entry for entry in logs if entry.get("service") == service]

    recent = logs[-limit:] if len(logs) > limit else logs
    sanitized_logs = []
    for entry in recent:
        sanitized_logs.append({
            "timestamp": entry["timestamp"],
            "level": entry["level"],
            "service": entry["service"],
            "message": redact_sensitive_data(entry["message"]),
        })

    return {
        "tool": "get_recent_logs",
        "count": len(sanitized_logs),
        "logs": sanitized_logs,
        "timestamp": now_iso(),
    }


def health_check() -> Dict[str, Any]:
    """
    Runs a composite read-only diagnostic check across Application, Port, and Ollama.
    """
    port_res = check_port(11434)
    proc_res = check_process("ollama")
    ollama_res = check_ollama()

    runtime_state = ollama_res.get("runtime_state")
    if port_res["is_open"] and ollama_res["is_available"]:
        overall = "HEALTHY"
    elif runtime_state == OLLAMA_NOT_INSTALLED:
        # Not an outage: the runtime is absent and no allowlisted action can fix it.
        overall = "NOT_INSTALLED"
    else:
        overall = "DEGRADED"

    return {
        "tool": "health_check",
        "ollama_running": proc_res["is_running"],
        "port_11434_open": port_res["is_open"],
        "ollama_api_healthy": ollama_res["is_available"],
        "runtime_state": runtime_state,
        "overall_status": overall,
        "timestamp": now_iso(),
    }
