"""
Safe Remediation Functions for AI Doctor.
All operations are strictly predefined and allowlisted.
No user-input command execution, shell injection, eval, or exec is permitted.

The two Ollama lifecycle actions delegate to `runner.ollama_runtime`, which
drives the REAL `ollama` binary. There is no stand-in service: when Ollama is
not installed these actions report OLLAMA_NOT_INSTALLED and fail, rather than
substituting a Python HTTP server and calling it a recovery.
"""

import json
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from .diagnostics import record_log
from .ollama_runtime import (
    OLLAMA_NOT_INSTALLED,
    get_runtime,
)
from .pidfile import DEFAULT_PID_FILE
from .redaction import redact_sensitive_data
from .security import validate_retry_url

# Retained for backwards compatibility with existing imports/tests.
OLLAMA_PID_FILE = DEFAULT_PID_FILE


def start_ollama() -> Dict[str, Any]:
    """
    Allowlisted remediation: start the real Ollama daemon.

    Delegates to `OllamaRuntime.start()`, which only reports success when the
    spawned process is alive, the listening socket belongs to that process (or a
    descendant), the port is open and the HTTP API answers. See defect D1 in
    SECURITY.md: success used to be inferred from the port alone, so a foreign
    listener on 11434 made a dead child look like a successful recovery.
    """
    runtime = get_runtime()
    record_log("INFO", "AI Doctor executing allowlisted remediation: start_ollama()", service="remediation")

    result = runtime.start()

    if result.state == OLLAMA_NOT_INSTALLED:
        record_log("ERROR", result.detail or "Ollama is not installed.", service="remediation")
    elif result.success:
        record_log("INFO", result.detail or "Ollama started.", service="remediation")
    else:
        record_log(
            "ERROR",
            f"start_ollama failed (state={result.state}, returncode={result.returncode}): {result.detail}",
            service="remediation",
        )

    payload = result.as_dict()
    # The captured child output may contain paths or credentials.
    if payload.get("output_tail"):
        payload["output_tail"] = redact_sensitive_data(payload["output_tail"])
    return payload


def stop_ollama() -> Dict[str, Any]:
    """
    Allowlisted remediation / chaos trigger: stop the real Ollama daemon.

    Targets are identified by executable path or exact process name. The AI
    Doctor process is never signalled.
    """
    runtime = get_runtime()
    record_log("WARN", "Intentional failure trigger: stopping real Ollama daemon...", service="remediation")

    result = runtime.stop()
    record_log(
        "INFO",
        f"Ollama stop complete (state={result.state}). Terminated PIDs: {result.terminated_pids}. "
        f"Port closed: {result.port_closed}",
        service="remediation",
    )
    return result.as_dict()


def retry_request(
    url: str,
    method: str = "GET",
    payload: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """
    Safely retries the original failed application request.
    Validates URL scheme and host to prevent SSRF.
    """
    # Safety check: structurally validate the destination before any egress.
    # See runner/security.py - the previous string-prefix check was bypassable
    # with hosts like "http://127.0.0.1.evil.com" and "http://localhost@evil.com".
    allowed, reason = validate_retry_url(url)
    if not allowed:
        # Log the reason but not the raw URL: a hostile destination string is
        # attacker-controlled content and should not be laundered into logs.
        record_log("SECURITY", f"Blocked retry_request: {reason}", service="remediation")
        return {
            "action": "retry_request",
            "success": False,
            "error": f"Security validation failed: {reason}",
        }

    record_log("INFO", f"Retrying failed request to {url[:200]} ({method})", service="remediation")

    data_bytes = None
    if payload is not None and method in ("POST", "PUT", "PATCH"):
        data_bytes = json.dumps(payload).encode("utf-8")

    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, data=data_bytes, headers=req_headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = resp.getcode()
            body = resp.read().decode("utf-8")
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = redact_sensitive_data(body)

            record_log("INFO", f"Retry request succeeded with HTTP {status_code}.", service="remediation")
            return {
                "action": "retry_request",
                "success": (200 <= status_code < 300),
                "status_code": status_code,
                "response": parsed,
            }
    except urllib.error.HTTPError as e:
        detail = redact_sensitive_data(f"{e.code} {e.reason}")
        record_log("ERROR", f"Retry request failed with HTTP {detail}", service="remediation")
        return {
            "action": "retry_request",
            "success": False,
            "status_code": e.code,
            "error_class": "HTTPError",
            "error": detail,
        }
    except Exception as e:
        # Exception text can embed a URL carrying credentials; redact it.
        detail = redact_sensitive_data(f"{type(e).__name__}: {e}")
        record_log("ERROR", f"Retry request failed: {detail}", service="remediation")
        return {
            "action": "retry_request",
            "success": False,
            "status_code": 500,
            "error_class": type(e).__name__,
            "error": detail,
        }
