"""
Safe Remediation Functions for AI Doctor.
All operations are strictly predefined and allowlisted.
No user-input command execution, shell injection, eval, or exec is permitted.
"""

import sys
import os
import subprocess
import time
import signal
import json
import urllib.request
import urllib.error
import psutil
from typing import Dict, Any, Optional

from .diagnostics import check_port, check_ollama, check_process, record_log
from .pidfile import (
    DEFAULT_PID_FILE,
    is_trusted_ollama_pid,
    pid_file_permissions_warning,
    read_trusted_pid,
    remove_pid_file,
)
from .procmatch import OLLAMA_IDENTITIES, matches_process
from .security import validate_retry_url

# Retained as an alias for backwards compatibility. The authoritative default
# now lives in runner.pidfile so the writer and the reader cannot diverge.
OLLAMA_PID_FILE = DEFAULT_PID_FILE


def start_ollama() -> Dict[str, Any]:
    """
    Safely starts the local Ollama service daemon.
    Predefined fixed command execution — no arbitrary input.
    """
    record_log("INFO", "AI Doctor executing predefined remediation: start_ollama()", service="remediation")

    # Check if already running
    proc_status = check_process("ollama")
    port_status = check_port(11434)
    if proc_status["is_running"] and port_status["is_open"]:
        record_log("INFO", "Ollama is already running and port 11434 is open.", service="remediation")
        return {
            "action": "start_ollama",
            "success": True,
            "message": "Ollama was already running and healthy.",
            "pids": proc_status["pids"],
        }

    # Start the Ollama process using python -m runner.ollama_service in a new process group
    try:
        # Launch detached server process
        process = subprocess.Popen(
            [sys.executable, "-m", "runner.ollama_service"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

        # Wait up to 5 seconds for port 11434 to become active
        started = False
        for _ in range(25):
            time.sleep(0.2)
            if check_port(11434)["is_open"]:
                started = True
                break

        if started:
            record_log("INFO", f"Ollama daemon successfully started with PID {process.pid}.", service="remediation")
            return {
                "action": "start_ollama",
                "success": True,
                "pid": process.pid,
                "message": f"Ollama daemon started successfully on port 11434 (PID: {process.pid}).",
            }
        else:
            record_log("ERROR", "Ollama daemon started but port 11434 did not respond within timeout.", service="remediation")
            return {
                "action": "start_ollama",
                "success": False,
                "pid": process.pid,
                "error": "Timeout waiting for Ollama to bind to port 11434.",
            }
    except Exception as e:
        record_log("ERROR", f"Failed to start Ollama daemon: {str(e)}", service="remediation")
        return {
            "action": "start_ollama",
            "success": False,
            "error": str(e),
        }


def stop_ollama() -> Dict[str, Any]:
    """
    Safely stops any running Ollama process.
    Used for intentional failure generation and clean recovery testing.

    Every PID is identity-verified before it is signalled. See runner/pidfile.py
    for why: the previous version trusted the contents of a world-writable
    /tmp file, which let any local user direct this remediation at an
    arbitrary process.
    """
    record_log("WARN", "Intentional failure trigger: stopping Ollama service...", service="remediation")
    killed_pids = []
    refused = []
    self_pid = os.getpid()

    perms_warning = pid_file_permissions_warning(OLLAMA_PID_FILE)
    if perms_warning:
        record_log("SECURITY", perms_warning, service="remediation")

    # Find matching processes in the process table.
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            pid = proc.info["pid"]
            name = proc.info["name"] or ""
            argv = proc.info["cmdline"] or []

            if pid == self_pid:
                # Never signal ourselves.
                continue

            # Identity, not mention. The previous substring test also matched
            # wrapper shells, editors and `tail -f ollama.log`, so invoking
            # this remediation could SIGTERM the very process that called it.
            matched, _reason = matches_process(name, argv, OLLAMA_IDENTITIES, strict=True)
            if not matched:
                continue

            # Re-verify through the shared identity check so the process table
            # sweep and the PID file path enforce exactly the same policy.
            trusted, reason = is_trusted_ollama_pid(pid)
            if not trusted:
                refused.append({"pid": pid, "reason": reason})
                record_log("SECURITY", f"Refused to signal PID {pid}: {reason}", service="remediation")
                continue

            os.kill(pid, signal.SIGTERM)
            killed_pids.append(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except OSError:
            continue

    # The PID file is a hint, not authority: read_trusted_pid only returns a
    # PID whose live process has already been confirmed to be our service.
    pid_from_file, refusal_reason = read_trusted_pid(OLLAMA_PID_FILE)
    if refusal_reason:
        refused.append({"pid_file": OLLAMA_PID_FILE, "reason": refusal_reason})
        record_log("SECURITY", f"Refusing PID file target: {refusal_reason}", service="remediation")
    elif pid_from_file is not None and pid_from_file not in killed_pids:
        try:
            os.kill(pid_from_file, signal.SIGTERM)
            killed_pids.append(pid_from_file)
        except OSError:
            pass

    remove_pid_file(OLLAMA_PID_FILE)

    time.sleep(0.5)
    port_down = not check_port(11434)["is_open"]
    record_log("INFO", f"Ollama service stopped. Terminated PIDs: {killed_pids}. Port 11434 closed: {port_down}", service="remediation")

    return {
        "action": "stop_ollama",
        "terminated_pids": killed_pids,
        "refused_pids": refused,
        "port_11434_closed": port_down,
    }


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
                parsed = body

            record_log("INFO", f"Retry request succeeded with HTTP {status_code}.", service="remediation")
            return {
                "action": "retry_request",
                "success": (200 <= status_code < 300),
                "status_code": status_code,
                "response": parsed,
            }
    except urllib.error.HTTPError as e:
        record_log("ERROR", f"Retry request failed with HTTP {e.code}: {e.reason}", service="remediation")
        return {
            "action": "retry_request",
            "success": False,
            "status_code": e.code,
            "error": str(e),
        }
    except Exception as e:
        record_log("ERROR", f"Retry request failed with network error: {str(e)}", service="remediation")
        return {
            "action": "retry_request",
            "success": False,
            "status_code": 500,
            "error": str(e),
        }
