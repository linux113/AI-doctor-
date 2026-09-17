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

OLLAMA_PID_FILE = "/tmp/ollama.pid"


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
    """
    record_log("WARN", "Intentional failure trigger: stopping Ollama service...", service="remediation")
    killed_pids = []

    # Find matching processes
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            name = proc.info["name"] or ""
            cmdline = " ".join(proc.info["cmdline"] or [])
            # Target our runner.ollama_service or ollama binary
            if "runner.ollama_service" in cmdline or name == "ollama":
                pid = proc.info["pid"]
                os.kill(pid, signal.SIGTERM)
                killed_pids.append(pid)
        except Exception:
            continue

    if os.path.exists(OLLAMA_PID_FILE):
        try:
            with open(OLLAMA_PID_FILE, "r") as f:
                pid = int(f.read().strip())
            os.kill(pid, signal.SIGTERM)
            if pid not in killed_pids:
                killed_pids.append(pid)
        except Exception:
            pass
        try:
            os.remove(OLLAMA_PID_FILE)
        except Exception:
            pass

    time.sleep(0.5)
    port_down = not check_port(11434)["is_open"]
    record_log("INFO", f"Ollama service stopped. Terminated PIDs: {killed_pids}. Port 11434 closed: {port_down}", service="remediation")

    return {
        "action": "stop_ollama",
        "terminated_pids": killed_pids,
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
    record_log("INFO", f"Retrying failed request to {url} ({method})", service="remediation")

    # Safety check: enforce HTTP/HTTPS and local/approved endpoints only
    if not (url.startswith("http://127.0.0.1") or url.startswith("http://localhost") or url.startswith("http://0.0.0.0")):
        return {
            "action": "retry_request",
            "success": False,
            "error": "Security validation failed: Request destination must be local service.",
        }

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
