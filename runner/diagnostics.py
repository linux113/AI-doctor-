"""
Safe Diagnostic Tools for AI Doctor.
All tools are strictly read-only and inspect system/service state without mutations.
Sensitive credentials and tokens are redacted before returning log data.
"""

import socket
import re
import urllib.request
import urllib.error
import json
import psutil
from typing import Dict, Any, List, Optional
from datetime import datetime

# Common credential and token regex patterns to redact
CREDENTIAL_PATTERNS = [
    (re.compile(r"(sk-[a-zA-Z0-9]{20,})", re.IGNORECASE), "[REDACTED_API_KEY]"),
    (re.compile(r"(Bearer\s+)[a-zA-Z0-9_\-\.]{20,}", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(api[_-]?key\s*[:=]\s*['\"]?)[a-zA-Z0-9_\-]{8,}(['\"]?)", re.IGNORECASE), r"\1[REDACTED_KEY]\2"),
    (re.compile(r"(password\s*[:=]\s*['\"]?)[^\s'\"]+(['\"]?)", re.IGNORECASE), r"\1[REDACTED_PASSWORD]\2"),
    (re.compile(r"(secret\s*[:=]\s*['\"]?)[^\s'\"]+(['\"]?)", re.IGNORECASE), r"\1[REDACTED_SECRET]\2"),
]


def redact_sensitive_data(text: str) -> str:
    """Redacts potential secrets, credentials, and API keys from text or logs."""
    if not isinstance(text, str):
        return text
    result = text
    for pattern, replacement in CREDENTIAL_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


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
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


def check_process(process_name: str = "ollama") -> Dict[str, Any]:
    """
    Checks if a process matching process_name is running on the system.
    Read-only inspection via process table.
    """
    matching_pids = []
    process_details = []

    for proc in psutil.process_iter(["pid", "name", "cmdline", "status"]):
        try:
            name = proc.info["name"] or ""
            cmdline = " ".join(proc.info["cmdline"] or [])
            if process_name.lower() in name.lower() or process_name.lower() in cmdline.lower():
                # Redact any accidental tokens in command lines
                safe_cmdline = redact_sensitive_data(cmdline)
                matching_pids.append(proc.info["pid"])
                process_details.append({
                    "pid": proc.info["pid"],
                    "name": name,
                    "cmdline": safe_cmdline[:120],
                    "status": proc.info["status"],
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    is_running = len(matching_pids) > 0
    return {
        "tool": "check_process",
        "process_name": process_name,
        "is_running": is_running,
        "pid_count": len(matching_pids),
        "pids": matching_pids,
        "details": process_details,
        "timestamp": datetime.utcnow().isoformat() + "Z",
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
            response_body = f"Models available: {len(data.get('models', []))}"
    except urllib.error.URLError as e:
        error_message = str(e.reason) if hasattr(e, "reason") else str(e)
    except Exception as e:
        error_message = str(e)

    return {
        "tool": "check_ollama",
        "endpoint": url,
        "is_available": available,
        "status_code": status_code,
        "response": response_body,
        "error": error_message,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


# In-memory application log buffer for local runner
_APPLICATION_LOGS: List[Dict[str, Any]] = []


def record_log(level: str, message: str, service: str = "application") -> None:
    """Appends a log record to the local buffer with timestamps."""
    _APPLICATION_LOGS.append({
        "timestamp": datetime.utcnow().isoformat() + "Z",
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
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


def health_check() -> Dict[str, Any]:
    """
    Runs a composite read-only diagnostic check across Application, Port, and Ollama.
    """
    port_res = check_port(11434)
    proc_res = check_process("ollama")
    ollama_res = check_ollama()

    return {
        "tool": "health_check",
        "ollama_running": proc_res["is_running"],
        "port_11434_open": port_res["is_open"],
        "ollama_api_healthy": ollama_res["is_available"],
        "overall_status": "HEALTHY" if (port_res["is_open"] and ollama_res["is_available"]) else "DEGRADED",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
