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
from typing import Dict, Any, List, Optional, Sequence
from datetime import datetime
from .timeutil import now_iso
from .procmatch import default_identities, matches_process

# Common credential and token regex patterns to redact.
#
# ORDER MATTERS: the most specific patterns run first so a generic rule cannot
# partially match a structured token and leave a recognisable fragment behind
# (for example the generic key/value rule clipping a PEM block down to its
# header line, which still discloses the key type).
CREDENTIAL_PATTERNS = [
    # --- Multi-line structured secrets -----------------------------------
    # PEM private keys, including OPENSSH / RSA / EC / PGP variants.
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----",
            re.DOTALL,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    # JSON Web Tokens: three dot-separated base64url segments, header always "eyJ".
    (
        re.compile(r"\beyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\b"),
        "[REDACTED_JWT]",
    ),

    # --- Provider-specific token formats ---------------------------------
    # AWS access key IDs (long-term AKIA, temporary ASIA/ABIA/ACCA).
    (re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY_ID]"),
    # Anthropic and OpenAI project keys (both contain dashes, so the generic
    # "sk-" rule below does not reach them).
    (re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{16,}\b"), "[REDACTED_API_KEY]"),
    # GitHub personal access tokens (classic and fine-grained).
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    # Slack tokens.
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), "[REDACTED_SLACK_TOKEN]"),
    # Google API keys.
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"), "[REDACTED_GOOGLE_KEY]"),
    # Stripe secret keys.
    (re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"), "[REDACTED_STRIPE_KEY]"),
    # Generic "sk-" prefixed keys (OpenAI classic and lookalikes).
    (re.compile(r"(sk-[a-zA-Z0-9]{20,})", re.IGNORECASE), "[REDACTED_API_KEY]"),

    # --- Header and key/value forms --------------------------------------
    (re.compile(r"(Bearer\s+)[a-zA-Z0-9_\.\-]{20,}", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(Basic\s+)[A-Za-z0-9+/=_\-]{16,}"), r"\1[REDACTED_TOKEN]"),
    # Connection-string credentials, e.g. postgres://user:hunter2@host
    (re.compile(r"(://[^/\s:@]+:)[^@\s/]+(@)"), r"\1[REDACTED_PASSWORD]\2"),
    (re.compile(r"(x-api-key\s*[:=]\s*['\"]?)[^\s'\",}]+(['\"]?)", re.IGNORECASE), r"\1[REDACTED_KEY]\2"),
    (re.compile(r"(authorization\s*[:=]\s*['\"]?)[^\s'\",}]+(['\"]?)", re.IGNORECASE), r"\1[REDACTED_HEADER]\2"),
    (re.compile(r"(api[_-]?key\s*[:=]\s*['\"]?)[a-zA-Z0-9_\-]{8,}(['\"]?)", re.IGNORECASE), r"\1[REDACTED_KEY]\2"),
    (re.compile(r"(access[_-]?key(?:[_-]?id)?\s*[:=]\s*['\"]?)[^\s'\",}]+(['\"]?)", re.IGNORECASE), r"\1[REDACTED_KEY]\2"),
    (re.compile(r"(password|passwd|pwd)(\s*[:=]\s*['\"]?)[^\s'\",}]+(['\"]?)", re.IGNORECASE), r"\1\2[REDACTED_PASSWORD]\3"),
    (re.compile(r"(secret(?:[_-]?access[_-]?key)?)(\s*[:=]\s*['\"]?)[^\s'\",}]+(['\"]?)", re.IGNORECASE), r"\1\2[REDACTED_SECRET]\3"),
    (re.compile(r"(token\s*[:=]\s*['\"]?)[^\s'\",}]+(['\"]?)", re.IGNORECASE), r"\1[REDACTED_TOKEN]\2"),
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
        "timestamp": now_iso(),
    }


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

    return {
        "tool": "health_check",
        "ollama_running": proc_res["is_running"],
        "port_11434_open": port_res["is_open"],
        "ollama_api_healthy": ollama_res["is_available"],
        "overall_status": "HEALTHY" if (port_res["is_open"] and ollama_res["is_available"]) else "DEGRADED",
        "timestamp": now_iso(),
    }
