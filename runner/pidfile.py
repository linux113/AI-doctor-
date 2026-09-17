"""
PID file handling for the local Ollama service.

The vulnerability this closes
-----------------------------
`stop_ollama()` used to read `/tmp/ollama.pid` and immediately
`os.kill(pid, SIGTERM)` whatever integer it found there. `/tmp` is
world-writable, so any local user could pre-seed that file with the PID of a
process they wanted killed, and the AI Doctor backend - typically running with
more privilege than an unattended demo server should - would dutifully signal
it. The remediation allowlist was being used as a confused deputy.

Two defences, applied together:

1. **Identity verification (the one that actually matters).** Before any PID
   from a file is signalled, `is_trusted_ollama_pid()` confirms the process
   still alive under that PID is genuinely our Ollama service, by inspecting
   its command line. A PID is not an identity; reusing one is trivial, so the
   file is treated as a hint that must be validated, never as authority.

2. **Restrictive file creation.** The service writes the file 0600 so it is
   not world-writable in the first place, and the reader warns when it finds a
   file with insecure permissions.
"""

import os
import stat
from typing import Optional, Tuple

import psutil

from .procmatch import OLLAMA_IDENTITIES, matches_process

# Overridable so deployments can point at a non-world-writable runtime dir
# (e.g. $XDG_RUNTIME_DIR). Defaults to the historical path for compatibility.
DEFAULT_PID_FILE = os.environ.get("AIDOCTOR_OLLAMA_PID_FILE", "/tmp/ollama.pid")

# Command-line marker identifying a process this project started. Kept for
# callers that want the raw string; identity decisions go through
# procmatch.matches_process, which compares whole arguments rather than
# searching for this substring.
SERVICE_MARKER = "runner.ollama_service"


def write_pid_file(pid: int, path: str = DEFAULT_PID_FILE) -> bool:
    """
    Writes `pid` to `path` with 0600 permissions.

    Uses os.open with an explicit mode rather than open()+chmod so the file is
    never briefly world-writable between creation and the permission change.
    Returns True on success; failures are non-fatal and reported as False.
    """
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(path, flags, 0o600)
        try:
            os.write(fd, str(pid).encode("ascii"))
        finally:
            os.close(fd)
        # Enforce even if the file pre-existed with looser permissions.
        os.chmod(path, 0o600)
        return True
    except OSError:
        return False


def remove_pid_file(path: str = DEFAULT_PID_FILE) -> None:
    """Removes the PID file if present. Never raises."""
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


def pid_file_permissions_warning(path: str = DEFAULT_PID_FILE) -> Optional[str]:
    """
    Returns a warning string if the PID file is group- or world-writable.

    A world-writable PID file means another local user could redirect
    remediation at an arbitrary process. We still verify identity before
    acting, but the condition is worth surfacing in the audit log.
    """
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return None
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        return (
            f"PID file {path} has insecure permissions "
            f"({stat.filemode(mode)}); it is writable by other users. "
            "Contents were treated as untrusted and verified before use."
        )
    return None


def is_trusted_ollama_pid(pid: int) -> Tuple[bool, str]:
    """
    Confirms that the live process under `pid` is genuinely our Ollama service.

    Returns (trusted, reason). Refuses PIDs that no longer exist, that belong
    to a different process reusing the number, and to our own process.
    """
    if not isinstance(pid, int) or pid <= 0:
        return False, "PID is not a positive integer."

    if pid == os.getpid():
        return False, "PID refers to the AI Doctor process itself; refusing to self-terminate."

    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            argv = proc.cmdline() or []
            name = proc.name() or ""
    except psutil.NoSuchProcess:
        return False, "No live process under that PID (stale PID file)."
    except (psutil.AccessDenied, psutil.ZombieProcess):
        return False, "Process state could not be inspected; refusing to signal an unverified PID."

    # Identity, never mention: a wrapper shell whose argv contains
    # "python -m runner.ollama_service" as one long string is NOT the service,
    # and signalling it would kill whatever invoked the remediation.
    matched, reason = matches_process(name, argv, OLLAMA_IDENTITIES, strict=True)
    if matched:
        return True, reason

    return False, (
        "PID file contents do not correspond to the Ollama service; "
        "the PID may have been recycled or tampered with. Refusing to signal it."
    )


def read_trusted_pid(path: str = DEFAULT_PID_FILE) -> Tuple[Optional[int], Optional[str]]:
    """
    Reads the PID file and verifies it before returning it.

    Returns (pid, None) when the PID is trusted, or (None, reason) when it is
    absent, malformed, or fails identity verification. Callers must not signal
    a PID that did not come back trusted.
    """
    try:
        with open(path, "r") as f:
            raw = f.read().strip()
    except OSError:
        return None, None

    if not raw:
        return None, None

    try:
        pid = int(raw)
    except ValueError:
        return None, f"PID file {path} does not contain an integer; ignored."

    trusted, reason = is_trusted_ollama_pid(pid)
    if not trusted:
        return None, f"PID file {path} claimed PID {pid}: {reason}"

    return pid, None
