"""
Real Ollama runtime abstraction.

This replaces `runner/ollama_service.py`, which was a ~180-line Python
`http.server` stand-in bound to port 11434. That stand-in was described as
"Ollama" throughout the README and the demo, which was inaccurate: no model
inference ever occurred, and `/api/generate` returned a formatted string.

The stand-in has been **deleted**, not renamed. This module drives the real
`ollama` binary and refuses to substitute anything for it.

Runtime states (requirement: report the truth, never pretend)
-------------------------------------------------------------
    OLLAMA_NOT_INSTALLED   no `ollama` executable could be found or verified
    OLLAMA_STOPPED         installed, but nothing is listening on the port
    OLLAMA_UNHEALTHY       something is listening, but the API does not answer
    OLLAMA_RUNNING         listening and the API responds successfully

Startup verification (fixes defect D1)
--------------------------------------
The previous `start_ollama` decided success by probing the *port* alone. If any
other process held port 11434, the spawned child would fail to bind and exit
immediately, yet the port probe succeeded against the foreign listener and the
function returned `success=True` with a PID that was already dead. The incident
was then marked RESOLVED. This was reproduced live during the audit.

`OllamaRuntime.start()` therefore requires ALL of:
    1. the spawned child is still alive (`Popen.poll() is None`),
    2. the TCP port is open,
    3. the listening socket on that port belongs to the spawned process or one
       of its descendants - a random listener is not accepted as proof,
    4. the Ollama HTTP API answers successfully.

If the child exits before readiness, `start()` returns `success=False` with the
captured return code and a redacted tail of its output, and never claims
recovery. The incident stays unresolved.
"""

import os
import shutil
import signal
import subprocess
import tempfile
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

import psutil

from .pidfile import (
    DEFAULT_PID_FILE,
    pid_file_permissions_warning,
    read_trusted_pid,
    remove_pid_file,
    write_pid_file,
)
from .redaction import redact_sensitive_data
from .timeutil import now_iso

# ---------------------------------------------------------------------------
# Runtime states
# ---------------------------------------------------------------------------
OLLAMA_NOT_INSTALLED = "OLLAMA_NOT_INSTALLED"
OLLAMA_STOPPED = "OLLAMA_STOPPED"
OLLAMA_UNHEALTHY = "OLLAMA_UNHEALTHY"
OLLAMA_RUNNING = "OLLAMA_RUNNING"
OLLAMA_START_FAILED = "OLLAMA_START_FAILED"

# Subcommand used to run the daemon. Never interpolated from user input.
SERVE_ARG = "serve"
VERSION_ARG = "--version"

# Standard installation locations, probed in order after $PATH. Not hardcoded
# to a single machine: discovery is env override -> PATH -> known prefixes.
CANDIDATE_PATHS: Tuple[str, ...] = (
    "/usr/local/bin/ollama",
    "/usr/bin/ollama",
    "/usr/sbin/ollama",
    "/opt/ollama/bin/ollama",
    "/usr/libexec/ollama/ollama",
    "/snap/bin/ollama",
    "/opt/homebrew/bin/ollama",          # macOS (Apple Silicon)
    "/Applications/Ollama.app/Contents/Resources/ollama",
)

# Bounded tail of captured child output, so a chatty or hostile daemon cannot
# flood an incident document.
OUTPUT_TAIL_BYTES = 4000


@dataclass
class RuntimeStatus:
    """Point-in-time state of the real Ollama runtime."""

    state: str
    installed: bool
    executable: Optional[str] = None
    version: Optional[str] = None
    pid: Optional[int] = None
    process_running: bool = False
    port_open: bool = False
    api_healthy: bool = False
    api_status_code: Optional[int] = None
    api_error: Optional[str] = None
    detail: Optional[str] = None
    timestamp: str = field(default_factory=now_iso)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state,
            "installed": self.installed,
            "executable": self.executable,
            "version": self.version,
            "pid": self.pid,
            "process_running": self.process_running,
            "port_open": self.port_open,
            "api_healthy": self.api_healthy,
            "api_status_code": self.api_status_code,
            "api_error": self.api_error,
            "detail": self.detail,
            "timestamp": self.timestamp,
        }


@dataclass
class StartResult:
    """Outcome of an attempt to start the real Ollama daemon."""

    success: bool
    state: str
    pid: Optional[int] = None
    returncode: Optional[int] = None
    port_open: bool = False
    api_healthy: bool = False
    socket_owned_by_child: bool = False
    foreign_listener_pid: Optional[int] = None
    output_tail: Optional[str] = None
    already_running: bool = False
    elapsed_seconds: Optional[float] = None
    detail: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "action": "start_ollama",
            "success": self.success,
            "state": self.state,
            "pid": self.pid,
            "returncode": self.returncode,
            "port_open": self.port_open,
            "api_healthy": self.api_healthy,
            "socket_owned_by_child": self.socket_owned_by_child,
            "foreign_listener_pid": self.foreign_listener_pid,
            "output_tail": self.output_tail,
            "already_running": self.already_running,
            "elapsed_seconds": self.elapsed_seconds,
            "detail": self.detail,
        }


@dataclass
class StopResult:
    """Outcome of an attempt to stop the real Ollama daemon."""

    success: bool
    state: str
    terminated_pids: List[int] = field(default_factory=list)
    refused_pids: List[Dict[str, Any]] = field(default_factory=list)
    port_closed: bool = False
    detail: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "action": "stop_ollama",
            "success": self.success,
            "state": self.state,
            "terminated_pids": self.terminated_pids,
            "refused_pids": self.refused_pids,
            # Retained for backwards compatibility with existing callers/tests.
            "port_11434_closed": self.port_closed,
            "port_closed": self.port_closed,
            "detail": self.detail,
        }


def _tail_file(path: Optional[str], limit: int = OUTPUT_TAIL_BYTES) -> Optional[str]:
    """Reads a bounded, redacted tail of a captured output file."""
    if not path:
        return None
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            if size > limit:
                f.seek(size - limit)
            raw = f.read(limit)
    except OSError:
        return None
    text = raw.decode("utf-8", errors="replace").strip()
    return redact_sensitive_data(text) if text else None


class OllamaRuntime:
    """
    Discovers and drives the real Ollama binary.

    No fallback server of any kind is provided. When Ollama is not installed the
    runtime says so, and callers must surface OLLAMA_NOT_INSTALLED instead of
    treating it as an outage.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 11434,
        executable: Optional[str] = None,
        pid_file: str = DEFAULT_PID_FILE,
        log_path: Optional[str] = None,
        readiness_timeout: float = 60.0,
        poll_interval: float = 0.2,
        serve_args: Optional[Sequence[str]] = None,
    ):
        self.host = host
        self.port = port
        # PID file written on a verified start and re-read (never trusted
        # blindly) by stop(). Injectable so tests can exercise the
        # tampered-PID defence without touching /tmp.
        self.pid_file = pid_file
        self.readiness_timeout = readiness_timeout
        self.poll_interval = poll_interval
        # Explicit executable wins; otherwise discovery runs on first use.
        self._explicit_executable = executable
        self._resolved_executable: Optional[str] = None
        self._resolution_attempted = False
        self._version: Optional[str] = None
        default_log_path = (
            os.path.join(tempfile.gettempdir(), "ai-doctor", "ollama.log")
            if os.name == "nt"
            else "/tmp/ai-doctor-ollama.log"
        )
        self.log_path = log_path or os.environ.get(
            "OLLAMA_RUNTIME_LOG", default_log_path
        )
        self._serve_args = list(serve_args) if serve_args else [SERVE_ARG]
        # PID of the daemon this process started, if any.
        self.started_pid: Optional[int] = None

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------
    def _candidates(self) -> List[str]:
        """Ordered candidate executable paths: env override, PATH, known prefixes."""
        out: List[str] = []
        if self._explicit_executable:
            return [os.path.expanduser(self._explicit_executable)]
        env_exe = os.environ.get("OLLAMA_EXECUTABLE")
        if env_exe:
            return [os.path.expanduser(env_exe)]
        which = shutil.which("ollama")
        if which:
            out.append(which)
        home = os.path.expanduser("~/.ollama/bin/ollama")
        out.extend(list(CANDIDATE_PATHS) + [home])
        # De-duplicate while preserving order.
        seen = set()
        unique = []
        for c in out:
            if c not in seen:
                seen.add(c)
                unique.append(c)
        return unique

    def _verify_identity(self, exe: str) -> Optional[str]:
        """
        Confirms a candidate really is Ollama and returns its version string.

        Finding a file named "ollama" is not enough - the binary is asked to
        identify itself. Uses a fixed argv list, no shell, and a short timeout.
        """
        if not os.path.isfile(exe) or not os.access(exe, os.X_OK):
            return None
        try:
            proc = subprocess.run(
                [exe, VERSION_ARG],
                capture_output=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        # Real ollama writes its version to stderr; accept either stream.
        blob = ((proc.stdout or b"") + (proc.stderr or b"")).decode("utf-8", "replace")
        if proc.returncode != 0 or "ollama" not in blob.lower():
            return None
        return blob.strip().splitlines()[-1].strip() if blob.strip() else "unknown"

    def resolve_executable(self) -> Optional[str]:
        """Returns the verified absolute path to the real Ollama binary, or None."""
        if self._resolution_attempted:
            return self._resolved_executable
        self._resolution_attempted = True
        for candidate in self._candidates():
            version = self._verify_identity(candidate)
            if version is not None:
                self._resolved_executable = os.path.realpath(candidate)
                self._version = version
                return self._resolved_executable
        self._resolved_executable = None
        return None

    def is_installed(self) -> bool:
        """True only when a verified Ollama executable was found."""
        return self.resolve_executable() is not None

    def version(self) -> Optional[str]:
        """Version reported by the binary itself, or None if not installed."""
        if not self.is_installed():
            return None
        if self._version is None:
            self._version = self._verify_identity(self._resolved_executable or "")
        return self._version

    def rediscover(self) -> Optional[str]:
        """Forces discovery to run again (used after an install, or in tests)."""
        self._resolution_attempted = False
        self._resolved_executable = None
        self._version = None
        return self.resolve_executable()

    # ------------------------------------------------------------------
    # Probes
    # ------------------------------------------------------------------
    def port_is_open(self, timeout: float = 1.0) -> bool:
        """Raw TCP connect probe against the configured host/port."""
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            return sock.connect_ex((self.host, self.port)) == 0
        except OSError:
            return False
        finally:
            sock.close()

    def api_health(self, timeout: float = 3.0) -> Tuple[bool, Optional[int], Optional[str]]:
        """
        Queries the real Ollama HTTP API. Returns (healthy, status_code, error).
        """
        import json
        import urllib.error
        import urllib.request

        url = f"http://{self.host}:{self.port}/api/tags"
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                code = resp.getcode()
                body = resp.read().decode("utf-8", "replace")
                if code != 200:
                    return False, code, f"HTTP {code}"
                try:
                    json.loads(body)
                except ValueError:
                    return False, code, "response was not valid JSON"
                return True, code, None
        except urllib.error.HTTPError as e:
            return False, e.code, redact_sensitive_data(f"HTTP {e.code} {e.reason}")
        except urllib.error.URLError as e:
            return False, None, redact_sensitive_data(str(e.reason))
        except Exception as e:  # timeout, malformed response, etc.
            return False, None, redact_sensitive_data(f"{type(e).__name__}: {e}")

    def find_ollama_processes(self) -> List[psutil.Process]:
        """
        Live Ollama daemon processes, identified by executable path or exact
        process name - never by a substring of the command line.
        """
        exe = self.resolve_executable()
        # Safety interlock: never match processes by executable path when the
        # resolved "ollama" executable IS the interpreter running AI Doctor.
        # That would put every Python process on the machine into the kill list.
        # Discovery verifies identity by running `<exe> --version` and requiring
        # "ollama" in the output, so this cannot happen in production; the guard
        # exists so a misconfigured or injected path cannot turn stop_ollama into
        # a mass-kill.
        if exe and sys.executable and os.path.realpath(exe) == os.path.realpath(sys.executable):
            exe = None
        found = []
        self_pid = os.getpid()
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                if pid == self_pid:
                    continue
                name = (proc.info["name"] or "").lower()
                proc_exe = None
                try:
                    proc_exe = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    proc_exe = None
                if exe and proc_exe and os.path.realpath(proc_exe) == exe:
                    found.append(proc)
                elif name == "ollama":
                    found.append(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return found

    def listening_pid(self) -> Optional[int]:
        """
        PID owning the LISTEN socket on the configured port, or None when it
        cannot be determined. A None here is treated as "unverified", never as
        "ours" - that is what stops a foreign listener being accepted as proof
        of a successful start.
        """
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status != psutil.CONN_LISTEN:
                    continue
                laddr = conn.laddr
                if laddr and laddr.port == self.port:
                    return conn.pid  # may legitimately be None without privilege
        except (psutil.AccessDenied, OSError):
            return None
        return None

    def _is_self_or_descendant(self, proc: "subprocess.Popen[Any]", pid: Optional[int]) -> bool:
        """True when `pid` is the spawned process or one of its descendants."""
        if pid is None:
            return False
        if pid == proc.pid:
            return True
        try:
            parent = psutil.Process(proc.pid)
            return any(child.pid == pid for child in parent.children(recursive=True))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def _ollama_pid(self) -> Optional[int]:
        procs = self.find_ollama_processes()
        return procs[0].pid if procs else None

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------
    def health(self) -> RuntimeStatus:
        """Deterministic runtime state: NOT_INSTALLED / STOPPED / UNHEALTHY / RUNNING."""
        exe = self.resolve_executable()
        if exe is None:
            return RuntimeStatus(
                state=OLLAMA_NOT_INSTALLED,
                installed=False,
                detail=(
                    "No verified 'ollama' executable was found on PATH or in the standard "
                    "install locations. This is not an outage: the runtime is absent. "
                    "Set OLLAMA_EXECUTABLE or install Ollama."
                ),
            )

        port_open = self.port_is_open()
        api_ok, api_code, api_error = self.api_health() if port_open else (False, None, "port closed")
        pid = self._ollama_pid()
        listener = self.listening_pid() if port_open else None

        if port_open and api_ok and pid is not None:
            state = OLLAMA_RUNNING
            detail = None
        elif port_open and api_ok:
            # The port is open and something answered /api/tags, but no process
            # matched the Ollama identity. Either the process probe is blind
            # (container or namespace boundary, insufficient privilege) or the
            # port belongs to an unrelated listener. Neither is accepted as a
            # verified RUNNING runtime: a listener that happens to answer is not
            # proof that Ollama recovered (defect D1, scenario E).
            state = OLLAMA_UNHEALTHY
            owner = f" (the socket is owned by PID {listener})" if listener else ""
            detail = (
                f"Port {self.port} is open and the API answered{owner}, but no process "
                "matched the Ollama identity. The process probe may be blind, or the port "
                "may belong to an unrelated listener. Not accepted as RUNNING."
            )
        elif port_open and not api_ok:
            state = OLLAMA_UNHEALTHY
            detail = f"Port {self.port} is open but the Ollama API did not answer successfully: {api_error}"
        else:
            state = OLLAMA_STOPPED
            if pid is not None:
                detail = (
                    f"An Ollama process (PID {pid}) exists but is not listening on port "
                    f"{self.port}; it may still be starting or may be hung."
                )
            else:
                detail = f"Nothing is listening on port {self.port}."

        return RuntimeStatus(
            state=state,
            installed=True,
            executable=exe,
            version=self._version,
            pid=pid,
            process_running=pid is not None,
            port_open=port_open,
            api_healthy=api_ok,
            api_status_code=api_code,
            api_error=api_error,
            detail=detail,
        )

    def is_running(self) -> bool:
        """True only when the runtime is installed, listening and answering."""
        return self.health().state == OLLAMA_RUNNING

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> StartResult:
        """
        Starts the real Ollama daemon and verifies it properly.

        Success requires the spawned child to be alive, the port to be open, the
        listening socket to belong to that child (or a descendant), and the HTTP
        API to answer. See the module docstring for the defect this closes.
        """
        exe = self.resolve_executable()
        if exe is None:
            return StartResult(
                success=False,
                state=OLLAMA_NOT_INSTALLED,
                detail=(
                    "Cannot start Ollama: no verified 'ollama' executable was found. "
                    "No stand-in service is substituted."
                ),
            )

        # Already healthy - nothing to do, and do not claim we started it.
        current = self.health()
        if current.state == OLLAMA_RUNNING:
            return StartResult(
                success=True,
                state=OLLAMA_RUNNING,
                pid=current.pid,
                port_open=True,
                api_healthy=True,
                socket_owned_by_child=False,
                already_running=True,
                detail=f"Ollama was already running (PID {current.pid}).",
            )

        env = dict(os.environ)
        # Bind where we intend to probe. Ollama defaults to 127.0.0.1:11434.
        env["OLLAMA_HOST"] = f"{self.host}:{self.port}"
        env.setdefault("OLLAMA_MODELS", os.environ.get("OLLAMA_MODELS", os.path.expanduser("~/.ollama/models")))

        # Truncate the capture file so the tail we report is from THIS attempt.
        try:
            with open(self.log_path, "wb"):
                pass
        except OSError:
            pass

        try:
            log_handle = open(self.log_path, "ab")
        except OSError:
            log_handle = subprocess.DEVNULL

        argv = [exe] + list(self._serve_args)
        try:
            proc = subprocess.Popen(
                argv,
                stdout=log_handle,
                stderr=log_handle,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
                env=env,
                cwd=os.path.dirname(exe) or None,
            )
        except OSError as e:
            if log_handle not in (subprocess.DEVNULL, None):
                try:
                    log_handle.close()
                except OSError:
                    pass
            return StartResult(
                success=False,
                state=OLLAMA_START_FAILED,
                detail=f"Failed to spawn {os.path.basename(exe)}: {redact_sensitive_data(str(e))}",
            )

        # Requirement: retain the Popen/PID immediately.
        self.started_pid = proc.pid
        pid = proc.pid
        began = time.monotonic()
        deadline = began + self.readiness_timeout

        foreign_pid: Optional[int] = None
        last_port_open = False
        last_api_ok = False

        while time.monotonic() < deadline:
            # 1. Is the child still alive? A dead child can never become ready.
            returncode = proc.poll()
            if returncode is not None:
                elapsed = round(time.monotonic() - began, 3)
                if log_handle not in (subprocess.DEVNULL, None):
                    try:
                        log_handle.close()
                    except OSError:
                        pass
                return StartResult(
                    success=False,
                    state=OLLAMA_START_FAILED,
                    pid=pid,
                    returncode=returncode,
                    port_open=self.port_is_open(),
                    output_tail=_tail_file(self.log_path),
                    elapsed_seconds=elapsed,
                    detail=(
                        f"Ollama exited with return code {returncode} during startup, "
                        f"{elapsed}s after spawn. Recovery is NOT claimed."
                    ),
                )

            last_port_open = self.port_is_open()
            listener = self.listening_pid() if last_port_open else None
            owns = self._is_self_or_descendant(proc, listener)

            if last_port_open and not owns:
                # Requirement: a random process listening on the port is NOT
                # proof that our spawn succeeded.
                foreign_pid = listener

            if owns:
                last_api_ok, _code, _err = self.api_health()
                if last_api_ok:
                    elapsed = round(time.monotonic() - began, 3)
                    if log_handle not in (subprocess.DEVNULL, None):
                        try:
                            log_handle.close()
                        except OSError:
                            pass
                    # Record the verified PID for stop() to cross-check. Written
                    # only now - never before readiness - so the file can never
                    # claim a process that did not actually come up.
                    write_pid_file(pid, self.pid_file)
                    return StartResult(
                        success=True,
                        state=OLLAMA_RUNNING,
                        pid=pid,
                        returncode=None,
                        port_open=True,
                        api_healthy=True,
                        socket_owned_by_child=True,
                        elapsed_seconds=elapsed,
                        detail=f"Ollama started (PID {pid}) and is serving on port {self.port} after {elapsed}s.",
                    )

            time.sleep(self.poll_interval)

        # Readiness timeout.
        elapsed = round(time.monotonic() - began, 3)
        returncode = proc.poll()
        if log_handle not in (subprocess.DEVNULL, None):
            try:
                log_handle.close()
            except OSError:
                pass

        if returncode is not None:
            return StartResult(
                success=False,
                state=OLLAMA_START_FAILED,
                pid=pid,
                returncode=returncode,
                port_open=last_port_open,
                output_tail=_tail_file(self.log_path),
                elapsed_seconds=elapsed,
                detail=f"Ollama exited with return code {returncode} before becoming ready.",
            )

        detail = (
            f"Ollama (PID {pid}) is still alive after {elapsed}s but did not become ready "
            f"on port {self.port}."
        )
        if foreign_pid is not None:
            detail += (
                f" Port {self.port} is held by a DIFFERENT process (PID {foreign_pid}), "
                "so the open port is not evidence that this spawn succeeded."
            )
        elif last_port_open:
            detail += " The port is open but the API did not answer successfully."

        return StartResult(
            success=False,
            state=OLLAMA_UNHEALTHY if last_port_open else OLLAMA_STOPPED,
            pid=pid,
            returncode=None,
            port_open=last_port_open,
            api_healthy=False,
            socket_owned_by_child=False,
            foreign_listener_pid=foreign_pid,
            output_tail=_tail_file(self.log_path),
            elapsed_seconds=elapsed,
            detail=detail,
        )

    def _verified_ollama_parent(self, proc: psutil.Process) -> Optional[psutil.Process]:
        """Return the verified Ollama desktop parent of a real daemon, if present."""
        if os.name != "nt":
            return None
        try:
            parent = proc.parent()
            if parent is None or (parent.name() or "").lower() != "ollama app.exe":
                return None

            parent_exe = parent.exe()
            daemon_exe = self.resolve_executable()
            if not parent_exe or not daemon_exe:
                return None

            parent_real = os.path.realpath(parent_exe)
            daemon_real = os.path.realpath(daemon_exe)

            if os.path.dirname(parent_real).lower() != os.path.dirname(daemon_real).lower():
                return None

            return parent
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            return None

    def stop(self, grace_seconds: float = 8.0) -> StopResult:
        """
        Stops the real Ollama daemon.

        Targets are identified by executable path or exact process name. The
        AI Doctor process itself is never signalled, and a PID read from a file
        is never trusted without identity verification.
        """
        self_pid = os.getpid()
        terminated: List[int] = []
        refused: List[Dict[str, Any]] = []

        # The PID-file trust check runs FIRST, before the "nothing to stop"
        # short circuit, so a tampered PID file is always reported rather than
        # silently ignored. /tmp is world-writable: a local user could pre-seed
        # it with the PID of a process they want killed and use this
        # remediation as a confused deputy. read_trusted_pid() refuses any PID
        # whose live process does not match the ollama identity, and a refusal
        # is recorded and never acted on.
        pid_hint, pid_reason = read_trusted_pid(self.pid_file)
        if pid_reason:
            refused.append({"pid": pid_hint, "reason": pid_reason})
        elif pid_hint:
            warning = pid_file_permissions_warning(self.pid_file)
            if warning:
                refused.append({"pid": pid_hint, "reason": warning})

        exe = self.resolve_executable()
        if (
            exe is None
            and not pid_hint
            and not self.find_ollama_processes()
            and not self.port_is_open()
        ):
            return StopResult(
                success=False,
                state=OLLAMA_NOT_INSTALLED,
                port_closed=True,
                refused_pids=refused,
                detail="Nothing to stop: Ollama is not installed and no listener is present.",
            )

        targets = self.find_ollama_processes()
        for daemon in list(targets):
            parent = self._verified_ollama_parent(daemon)
            if parent and parent.pid not in {p.pid for p in targets}:
                targets.append(parent)
        if pid_hint and pid_hint != self_pid and pid_hint not in {p.pid for p in targets}:
            try:
                targets.append(psutil.Process(pid_hint))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                refused.append({"pid": pid_hint, "reason": "PID vanished before it could be signalled."})

        if self.started_pid and not any(p.pid == self.started_pid for p in targets):
            try:
                targets.append(psutil.Process(self.started_pid))
            except psutil.NoSuchProcess:
                pass

        for proc in targets:
            pid = proc.pid
            if pid == self_pid:
                continue
            try:
                proc.send_signal(signal.SIGTERM)
                terminated.append(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                refused.append({"pid": pid, "reason": f"{type(e).__name__}: {e}"})

        deadline = time.monotonic() + grace_seconds
        while time.monotonic() < deadline:
            if not self.port_is_open() and not self.find_ollama_processes():
                break
            time.sleep(0.2)

        # Escalate only for processes that ignored SIGTERM.
        for proc in list(targets):
            try:
                if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
                    proc.send_signal(signal.SIGKILL)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        time.sleep(0.3)
        port_closed = not self.port_is_open()
        remaining = [p.pid for p in self.find_ollama_processes()]
        self.started_pid = None
        if port_closed and not remaining:
            remove_pid_file(self.pid_file)

        if exe is None:
            state = OLLAMA_NOT_INSTALLED
        elif port_closed and not remaining:
            state = OLLAMA_STOPPED
        else:
            state = OLLAMA_RUNNING

        return StopResult(
            success=port_closed and not remaining,
            state=state,
            terminated_pids=terminated,
            refused_pids=refused,
            port_closed=port_closed,
            detail=None if (port_closed and not remaining) else f"Still present after stop: PIDs {remaining}",
        )


# Module-level default runtime, configured from the environment.
_default_runtime: Optional[OllamaRuntime] = None


def get_runtime() -> OllamaRuntime:
    """Returns the shared OllamaRuntime, configured from environment variables."""
    global _default_runtime
    if _default_runtime is None:
        _default_runtime = OllamaRuntime(
            host=os.environ.get("OLLAMA_HOST_BIND", "127.0.0.1"),
            port=int(os.environ.get("OLLAMA_PORT", "11434")),
            executable=os.environ.get("OLLAMA_EXECUTABLE"),
            readiness_timeout=float(os.environ.get("OLLAMA_START_TIMEOUT", "60")),
        )
    return _default_runtime


def reset_runtime() -> None:
    """Drops the shared runtime so the next call re-reads configuration."""
    global _default_runtime
    _default_runtime = None
