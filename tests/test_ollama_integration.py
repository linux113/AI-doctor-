"""
Ollama runtime test matrix - scenarios A through F.

    A  Ollama installed and running
    B  Ollama installed but stopped
    C  Ollama unavailable / not installed
    D  Ollama fails during startup
    E  A different process owns the port
    F  The port is open but the health endpoint does not answer

Two kinds of test live here, and the distinction matters:

**Integration tests (A, B, and the running-baseline parts of C).** These drive the
REAL `ollama` binary. When Ollama is not installed they SKIP with an explicit
reason via the `requires_real_ollama` fixture. They are never satisfied by a
substitute: a Python HTTP server on port 11434 is not Ollama, and a test that
accepted one would assert nothing about the product.

**Deterministic state tests (C, D, E, F).** These exercise how `OllamaRuntime`
classifies a given world state. They construct the runtime against an EPHEMERAL
port and inject an executable path directly, so no discovery is fooled and
nothing is presented as Ollama. The injected programs are ordinary shell scripts
that exit, sleep, or answer HTTP 500 - they never claim to be Ollama and never
bind 11434. Every one of these tests asserts a FAILURE or an ABSENCE state, so
they cannot pass by accidentally simulating a healthy runtime.

Why the port is parameterised for D/E/F: `OllamaRuntime` treats the port as
configuration (`OLLAMA_HOST`). The logic under test - "an open socket is not
proof of recovery", "a child that exits during startup is not a recovery" - is
identical on any port, and running it on an ephemeral port means the suite cannot
collide with a real daemon on the developer's machine.
"""

import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import psutil
import pytest

from runner.diagnostics import check_ollama, check_ollama_runtime, check_port, health_check
from runner.diagnosis import diagnose
from runner.doctor_runner import doctor_runner
from runner.ollama_runtime import (
    OLLAMA_NOT_INSTALLED,
    OLLAMA_RUNNING,
    OLLAMA_START_FAILED,
    OLLAMA_STOPPED,
    OLLAMA_UNHEALTHY,
    OllamaRuntime,
    get_runtime,
)
from runner.remediation import start_ollama, stop_ollama
from tests.conftest import free_port


# =========================================================================
# Helpers: explicit test doubles. None of these is presented as Ollama.
# =========================================================================


def _write_double(tmp_path, name: str, body: str) -> str:
    """Writes a cross-platform executable used as an injected runtime double."""
    if os.name == "nt":
        path = tmp_path / f"{name}.py"

        if "sleep 20" in body:
            code = "import time\ntime.sleep(20)\n"
        elif "exit 7" in body:
            code = "import sys\nsys.exit(7)\n"
        elif "exit 3" in body:
            code = (
                "import sys\n"
                "print('Error: could not bind or load models', file=sys.stderr, flush=True)\n"
                "sys.exit(3)\n"
            )
        else:
            code = "pass\n"

        path.write_text(code)

        return str(path)

    path = tmp_path / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)
    return str(path)


def _runtime_with_injected_executable(port: int, exe: str, **kwargs) -> OllamaRuntime:
    """
    Builds a runtime whose executable is injected rather than discovered.

    Discovery is bypassed deliberately: it verifies identity by running
    `<exe> --version` and requiring "ollama" in the output, so a shell-script
    double would (correctly) be rejected as NOT_INSTALLED. Injecting the path
    lets these tests exercise the *state machine* without the double ever
    claiming to be Ollama.
    """
    runtime = OllamaRuntime(port=port, poll_interval=0.05, **kwargs)
    if os.name == "nt" and exe.lower().endswith(".py"):
        runtime._resolved_executable = sys.executable
        runtime._serve_args = [exe] + list(runtime._serve_args)
    else:
        runtime._resolved_executable = exe
    runtime._resolution_attempted = True
    return runtime


def _kill(pid):
    """
    Terminates AND reaps a spawned double.

    Reaping matters: an unreaped child leaves a ResourceWarning in the suite
    output and a stray process on the machine.
    """
    if not pid:
        return
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except psutil.NoSuchProcess:
        pass
    except psutil.TimeoutExpired:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except (psutil.NoSuchProcess, psutil.TimeoutExpired):
            pass


class _FailingHealthHandler(BaseHTTPRequestHandler):
    """Accepts connections and answers every request with HTTP 500."""

    def do_GET(self):  # noqa: N802
        body = b'{"error":"model not loaded"}'
        self.send_response(500)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def unhealthy_listener():
    """A listener that holds a port but whose health endpoint always fails."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FailingHealthHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# =========================================================================
# A - Ollama installed and running            (INTEGRATION)
# =========================================================================


def test_A_installed_and_running(requires_real_ollama):
    runtime = requires_real_ollama
    started = runtime.start()
    assert started.success, started.detail

    status = runtime.health()
    assert status.state == OLLAMA_RUNNING
    assert status.installed is True
    assert status.executable and os.path.isabs(status.executable)
    assert status.version, "the binary must report its own version"
    assert status.pid and status.process_running
    assert status.port_open is True
    assert status.api_healthy is True
    assert status.api_status_code == 200

    # The read-only diagnostic tools must agree with the runtime.
    assert check_ollama_runtime()["state"] == OLLAMA_RUNNING
    assert check_ollama()["is_available"] is True
    assert check_port(11434)["is_open"] is True
    assert health_check()["overall_status"] == "HEALTHY"

    # Real Ollama serves a JSON model list, not a canned string.
    probe = check_ollama()
    assert isinstance(probe["response"], dict)
    assert "models" in probe["response"]


# =========================================================================
# B - Ollama installed but stopped            (INTEGRATION)
# =========================================================================


def test_B_installed_but_stopped(requires_real_ollama):
    runtime = requires_real_ollama
    assert runtime.start().success, "could not reach a running baseline"

    stopped = runtime.stop()
    assert stopped.success is True
    assert stopped.state == OLLAMA_STOPPED
    assert stopped.port_closed is True

    status = runtime.health()
    assert status.state == OLLAMA_STOPPED
    assert status.installed is True, "stopped is not the same as absent"
    assert status.port_open is False
    assert status.api_healthy is False

    assert check_ollama()["is_available"] is False
    assert health_check()["overall_status"] == "DEGRADED"

    # The engine must call this a terminated daemon and offer the real remedy.
    d = diagnose(doctor_runner.collect_evidence(), "ConnectionRefusedError")
    assert d.hypothesis == "ollama_daemon_terminated"
    assert d.recommended_remediation == "start_ollama"
    assert d.requires_human is False

    # Restore.
    assert runtime.start().success


# =========================================================================
# C - Ollama unavailable / not installed
# =========================================================================


def test_C_not_installed_is_reported_on_this_machine(ollama_state):
    """
    On a machine without Ollama the whole stack must say NOT_INSTALLED - the
    runtime, the diagnostic tools, the health summary and the diagnosis engine.
    """
    if ollama_state != OLLAMA_NOT_INSTALLED:
        pytest.skip("Ollama is installed here; NOT_INSTALLED cannot be observed.")

    assert check_ollama_runtime()["state"] == OLLAMA_NOT_INSTALLED
    assert check_ollama()["installed"] is False
    assert check_ollama()["is_available"] is False
    assert health_check()["overall_status"] == "NOT_INSTALLED"

    d = diagnose(doctor_runner.collect_evidence(), "ConnectionRefusedError")
    assert d.hypothesis == "ollama_not_installed"
    assert d.runtime_state == OLLAMA_NOT_INSTALLED
    assert d.requires_human is True
    assert "OLLAMA_NOT_INSTALLED" in d.root_cause


def test_C_absent_runtime_is_never_confused_with_a_stopped_one(tmp_path):
    """
    Deterministic: a runtime that discovers nothing reports NOT_INSTALLED even
    when a listener happens to hold its port. Absence outranks an outage.
    """
    port = free_port()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", port))
    listener.listen(1)
    try:
        runtime = OllamaRuntime(port=port, executable=str(tmp_path / "does-not-exist"))
        status = runtime.health()
        assert status.state == OLLAMA_NOT_INSTALLED
        assert status.installed is False
        assert "not an outage" in status.detail
    finally:
        listener.close()


def test_C_start_is_refused_without_a_verified_executable(tmp_path):
    port = free_port()
    runtime = OllamaRuntime(port=port, executable=str(tmp_path / "no-such-binary"))
    res = runtime.start().as_dict()
    assert res["success"] is False
    assert res["state"] == OLLAMA_NOT_INSTALLED
    assert res["pid"] is None
    assert "No stand-in service is substituted" in res["detail"]


def test_C_a_file_named_ollama_is_not_trusted_without_identifying_itself(tmp_path):
    """
    Identity is verified by asking the binary, not by its filename. A script
    named `ollama` that does not report an Ollama version must be rejected.
    """
    impostor = _write_double(tmp_path, "ollama", 'echo "not the real thing"; exit 0\n')
    runtime = OllamaRuntime(executable=impostor)
    assert runtime.resolve_executable() is None
    assert runtime.is_installed() is False
    assert runtime.health().state == OLLAMA_NOT_INSTALLED


# =========================================================================
# D - Ollama fails during startup
# =========================================================================


def test_D_child_exits_immediately_is_not_reported_as_recovery(tmp_path):
    """
    The exact shape of defect D1: the spawned process dies before it can serve.
    The runtime must report failure, the real return code, and the child's own
    output - and must not claim a recovery.
    """
    port = free_port()
    double = _write_double(
        tmp_path,
        "dies",
        'echo "Error: could not bind or load models" >&2\nexit 3\n',
    )
    runtime = _runtime_with_injected_executable(port, double, readiness_timeout=3.0)

    res = runtime.start().as_dict()
    assert res["success"] is False
    assert res["state"] == OLLAMA_START_FAILED
    assert res["returncode"] == 3, "the real exit code must be captured"
    assert res["pid"], "the PID must be retained even though the child died"
    assert res["api_healthy"] is False
    assert "NOT claimed" in res["detail"]
    assert res["output_tail"] and "could not bind" in res["output_tail"]
    assert check_port(port)["is_open"] is False


def test_D_child_stays_alive_but_never_serves(tmp_path):
    """Alive is not ready: no listener ever appears, so this is not a recovery."""
    port = free_port()
    double = _write_double(tmp_path, "hangs", "sleep 20\n")
    runtime = _runtime_with_injected_executable(port, double, readiness_timeout=1.0)

    try:
        res = runtime.start().as_dict()
        assert res["success"] is False
        assert res["returncode"] is None, "the child is alive - it did not exit"
        assert res["pid"] == runtime.started_pid
        assert res["port_open"] is False
        assert res["state"] == OLLAMA_STOPPED
        assert "did not become ready" in res["detail"]
    finally:
        _kill(runtime.started_pid)


def test_D_allowlisted_action_surfaces_the_failure(tmp_path, monkeypatch):
    """`start_ollama()` must pass the runtime's honest verdict through unchanged."""
    port = free_port()
    double = _write_double(tmp_path, "dies", "exit 7\n")
    runtime = _runtime_with_injected_executable(port, double, readiness_timeout=2.0)

    import runner.remediation as rm

    monkeypatch.setattr(rm, "get_runtime", lambda: runtime)
    out = rm.start_ollama()
    assert out["success"] is False
    assert out["returncode"] == 7
    assert out["state"] == OLLAMA_START_FAILED


# =========================================================================
# E - A different process owns the port
# =========================================================================


def test_E_foreign_listener_is_not_adopted_as_our_start(tmp_path, local_http_server):
    """
    A live child plus an open port is still not a recovery when the socket
    belongs to somebody else. The open port must never be treated as evidence.
    """
    _host, foreign_port, _url = local_http_server
    double = _write_double(tmp_path, "hangs", "sleep 20\n")
    runtime = _runtime_with_injected_executable(foreign_port, double, readiness_timeout=1.0)

    try:
        res = runtime.start().as_dict()
        assert res["success"] is False
        assert res["socket_owned_by_child"] is False
        assert res["port_open"] is True, "the port really is open - by someone else"
        assert res["api_healthy"] is False
        assert res["foreign_listener_pid"] != res["pid"]
        assert "did not become ready" in res["detail"]
    finally:
        _kill(runtime.started_pid)


def test_E_health_refuses_running_when_no_process_matches(tmp_path, local_http_server):
    """
    health() must not report RUNNING on the strength of an answering socket when
    no process matches the Ollama identity.
    """
    _host, foreign_port, _url = local_http_server
    double = _write_double(tmp_path, "unused", "exit 0\n")
    runtime = _runtime_with_injected_executable(foreign_port, double)

    status = runtime.health()
    assert status.state == OLLAMA_UNHEALTHY
    assert status.port_open is True
    assert status.api_healthy is True, "the foreign listener does answer HTTP"
    assert status.process_running is False
    assert "no process matched the Ollama identity" in status.detail


def test_E_interpreter_is_never_treated_as_the_runtime(tmp_path):
    """
    Safety interlock: if the resolved executable were ever the Python interpreter
    running AI Doctor, matching by path would put every Python process on the
    machine into stop_ollama's kill list. It must not.
    """
    runtime = _runtime_with_injected_executable(free_port(), sys.executable)
    matches = runtime.find_ollama_processes()
    assert os.getpid() not in [p.pid for p in matches]
    for proc in matches:
        assert os.path.realpath(proc.exe() or "") != os.path.realpath(sys.executable)


# =========================================================================
# F - Health endpoint unavailable
# =========================================================================


def test_F_open_port_with_failing_health_endpoint_is_unhealthy(tmp_path, unhealthy_listener):
    port = unhealthy_listener
    double = _write_double(tmp_path, "unused", "exit 0\n")
    runtime = _runtime_with_injected_executable(port, double)

    status = runtime.health()
    assert status.state == OLLAMA_UNHEALTHY
    assert status.port_open is True
    assert status.api_healthy is False
    assert status.api_status_code == 500, "the failing status code must be captured"
    assert "did not answer successfully" in status.detail

    # The engine routes this to the API-unhealthy hypothesis, not to
    # "daemon terminated".
    evidence = {
        "runtime": status.as_dict(),
        "port_11434": {"is_open": True},
        "process_ollama": {"is_running": False},
        "ollama_api": {"is_available": False},
    }
    d = diagnose(evidence, "HTTP 500 from Ollama")
    assert d.hypothesis == "ollama_api_unhealthy"


def test_F_start_never_reports_healthy_when_the_endpoint_fails(tmp_path, unhealthy_listener):
    port = unhealthy_listener
    double = _write_double(tmp_path, "hangs", "sleep 20\n")
    runtime = _runtime_with_injected_executable(port, double, readiness_timeout=1.0)
    try:
        res = runtime.start().as_dict()
        assert res["success"] is False
        assert res["api_healthy"] is False
        assert res["state"] != OLLAMA_RUNNING
    finally:
        _kill(runtime.started_pid)


def test_F_a_dead_daemon_behind_a_stale_socket_is_not_verified(tmp_path):
    """
    Verification after remediation must reject a world where the port is closed,
    regardless of what the action claimed.
    """
    from runner.remediation_registry import remediation_registry

    port = free_port()
    runtime = get_runtime()
    original_port = runtime.port
    original_action = remediation_registry._actions["start_ollama"]["fn"]
    remediation_registry._actions["start_ollama"]["fn"] = lambda: {
        "action": "start_ollama",
        "success": True,
        "message": "lying action",
    }
    try:
        runtime.port = port
        out = doctor_runner.run_remediation_and_verify("start_ollama")
        assert out["success"] is False
        assert out["stage"] == "VERIFY"
        assert out["runtime_state"] != OLLAMA_RUNNING
    finally:
        remediation_registry._actions["start_ollama"]["fn"] = original_action
        runtime.port = original_port
    assert check_port(port)["is_open"] is False


# =========================================================================
# Cross-cutting: the singleton and honest reporting
# =========================================================================


def test_runtime_singleton_is_shared_by_remediation_and_diagnostics():
    """All callers must observe one runtime, not divergent copies."""
    assert get_runtime() is get_runtime()
    assert check_ollama_runtime()["state"] == get_runtime().health().state


def test_no_stand_in_server_is_left_listening_on_11434(ollama_state):
    """
    After everything above has run, port 11434 must not be held by anything this
    suite started. Guards against reintroducing the deleted fake service.
    """
    if ollama_state == OLLAMA_NOT_INSTALLED:
        assert check_port(11434)["is_open"] is False
        assert check_ollama()["is_available"] is False
