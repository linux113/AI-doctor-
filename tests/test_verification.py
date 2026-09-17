"""
Tests for the post-remediation VERIFY stage.

The VERIFY stage decides whether a remediation actually restored the runtime.
Defect D1 made it accept "something is listening on the port" as proof, so a
dead daemon was reported as a successful recovery. These tests pin the corrected
behaviour: verification requires the authoritative OLLAMA_RUNNING state, and it
must reject both an action that lies about success and a port owned by a
different process.

Nothing here impersonates Ollama on port 11434. The foreign-listener test uses an
ephemeral port and asserts FAILURE - it exists to prove the runtime is not fooled.
"""

import sys

import pytest

from runner.doctor_runner import doctor_runner
from runner.ollama_runtime import OllamaRuntime
from runner.remediation import stop_ollama
from runner.remediation_registry import remediation_registry


def test_verification_stage_succeeds_when_service_recovers(requires_real_ollama):
    """INTEGRATION - requires the real Ollama daemon; skips when absent."""
    stop_ollama()

    result = doctor_runner.run_remediation_and_verify(remediation_action="start_ollama")

    assert result["success"] is True
    assert result["verification"]["port_open"] is True
    assert result["verification"]["api_available"] is True
    assert result["verification"]["runtime_state"] == "OLLAMA_RUNNING"
    assert result["verification"]["pid"], "verification must name the live daemon PID"
    assert "verification_time" in result["verification"]


def test_verification_detects_failure_if_action_does_not_restore_the_runtime():
    """
    An action that claims success without restoring the runtime must still fail
    verification - the VERIFY half of defect D1.

    The action is replaced with one that lies: it reports success while nothing
    is listening. The loop must not adopt that verdict, and no stand-in server
    is started to make the test pass.
    """
    original = remediation_registry._actions["start_ollama"]["fn"]
    remediation_registry._actions["start_ollama"]["fn"] = lambda: {
        "action": "start_ollama",
        "success": True,
        "message": "claimed a recovery that did not happen",
    }
    try:
        result = doctor_runner.run_remediation_and_verify(remediation_action="start_ollama")
        assert result["success"] is False
        assert result["stage"] == "VERIFY"
        assert result["runtime_state"] != "OLLAMA_RUNNING"
        assert "RUNNING state" in result["error"]
        assert "not accepted as proof" in result["error"]
    finally:
        remediation_registry._actions["start_ollama"]["fn"] = original


def test_verification_rejects_a_port_owned_by_a_different_process(local_http_server):
    """
    Scenario E: the port is open, but a DIFFERENT process owns it.

    A plain listener holds an ephemeral port while the runtime is pointed at an
    executable that stays alive without ever serving. An open port plus a live
    child must still not be accepted as recovery, and the foreign listener must
    be identified rather than adopted.
    """
    _host, foreign_port, _url = local_http_server

    runtime = OllamaRuntime(port=foreign_port, readiness_timeout=2.0, poll_interval=0.1)
    # Inject the executable directly: real discovery would (correctly) refuse to
    # treat a Python interpreter as the ollama binary, and this test needs a
    # child that stays alive without binding the port.
    runtime._resolved_executable = sys.executable
    runtime._resolution_attempted = True
    runtime._serve_args = ["-c", "import time; time.sleep(30)"]

    try:
        result = runtime.start().as_dict()
        assert result["success"] is False
        assert result["socket_owned_by_child"] is False
        assert result["api_healthy"] is False
        assert result["pid"], "the spawned child must still be reported"
        assert result["port_open"] is True, "the foreign listener really is holding the port"

        # Attributing a listening socket to a PID needs privilege on Linux. When
        # it is unavailable the runtime must treat the port as UNVERIFIED rather
        # than adopt it as proof - which is the property that matters here. When
        # it IS available, the owner must be named and must not be our child.
        if result["foreign_listener_pid"] is not None:
            assert result["foreign_listener_pid"] != result["pid"]
            assert "DIFFERENT process" in result["detail"]
        else:
            assert "did not become ready" in result["detail"]
            assert "The port is open but the API did not answer successfully." in result["detail"]
    finally:
        # Terminate the spawned child directly. runtime.stop() is deliberately
        # NOT used here: this test injects the Python interpreter as the
        # "executable", and although find_ollama_processes() refuses to match by
        # path in that case, the test must not depend on that interlock to avoid
        # signalling unrelated processes.
        if runtime.started_pid:
            import psutil

            try:
                child = psutil.Process(runtime.started_pid)
                child.terminate()
                child.wait(timeout=5)
            except (psutil.NoSuchProcess, psutil.TimeoutExpired):
                pass


def test_verification_of_stop_reports_failure_because_the_runtime_is_down():
    """
    Verifying a stop action must fail: stopping removes the thing verification
    looks for. This asserts the loop does not confuse "action completed" with
    "service healthy".
    """
    result = doctor_runner.run_remediation_and_verify(remediation_action="stop_ollama")
    assert result["success"] is False
    assert result["stage"] in ("FIX", "VERIFY")
    if result["stage"] == "VERIFY":
        assert result["runtime_state"] != "OLLAMA_RUNNING"
