"""
Tests for the Ollama recovery lifecycle (stop -> confirm down -> start -> confirm up).

The full lifecycle needs the real daemon and skips when it is absent. What runs
everywhere is the honesty of the failure path: with no Ollama installed,
`start_ollama` must report failure and the runtime state must say so, rather than
claiming a recovery that did not happen (defect D1) or silently standing up a
Python HTTP server in its place.
"""

import pytest

from runner.diagnostics import check_ollama, check_port
from runner.ollama_runtime import OLLAMA_NOT_INSTALLED, OLLAMA_RUNNING, get_runtime
from runner.remediation import start_ollama, stop_ollama


# =========================================================================
# Runs everywhere: honest reporting when the runtime is absent
# =========================================================================


def test_start_ollama_reports_failure_when_the_runtime_is_not_installed(ollama_state):
    if ollama_state != OLLAMA_NOT_INSTALLED:
        pytest.skip("Ollama is installed on this machine; see the integration test below.")

    res = start_ollama()
    assert res["success"] is False, "start_ollama must not claim success without a real daemon"
    assert res["state"] == OLLAMA_NOT_INSTALLED
    assert res["pid"] is None
    assert res["port_open"] is False
    assert res["api_healthy"] is False
    assert "not installed" in res["detail"].lower() or "no verified" in res["detail"].lower()


def test_absent_runtime_is_not_reported_as_an_outage(ollama_state):
    """OLLAMA_NOT_INSTALLED must not be laundered into 'daemon terminated'."""
    if ollama_state != OLLAMA_NOT_INSTALLED:
        pytest.skip("Ollama is installed on this machine.")

    runtime = check_port(11434)
    assert runtime["is_open"] is False

    from runner.diagnosis import diagnose
    from runner.doctor_runner import doctor_runner

    d = diagnose(doctor_runner.collect_evidence(), "ConnectionRefusedError")
    assert d.hypothesis == "ollama_not_installed"
    assert "OLLAMA_NOT_INSTALLED" in d.root_cause
    assert d.requires_human is True
    assert d.runtime_state == OLLAMA_NOT_INSTALLED


def test_start_ollama_does_not_substitute_a_stand_in_server(ollama_state):
    """
    After a failed start nothing may be listening on 11434.

    Guards against reintroducing the deleted fake service: if any code path
    started a Python HTTP server to make the demo work, this assertion fails.
    """
    if ollama_state != OLLAMA_NOT_INSTALLED:
        pytest.skip("Ollama is installed on this machine.")

    start_ollama()
    assert check_port(11434)["is_open"] is False
    assert check_ollama()["is_available"] is False


def test_stop_ollama_reports_nothing_to_stop_when_the_runtime_is_absent(ollama_state):
    if ollama_state != OLLAMA_NOT_INSTALLED:
        pytest.skip("Ollama is installed on this machine.")

    res = stop_ollama()
    assert res["success"] is False
    assert res["terminated_pids"] == []
    assert res["port_closed"] is True


# =========================================================================
# Integration: requires the real daemon
# =========================================================================


def test_ollama_recovery_lifecycle(requires_real_ollama):
    """Stop the real daemon, confirm it is down, start it, confirm it is up."""
    runtime = requires_real_ollama
    if runtime.health().state != OLLAMA_RUNNING:
        # Bring it up first so the lifecycle has a defined starting point.
        assert runtime.start().success, "could not reach a running baseline"

    # 1. Stop
    stop_res = stop_ollama()
    assert stop_res["action"] == "stop_ollama"
    assert stop_res["success"] is True
    assert stop_res["port_closed"] is True

    # 2. Confirm down
    assert check_port(11434)["is_open"] is False
    assert check_ollama()["is_available"] is False

    # 3. Start the real daemon
    start_res = start_ollama()
    assert start_res["success"] is True, start_res["detail"]
    assert start_res["state"] == OLLAMA_RUNNING
    assert start_res["pid"], "a real start must report the daemon PID"
    assert start_res["socket_owned_by_child"] is True

    # 4. Confirm restored
    assert check_port(11434)["is_open"] is True
    ollama_check = check_ollama()
    assert ollama_check["is_available"] is True
    assert ollama_check["status_code"] == 200


def test_start_is_idempotent_when_already_running(requires_real_ollama):
    """A second start must not spawn a duplicate daemon or report failure."""
    runtime = requires_real_ollama
    if runtime.health().state != OLLAMA_RUNNING:
        assert runtime.start().success

    res = start_ollama()
    assert res["success"] is True
    assert res["already_running"] is True
    assert get_runtime().health().state == OLLAMA_RUNNING
