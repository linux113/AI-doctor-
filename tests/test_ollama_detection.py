"""
Tests for Ollama availability detection.

Split deliberately in two:

* Assertions about what the probe reports **on this machine** run everywhere,
  because they are driven by the authoritative runtime state rather than by a
  hardcoded expectation of a healthy daemon.
* Assertions that Ollama is **running and serving** require the real binary and
  skip explicitly when it is absent (`requires_real_ollama`). No stand-in server
  is substituted to make them pass.
"""

import pytest

from runner.diagnostics import check_ollama, check_ollama_runtime
from runner.ollama_runtime import (
    OLLAMA_NOT_INSTALLED,
    OLLAMA_RUNNING,
    OLLAMA_STOPPED,
    OLLAMA_UNHEALTHY,
)
from runner.remediation import start_ollama, stop_ollama


def test_check_ollama_reports_the_probe_shape():
    result = check_ollama()
    assert result["tool"] == "check_ollama"
    assert result["endpoint"].endswith("/api/tags")
    assert isinstance(result["is_available"], bool)
    # The runtime state is reported alongside the probe so callers can tell
    # "absent" from "down".
    assert result["runtime_state"] in (
        OLLAMA_NOT_INSTALLED,
        OLLAMA_STOPPED,
        OLLAMA_UNHEALTHY,
        OLLAMA_RUNNING,
    )
    assert isinstance(result["installed"], bool)


def test_check_ollama_never_fabricates_a_response_body():
    """
    The deleted Python stand-in answered /api/tags with a canned
    "Models available: 1" string. Detection must not invent a payload: when the
    API is unreachable the response is None and an error is recorded.
    """
    result = check_ollama()
    if not result["is_available"]:
        assert result["response"] is None
        assert result["error"]


def test_check_ollama_runtime_reports_the_authoritative_state():
    result = check_ollama_runtime()
    assert result["tool"] == "check_ollama_runtime"
    assert result["state"] in (
        OLLAMA_NOT_INSTALLED,
        OLLAMA_STOPPED,
        OLLAMA_UNHEALTHY,
        OLLAMA_RUNNING,
    )
    if result["state"] == OLLAMA_RUNNING:
        assert result["installed"] is True
        assert result["api_healthy"] is True
        assert result["port_open"] is True
        assert result["pid"]


def test_detection_is_consistent_between_probe_and_runtime():
    """The HTTP probe and the runtime probe must not contradict each other."""
    probe = check_ollama()
    runtime = check_ollama_runtime()
    assert probe["is_available"] == runtime["api_healthy"]
    if runtime["state"] == OLLAMA_NOT_INSTALLED:
        assert probe["is_available"] is False


def test_ollama_detection_when_running(requires_real_ollama):
    """Integration: the real daemon answers GET /api/tags with HTTP 200."""
    runtime = requires_real_ollama
    if runtime.health().state != OLLAMA_RUNNING:
        pytest.skip(f"real Ollama installed but not healthy (state={runtime.health().state}).")

    result = check_ollama()
    assert result["is_available"] is True
    assert result["status_code"] == 200
    # Real Ollama returns a JSON document with a models list - not a canned
    # human-readable string.
    assert isinstance(result["response"], dict)
    assert "models" in result["response"]


def test_detection_after_a_real_stop(requires_real_ollama):
    """Integration: stopping the real daemon makes the probe report unavailable."""
    runtime = requires_real_ollama
    if runtime.health().state != OLLAMA_RUNNING:
        pytest.skip("requires a running Ollama daemon to stop.")
    try:
        stop_res = stop_ollama()
        assert stop_res["success"] is True
        assert stop_res["port_closed"] is True
        assert check_ollama()["is_available"] is False
    finally:
        start_ollama()
