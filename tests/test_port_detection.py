"""
Tests for the TCP port probe.

`check_port` is a service-agnostic TCP connect: it reports whether *something*
is listening. Testing it therefore needs a listener, not Ollama. These tests use
an ephemeral local socket and never bind 11434, so they run everywhere and assert
nothing false about the Ollama runtime.

Ollama-specific port behaviour (port 11434 owned by the real daemon) lives in
tests/test_ollama_integration.py and skips when Ollama is absent.
"""

import socket

from runner.diagnostics import check_port
from tests.conftest import unused_port


def test_port_detection_closed():
    port = unused_port()
    res = check_port(port)
    assert res["tool"] == "check_port"
    assert res["port"] == port
    assert res["is_open"] is False
    assert res["status"] == "CLOSED"


def test_port_detection_open(local_http_server):
    _host, port, _url = local_http_server
    res = check_port(port)
    assert res["tool"] == "check_port"
    assert res["port"] == port
    assert res["is_open"] is True
    assert res["status"] == "OPEN"


def test_port_detection_reports_a_listener_that_is_not_ollama_as_just_open():
    """
    A bare socket with no HTTP server behind it is still an OPEN port.

    This is the fact defect D1 turned on: an open port is not proof that Ollama
    recovered. check_port must keep reporting only what it observes, and the
    runtime-state decision belongs to OllamaRuntime, which additionally requires
    a live process and a healthy API.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        assert check_port(port)["is_open"] is True
    finally:
        listener.close()


def test_port_detection_never_claims_identity_of_the_listener():
    """The probe returns no process attribution - it must not imply one."""
    _host, port, _url = None, None, None
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        res = check_port(port)
        for forbidden in ("pid", "process", "owner", "is_ollama"):
            assert forbidden not in res, f"check_port must not assert {forbidden}"
    finally:
        listener.close()
