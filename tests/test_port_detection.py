"""
Tests for TCP port probe detection.
"""

from runner.diagnostics import check_port
from runner.remediation import start_ollama, stop_ollama


def test_port_detection_closed():
    stop_ollama()
    res = check_port(11434)
    assert res["tool"] == "check_port"
    assert res["port"] == 11434
    assert res["is_open"] is False
    assert res["status"] == "CLOSED"


def test_port_detection_open():
    start_ollama()
    res = check_port(11434)
    assert res["tool"] == "check_port"
    assert res["port"] == 11434
    assert res["is_open"] is True
    assert res["status"] == "OPEN"
