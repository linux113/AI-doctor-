"""
Tests for Ollama daemon recovery and restart lifecycle.
"""

from runner.remediation import start_ollama, stop_ollama
from runner.diagnostics import check_port, check_ollama


def test_ollama_recovery_lifecycle():
    # 1. Stop Ollama
    stop_res = stop_ollama()
    assert stop_res["action"] == "stop_ollama"
    assert stop_res["port_11434_closed"] is True

    # 2. Confirm down
    assert check_port(11434)["is_open"] is False
    assert check_ollama()["is_available"] is False

    # 3. Start Ollama
    start_res = start_ollama()
    assert start_res["success"] is True
    assert "started successfully" in start_res["message"] or "already running" in start_res["message"]

    # 4. Confirm restored
    assert check_port(11434)["is_open"] is True
    ollama_check = check_ollama()
    assert ollama_check["is_available"] is True
    assert ollama_check["status_code"] == 200
