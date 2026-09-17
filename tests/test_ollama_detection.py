"""
Tests for Ollama service availability detection.
"""

from runner.diagnostics import check_ollama
from runner.remediation import start_ollama, stop_ollama


def test_ollama_detection_when_stopped():
    stop_ollama()
    result = check_ollama()
    assert result["tool"] == "check_ollama"
    assert result["is_available"] is False
    assert result["error"] is not None


def test_ollama_detection_when_running():
    start_ollama()
    result = check_ollama()
    assert result["tool"] == "check_ollama"
    assert result["is_available"] is True
    assert result["status_code"] == 200
    assert "Models available" in result["response"]
