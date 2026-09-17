"""
Tests for automatic retry of failed requests following recovery.
"""

from runner.remediation import retry_request, start_ollama


def test_retry_request_against_recovered_service():
    # Ensure Ollama is running
    start_ollama()

    # Retry against Ollama's tags endpoint
    res = retry_request("http://127.0.0.1:11434/api/tags", method="GET")
    assert res["success"] is True
    assert res["status_code"] == 200
    models = res["response"].get("models", [])
    assert any(m.get("name") == "llama3:latest" for m in models)


def test_retry_request_with_invalid_url_fails_gracefully():
    res = retry_request("http://127.0.0.1:59999/nonexistent", method="GET")
    assert res["success"] is False
    assert res["error"] is not None
