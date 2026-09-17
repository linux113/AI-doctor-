"""
Tests for the `retry_request` remediation action.

`retry_request` is a generic HTTP replay guarded by SSRF validation. It has no
Ollama dependency, so these tests run everywhere against an ephemeral local
listener. The one test that genuinely needs the real runtime is marked with
`requires_real_ollama` and skips explicitly when Ollama is absent - it is not
satisfied by a stand-in.
"""

import pytest

from runner.remediation import retry_request
from tests.conftest import unused_port


def test_retry_request_against_a_reachable_service(local_http_server):
    _host, _port, url = local_http_server
    res = retry_request(url, method="GET")
    assert res["success"] is True
    assert res["status_code"] == 200
    assert res["response"]["served_by"] == "generic-test-listener"


def test_retry_request_replays_a_post_with_payload(local_http_server):
    _host, _port, url = local_http_server
    res = retry_request(url, method="POST", payload={"prompt": "hello"})
    assert res["success"] is True
    assert res["status_code"] == 200
    assert res["response"]["method"] == "POST"


def test_retry_request_with_unreachable_port_fails_gracefully():
    port = unused_port()
    res = retry_request(f"http://127.0.0.1:{port}/nonexistent", method="GET")
    assert res["success"] is False
    assert res["error"] is not None


def test_retry_request_reports_the_real_error_class():
    """
    The action names the exception it caught instead of flattening every failure
    into one generic message (same defect class as D3 on the demo endpoint).
    """
    port = unused_port()
    res = retry_request(f"http://127.0.0.1:{port}/", method="GET")
    assert res["success"] is False
    assert res["error_class"] == "URLError" or res["error_class"].endswith("Error")


def test_retry_request_against_real_ollama(requires_real_ollama):
    """Integration: replay against the real daemon's /api/tags endpoint."""
    res = retry_request("http://127.0.0.1:11434/api/tags", method="GET")
    assert res["success"] is True
    assert res["status_code"] == 200
    # Real Ollama returns a models list; its contents depend on what the
    # operator has pulled, so only the shape is asserted.
    assert isinstance(res["response"], dict)
    assert "models" in res["response"]


def test_retry_request_blocks_a_hostile_destination():
    """SSRF guard stays enforced regardless of runtime availability."""
    res = retry_request("http://169.254.169.254/latest/meta-data/", method="GET")
    assert res["success"] is False
    assert "Security validation failed" in res["error"]
