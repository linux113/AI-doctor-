"""
Regression tests for the three confirmed defects fixed in this pass, plus the
audit-trail requirement.

    D1  False-positive recovery: `start_ollama` inferred success from an open
        port, so a child that died immediately - or a port owned by an unrelated
        process - was reported as a successful recovery and the incident was
        marked RESOLVED.
    D2  Secret leak: `request_context`, `detected_error` and `evidence` were
        persisted and served verbatim, so a bearer token or API key in a failed
        request reached storage, the API and the dashboard.
    D3  Error misreporting: `demo_query` caught the real exception, discarded it,
        and stored one hardcoded "ConnectionRefusedError ... (Connection refused)"
        string for every failure type.

Plus:
    Phase 6  `action_result` and `audit_log` are first-class on the Incident,
             survive the lifecycle, and contain no secrets.

Secret fixtures are assembled at runtime rather than written as literals, so
credential-shaped strings are never committed.
"""

import json
import socket
import urllib.error

import pytest
from fastapi.testclient import TestClient

from backend.main import app, _classify_upstream_error
from backend.models import Incident, TimelineEvent
from backend.storage import IncidentRepository
from runner.doctor_runner import doctor_runner
from runner.ollama_runtime import OLLAMA_NOT_INSTALLED
from runner.redaction import sanitize_deep

client = TestClient(app)

_FILLER = "A1B2C3D4E5F6G7H8I9J0KLMNOPQRSTUVWX"
BEARER = "Bearer " + "sk-proj-" + _FILLER.lower()[:24]
AWS_KEY_ID = "AKIA" + _FILLER[:16]
AWS_SECRET = "aws_secret_access_key=" + _FILLER.lower()[:30]
GITHUB_TOKEN = "ghp_" + _FILLER[:36]
PASSWORD_ASSIGN = 'password = "' + _FILLER.lower()[:14] + '"'
PEM = "-----BEGIN PRIVATE KEY-----\nMIIE" + _FILLER[:20] + "\n-----END PRIVATE KEY-----"

ALL_SECRETS = [BEARER, AWS_KEY_ID, AWS_SECRET, GITHUB_TOKEN, PASSWORD_ASSIGN, "MIIE" + _FILLER[:20]]


def _assert_no_secret(blob: str):
    for secret in ALL_SECRETS:
        assert secret not in blob, f"secret survived sanitisation: {secret[:18]}..."


# =========================================================================
# D1 - no false-positive recovery
# =========================================================================


def test_D1_start_ollama_does_not_claim_recovery_without_a_runtime(ollama_state):
    if ollama_state != OLLAMA_NOT_INSTALLED:
        pytest.skip("Ollama is installed here; see tests/test_ollama_integration.py")

    from runner.remediation import start_ollama

    res = start_ollama()
    assert res["success"] is False
    assert res["state"] == OLLAMA_NOT_INSTALLED
    assert res["pid"] is None


def test_D1_incident_stays_unresolved_when_the_action_cannot_recover(ollama_state):
    """The loop must not mark RESOLVED unless the runtime really came back."""
    if ollama_state != OLLAMA_NOT_INSTALLED:
        pytest.skip("requires a machine without Ollama to observe an unrecoverable start.")

    out = doctor_runner.heal_incident({
        "incident_id": "inc-d1-unresolved",
        "detected_error": "ConnectionRefusedError",
        "request_context": {"url": "http://127.0.0.1:11434/api/generate", "method": "POST"},
    })
    assert out["status"] == "FAILED"
    assert out["failed_stage"] == "FIX"
    assert out["resolved_at"] is None
    assert out["action_result"]["success"] is False
    stages = [t["stage"] for t in out["timeline"]]
    assert "RESOLVED" not in stages
    assert stages[-1] == "FAILED"


def test_D1_a_lying_action_does_not_produce_a_resolved_incident():
    """
    Even when the action itself reports success, verification must reject the
    claim if the runtime never reached RUNNING. This is the guard that turns a
    false positive into an honest failure.
    """
    from runner.remediation_registry import remediation_registry

    original = remediation_registry._actions["start_ollama"]["fn"]
    remediation_registry._actions["start_ollama"]["fn"] = lambda: {
        "action": "start_ollama",
        "success": True,
        "message": "claims recovery",
    }
    try:
        out = doctor_runner.heal_incident({
            "incident_id": "inc-d1-liar",
            "detected_error": "ConnectionRefusedError",
        })
        if out["runtime_state"] == "OLLAMA_RUNNING":
            pytest.skip("a real Ollama daemon is running; the claim cannot be disproved.")
        assert out["status"] == "FAILED"
        assert out["failed_stage"] == "VERIFY"
        assert "RESOLVED" not in [t["stage"] for t in out["timeline"]]
    finally:
        remediation_registry._actions["start_ollama"]["fn"] = original


def test_D1_start_ollama_endpoint_does_not_report_success_on_failure(ollama_state):
    """The HTTP layer must not answer {"status": "started"} when nothing started."""
    if ollama_state != OLLAMA_NOT_INSTALLED:
        pytest.skip("requires a machine without Ollama.")

    res = client.post("/api/demo/start-ollama")
    assert res.status_code == 500
    body = res.json()
    assert body["status"] == "failed"
    assert body["success"] is False
    assert body["state"] == OLLAMA_NOT_INSTALLED


def test_D1_stop_ollama_endpoint_reports_when_nothing_was_stopped(ollama_state):
    if ollama_state != OLLAMA_NOT_INSTALLED:
        pytest.skip("requires a machine without Ollama.")

    body = client.post("/api/demo/stop-ollama").json()
    assert body["status"] == "no_runtime_stopped"
    assert body["success"] is False


# =========================================================================
# D2 - one authoritative sanitisation path, applied before persistence
# =========================================================================


def test_D2_sanitisation_happens_at_the_model_boundary():
    """Constructing the Incident is already enough - no caller has to remember."""
    inc = Incident(
        detected_error=f"upstream 500 with {BEARER}",
        request_context={"headers": {"Authorization": BEARER, "X-GitHub": GITHUB_TOKEN}},
    )
    _assert_no_secret(json.dumps(inc.model_dump()))
    assert "[REDACTED" in inc.detected_error


def test_D2_nested_evidence_and_lists_are_redacted():
    inc = Incident(
        detected_error="boom",
        evidence={
            "level1": {"level2": [{"level3": {"token": BEARER, "pem": PEM}}]},
            "logs": [f"line with {AWS_SECRET}", "clean line"],
        },
    )
    blob = json.dumps(inc.model_dump())
    _assert_no_secret(blob)
    assert inc.evidence["logs"][1] == "clean line", "benign content must survive"


def test_D2_sensitive_dict_keys_are_redacted_even_without_a_pattern_match():
    """
    {"password": "hunter2"} contains no "password=" substring, so content
    patterns alone cannot catch it. The key itself must trigger redaction.
    """
    inc = Incident(
        detected_error="boom",
        request_context={
            "payload": {
                "password": "hunter2-s3cret-value",
                "api_key": "some-key-value",
                "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI-K7MDENG-bPxRfiCY",
                "prompt": "keep me",
            }
        },
    )
    payload = inc.request_context["payload"]
    assert payload["password"] == "[REDACTED_PASSWORD]"
    assert payload["api_key"] == "[REDACTED_KEY]"
    assert "wJalrXUtnFEMI" not in json.dumps(payload)
    assert payload["prompt"] == "keep me", "non-secret fields must not be destroyed"


def test_D2_secrets_never_reach_the_persisted_incident():
    repo = IncidentRepository()
    inc = Incident(
        detected_error=f"failed call carrying {BEARER} and {AWS_KEY_ID}",
        request_context={"payload": {"prompt": "x", "secret_key": _FILLER.lower()[:20]}},
        evidence={"raw": PEM},
        timeline=[TimelineEvent(stage="DETECTED", timestamp="t", description=f"saw {GITHUB_TOKEN}")],
    )
    repo.save(inc)
    stored = repo.get(inc.incident_id)
    _assert_no_secret(json.dumps(stored.model_dump()))
    _assert_no_secret(json.dumps(stored.to_dynamodb_item()))


def test_D2_secrets_never_reach_an_api_response():
    res = client.post("/api/demo/query", json={"prompt": f"leak {BEARER}", "model": "llama3:latest"})
    assert res.status_code == 500
    _assert_no_secret(res.text)

    incident_id = res.json()["incident_id"]
    for path in (f"/api/incidents/{incident_id}", "/api/incidents/latest", "/api/incidents"):
        body = client.get(path).text
        _assert_no_secret(body)


def test_D2_the_prompt_itself_is_stored_redacted_when_it_carries_a_secret():
    """User text is reflected into the incident, so it is a leak vector too."""
    res = client.post("/api/demo/query", json={"prompt": f"token: {GITHUB_TOKEN}"})
    stored = client.get(f"/api/incidents/{res.json()['incident_id']}").json()
    assert GITHUB_TOKEN not in json.dumps(stored)
    assert stored["request_context"]["payload"]["prompt"]


def test_D2_sanitize_deep_does_not_mutate_its_input():
    original = {"a": [BEARER], "b": {"c": AWS_SECRET}}
    snapshot = json.dumps(original)
    sanitize_deep(original)
    assert json.dumps(original) == snapshot, "the caller's structure was modified in place"


def test_D2_sanitize_deep_preserves_non_string_scalars():
    out = sanitize_deep({"code": 500, "ok": True, "nothing": None, "ratio": 0.5})
    assert out == {"code": 500, "ok": True, "nothing": None, "ratio": 0.5}


# =========================================================================
# D3 - the real exception is preserved and classified
# =========================================================================


def test_D3_classification_is_structural_not_a_constant():
    url = "http://127.0.0.1:11434/api/generate"
    cases = [
        (ConnectionRefusedError(111, "Connection refused"), "ConnectionRefusedError"),
        (urllib.error.URLError(ConnectionRefusedError(111, "refused")), "ConnectionRefusedError"),
        (urllib.error.HTTPError(url, 503, "Service Unavailable", {}, None), "HTTPError"),
        (TimeoutError("timed out"), "TimeoutError"),
        (socket.timeout("timed out"), "TimeoutError"),
        (urllib.error.URLError(socket.timeout("timed out")), "TimeoutError"),
        (ConnectionResetError(104, "reset"), "ConnectionResetError"),
        (OSError(13, "Permission denied"), "PermissionError"),
    ]
    seen = set()
    for exc, expected in cases:
        error_class, detail = _classify_upstream_error(exc, url, 3.0)
        assert error_class == expected, f"{exc!r} classified as {error_class}"
        assert detail and isinstance(detail, str)
        seen.add(error_class)
    # A timeout must be distinguishable from a refused connection.
    assert {"ConnectionRefusedError", "TimeoutError", "HTTPError"} <= seen


def test_D3_http_error_preserves_the_upstream_status_code():
    url = "http://127.0.0.1:11434/api/generate"
    error_class, detail = _classify_upstream_error(
        urllib.error.HTTPError(url, 503, "Service Unavailable", {}, None), url, 3.0
    )
    assert error_class == "HTTPError"
    assert "503" in detail


def test_D3_demo_query_reports_the_real_error_class(monkeypatch):
    """A timeout must not be reported as a refused connection."""
    import urllib.request

    def fake_urlopen(*args, **kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    res = client.post("/api/demo/query", json={"prompt": "hello"})
    body = res.json()
    assert res.status_code == 500
    assert body["error_class"] == "TimeoutError"
    assert "ConnectionRefusedError" not in body["error"]
    assert "did not respond within" in body["error_detail"]

    stored = client.get(f"/api/incidents/{body['incident_id']}").json()
    assert stored["error_class"] == "TimeoutError"
    assert stored["error_detail"] == body["error_detail"]


def test_D3_demo_query_preserves_an_http_error_status(monkeypatch):
    import urllib.request

    def fake_urlopen(*args, **kwargs):
        raise urllib.error.HTTPError(
            "http://127.0.0.1:11434/api/generate", 500, "Internal Server Error", {}, None
        )

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    body = client.post("/api/demo/query", json={"prompt": "hello"}).json()
    assert body["error_class"] == "HTTPError"
    assert "500" in body["error_detail"]


def test_D3_demo_query_reports_a_refused_connection_as_refused():
    """The historical case must still be reported correctly - now because it is true."""
    from runner.diagnostics import check_port

    if check_port(11434)["is_open"]:
        pytest.skip("something is listening on 11434; a refused connection cannot be observed.")

    body = client.post("/api/demo/query", json={"prompt": "hello"}).json()
    assert body["error_class"] == "ConnectionRefusedError"
    assert "Connection refused" in body["error_detail"]


def test_D3_sensitive_values_in_exception_text_are_redacted(monkeypatch):
    import urllib.request

    def fake_urlopen(*args, **kwargs):
        raise OSError(f"could not connect using {BEARER} and {AWS_SECRET}")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    res = client.post("/api/demo/query", json={"prompt": "hello"})
    _assert_no_secret(res.text)
    stored = client.get(f"/api/incidents/{res.json()['incident_id']}").json()
    _assert_no_secret(json.dumps(stored))
    assert "[REDACTED" in stored["error_detail"]


def test_D3_not_installed_is_reported_as_absent_not_as_an_outage(ollama_state):
    if ollama_state != OLLAMA_NOT_INSTALLED:
        pytest.skip("requires a machine without Ollama.")

    body = client.post("/api/demo/query", json={"prompt": "hello"}).json()
    assert body["runtime_state"] == OLLAMA_NOT_INSTALLED
    assert body["requires_human"] is True
    assert "NOT INSTALLED" in body["error_detail"]


# =========================================================================
# Phase 6 - first-class action_result and audit_log
# =========================================================================


def test_phase6_incident_carries_action_result_and_audit_log():
    inc = Incident(detected_error="boom")
    assert inc.action_result is None
    assert inc.audit_log == []

    inc.action_result = {"action": "start_ollama", "success": False, "state": OLLAMA_NOT_INSTALLED}
    inc.audit_log = [{"action": "start_ollama", "incident_id": inc.incident_id, "status": "FAILED"}]
    assert inc.action_result["success"] is False
    assert inc.audit_log[0]["incident_id"] == inc.incident_id


def test_phase6_heal_records_an_incident_scoped_audit_trail():
    out = doctor_runner.heal_incident({
        "incident_id": "inc-audit-scope",
        "detected_error": "ConnectionRefusedError",
    })
    assert out["audit_log"], "a remediation attempt must always leave an audit trail"
    for entry in out["audit_log"]:
        assert entry["incident_id"] == "inc-audit-scope"
        assert entry["action"] in ("start_ollama", "retry_request", "stop_ollama")
        assert entry["allowed"] in (True, False)
        assert entry["status"] in ("SUCCESS", "FAILED", "BLOCKED", "PENDING")
        assert entry["timestamp"]
    assert out["action_result"] is not None
    assert out["action_result"]["action"] == out["action_taken"]


def test_phase6_audit_trail_survives_persistence_and_the_api(ollama_state):
    if ollama_state != OLLAMA_NOT_INSTALLED:
        pytest.skip("uses the absent-runtime path to produce a deterministic FAILED heal.")

    out = doctor_runner.heal_incident({
        "incident_id": "inc-audit-persist",
        "detected_error": "ConnectionRefusedError",
    })
    repo = IncidentRepository()
    inc = Incident(
        incident_id=out["incident_id"],
        detected_error="ConnectionRefusedError",
        status=out["status"],
        action_taken=out["action_taken"],
        action_result=out["action_result"],
        audit_log=out["audit_log"],
        runtime_state=out["runtime_state"],
        requires_human=out["requires_human"],
        failed_stage=out["failed_stage"],
        evidence=out["evidence"],
        timeline=[
            TimelineEvent(
                stage=t["stage"],
                timestamp=t["timestamp"],
                description=t["description"],
                details=t.get("details"),
                verified=t.get("verified"),
            )
            for t in out["timeline"]
        ],
    )
    repo.save(inc)
    restored = repo.get(inc.incident_id)

    assert restored.status == "FAILED"
    assert restored.action_result["success"] is False
    assert restored.action_result["state"] == OLLAMA_NOT_INSTALLED
    assert len(restored.audit_log) == len(out["audit_log"])
    assert restored.audit_log[0]["incident_id"] == "inc-audit-persist"
    assert restored.runtime_state == OLLAMA_NOT_INSTALLED
    assert restored.requires_human is True
    assert [t.stage for t in restored.timeline][-1] == "FAILED"


def test_phase6_audit_log_never_contains_secrets():
    from runner.remediation_registry import remediation_registry

    blocked = remediation_registry.execute(
        "exfiltrate", incident_id="inc-audit-secret"
    )
    assert blocked["blocked"] is True
    entries = [e for e in remediation_registry.get_audit_log(20) if e["action"] == "exfiltrate"]
    assert entries and entries[-1]["status"] == "BLOCKED"
    assert entries[-1]["incident_id"] == "inc-audit-secret"

    # A failing action whose error text carries a credential must be sanitised
    # inside the audit record itself.
    original = remediation_registry._actions["start_ollama"]["fn"]
    remediation_registry._actions["start_ollama"]["fn"] = lambda: {
        "action": "start_ollama",
        "success": False,
        "error": f"spawn failed with {BEARER}",
    }
    try:
        remediation_registry.execute("start_ollama", incident_id="inc-audit-secret2")
        entry = [
            e for e in remediation_registry.get_audit_log(5) if e.get("incident_id") == "inc-audit-secret2"
        ][-1]
        assert entry["status"] == "FAILED"
        _assert_no_secret(json.dumps(entry))
        assert "[REDACTED" in entry["error"]
    finally:
        remediation_registry._actions["start_ollama"]["fn"] = original
