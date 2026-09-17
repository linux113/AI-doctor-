"""
Comprehensive integration tests for AI Doctor backend API endpoints.
Validates the full DETECT -> DIAGNOSE -> FIX -> VERIFY -> RETRY autonomous cycle.
"""

from fastapi.testclient import TestClient
from backend.main import app
from runner.remediation import start_ollama, stop_ollama

client = TestClient(app)


def test_health_endpoint():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["doctor_runner"] == "active"


def test_system_status_endpoint(ollama_state):
    """
    Reports the real runtime state. "not_installed" is a distinct value from
    "down": the first means the binary is absent and no allowlisted action can
    help, the second means a daemon died and start_ollama may recover it.
    """
    from runner.ollama_runtime import OLLAMA_NOT_INSTALLED, OLLAMA_RUNNING

    res = client.get("/api/system-status")
    assert res.status_code == 200
    data = res.json()
    assert data["ollama"] in ("healthy", "down", "not_installed")
    assert data["backend"] == "healthy"
    assert data["doctor_runner"] == "active"
    assert data["runtime_state"] == ollama_state

    if ollama_state == OLLAMA_NOT_INSTALLED:
        assert data["ollama"] == "not_installed"
        assert data["port_11434_open"] is False
        assert data["application"] == "degraded"
    elif ollama_state == OLLAMA_RUNNING:
        assert data["ollama"] == "healthy"
        assert data["port_11434_open"] is True


def test_full_autonomous_healing_lifecycle(requires_real_ollama):
    """
    INTEGRATION - requires the real Ollama daemon; skips when it is absent.

    Validates the end-to-end autonomous healing cycle:
    1. Stop Ollama -> failure injected
    2. Demo query fails with 500 -> incident detected & recorded
    3. Call /api/diagnose -> system evidence collected, root cause deduced
    4. Call /api/heal -> remediation executed, verified, original request retried
    5. Incident timeline reflects full progression to RESOLVED
    """
    # 0. Reach a known-good baseline with the real daemon.
    assert requires_real_ollama.start().success, "could not start real Ollama for the lifecycle test"

    # 1. Simulate failure
    stop_res = client.post("/api/demo/stop-ollama")
    assert stop_res.status_code == 200
    assert stop_res.json()["success"] is True, "the real daemon should have been stopped"

    # 2. Query fails with 500
    query_res = client.post("/api/demo/query", json={"prompt": "Diagnose elevated latency"})
    assert query_res.status_code == 500
    err_data = query_res.json()
    incident_id = err_data["incident_id"]
    assert err_data["incident_status"] == "DETECTED"

    # 3. Diagnose
    diag_res = client.post("/api/diagnose", json={"incident_id": incident_id})
    assert diag_res.status_code == 200
    diag_data = diag_res.json()
    assert "port_11434" in diag_data["evidence"]
    assert diag_data["diagnosis"]["recommended_remediation"] == "start_ollama"
    assert "Ollama daemon process is terminated" in diag_data["diagnosis"]["root_cause"]
    assert diag_data["evidence"]["runtime"]["state"] == "OLLAMA_STOPPED"

    # 4. Heal
    heal_res = client.post("/api/heal", json={"incident_id": incident_id})
    assert heal_res.status_code == 200
    heal_data = heal_res.json()
    incident = heal_data["incident"]
    assert incident["status"] == "RESOLVED"
    assert incident["action_taken"] == "start_ollama"
    assert incident["verification"]["port_open"] is True
    assert incident["verification"]["api_available"] is True
    assert incident["verification"]["runtime_state"] == "OLLAMA_RUNNING"
    assert incident["verification"]["pid"], "verification must name the live daemon PID"
    # Phase 6: the action outcome and its audit trail are first-class and persisted.
    assert incident["action_result"]["success"] is True
    assert incident["runtime_state"] == "OLLAMA_RUNNING"
    assert incident["audit_log"], "healing must record an audit trail"
    entry = incident["audit_log"][0]
    assert entry["incident_id"] == incident_id
    assert entry["action"] == "start_ollama"
    assert entry["allowed"] is True
    assert entry["status"] == "SUCCESS"

    # 5. Check timeline progression
    stages = [event["stage"] for event in incident["timeline"]]
    assert "DETECTED" in stages
    assert "INVESTIGATING" in stages
    assert "ROOT CAUSE FOUND" in stages
    assert "REMEDIATION" in stages
    assert "VERIFYING" in stages
    assert "RESOLVED" in stages

    # 6. Verify demo query now succeeds
    recovery_query = client.post("/api/demo/query", json={"prompt": "Service status check"})
    assert recovery_query.status_code == 200
    assert recovery_query.json()["status"] == "success"
