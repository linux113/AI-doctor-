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


def test_system_status_endpoint():
    start_ollama()
    res = client.get("/api/system-status")
    assert res.status_code == 200
    data = res.json()
    assert data["ollama"] in ("healthy", "down")
    assert data["backend"] == "healthy"
    assert data["doctor_runner"] == "active"


def test_full_autonomous_healing_lifecycle():
    """
    Validates the end-to-end autonomous healing cycle:
    1. Stop Ollama -> failure injected
    2. Demo query fails with 500 -> incident detected & recorded
    3. Call /api/diagnose -> system evidence collected, root cause deduced
    4. Call /api/heal -> remediation executed, verified, original request retried
    5. Incident timeline reflects full progression to RESOLVED
    """
    # 1. Simulate failure
    stop_res = client.post("/api/demo/stop-ollama")
    assert stop_res.status_code == 200

    # 2. Query fails with 500
    query_res = client.post("/api/demo/query", json={"prompt": "Diagnose arrhythmia"})
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

    # 4. Heal
    heal_res = client.post("/api/heal", json={"incident_id": incident_id})
    assert heal_res.status_code == 200
    heal_data = heal_res.json()
    incident = heal_data["incident"]
    assert incident["status"] == "RESOLVED"
    assert incident["action_taken"] == "start_ollama"
    assert incident["verification"]["port_open"] is True
    assert incident["verification"]["api_available"] is True

    # 5. Check timeline progression
    stages = [event["stage"] for event in incident["timeline"]]
    assert "DETECTED" in stages
    assert "INVESTIGATING" in stages
    assert "ROOT CAUSE FOUND" in stages
    assert "REMEDIATION" in stages
    assert "VERIFYING" in stages
    assert "RESOLVED" in stages

    # 6. Verify demo query now succeeds
    recovery_query = client.post("/api/demo/query", json={"prompt": "Patient status check"})
    assert recovery_query.status_code == 200
    assert recovery_query.json()["status"] == "success"
