"""
FastAPI Backend Application for AI Doctor.
Exposes REST APIs for system status, incident tracking, diagnosis, and autonomous healing.
Includes the demo application endpoint with intentional failure generation.
"""

import os
import json
import secrets
import urllib.request
import urllib.error
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Header, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .models import (
    Incident,
    TimelineEvent,
    DiagnoseRequest,
    HealRequest,
    DemoQueryRequest,
    SystemStatus,
)
from .storage import incident_repo
from runner.timeutil import now_iso
from runner.diagnostics import (
    check_ollama,
    check_port,
    check_process,
    get_recent_logs,
    health_check,
    record_log,
)
from runner.doctor_runner import doctor_runner
from runner.remediation import start_ollama, stop_ollama
from runner.remediation_registry import REMEDIATION_ALLOWLIST

app = FastAPI(
    title="AI Doctor — Autonomous Troubleshooting & Recovery Agent",
    version="1.0.0",
    description="Backend API for incident detection, evidence collection, and automated healing.",
)

# ---------------------------------------------------------------------------
# CORS
#
# A wildcard origin combined with allow_credentials=True is not a valid CORS
# configuration - browsers reject the response - and it is the wrong default
# for an API that can spawn and signal OS processes. The dashboard reaches this
# backend through Next.js rewrites (same-origin from the browser's point of
# view), so it does not need permissive CORS at all.
#
# Credentials are therefore enabled only when the operator has named explicit
# origins. Override with a comma-separated AIDOCTOR_CORS_ORIGINS.
# ---------------------------------------------------------------------------
CORS_ORIGINS = [
    o.strip()
    for o in os.environ.get("AIDOCTOR_CORS_ORIGINS", "*").split(",")
    if o.strip()
]
CORS_ALLOW_CREDENTIALS = "*" not in CORS_ORIGINS

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=CORS_ALLOW_CREDENTIALS,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Optional token gate for state-changing / process-controlling endpoints.
#
# /api/heal, /api/demo/stop-ollama, /api/demo/start-ollama and
# /api/demo/simulate-incident all spawn or signal OS processes and were
# previously wide open. The gate is DISABLED unless AIDOCTOR_API_TOKEN is set,
# so local development and the test suite behave exactly as before, while any
# real deployment can set the variable and get an enforced boundary.
#
# frontend/next.config.js injects the same token server-side into the proxy
# rewrite, so the browser never holds it.
# ---------------------------------------------------------------------------
API_TOKEN = os.environ.get("AIDOCTOR_API_TOKEN", "").strip()
TOKEN_GATE_ENABLED = bool(API_TOKEN)


def require_api_token(authorization: Optional[str] = Header(default=None)) -> None:
    """
    FastAPI dependency enforcing a bearer token on sensitive endpoints.

    No-op when AIDOCTOR_API_TOKEN is unset. Uses a constant-time comparison so
    the token cannot be recovered one character at a time.
    """
    if not TOKEN_GATE_ENABLED:
        return

    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header. This endpoint controls OS processes.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not secrets.compare_digest(authorization.strip(), f"Bearer {API_TOKEN}"):
        record_log(
            "SECURITY",
            "Rejected a sensitive endpoint call carrying an invalid bearer token.",
            service="backend",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid bearer token.",
        )


# Applied via dependencies=[...] on each state-changing route.
SENSITIVE_ROUTE_GUARD = [Depends(require_api_token)]


@app.get("/health")
def health_endpoint():
    """Basic health check endpoint."""
    overall = health_check()
    return {
        "status": "healthy",
        "service": "ai-doctor-backend",
        "doctor_runner": "active",
        "system": overall,
        "timestamp": now_iso(),
    }


@app.get("/api/system-status", response_model=SystemStatus)
def get_system_status():
    """
    Returns real-time health across all system components:
    Application, Ollama, Backend, Doctor Runner, and Port 11434.
    """
    port_res = check_port(11434)
    proc_res = check_process("ollama")
    ollama_res = check_ollama()

    ollama_status = "healthy" if (port_res["is_open"] and ollama_res["is_available"]) else "down"

    # Application status depends on its runtime dependency (Ollama)
    app_status = "healthy" if ollama_status == "healthy" else "degraded"

    active_incidents = [
        i for i in incident_repo.list_all()
        if i.status in ("DETECTED", "INVESTIGATING", "ROOT CAUSE FOUND", "REMEDIATION", "VERIFYING")
    ]

    return SystemStatus(
        application=app_status,
        ollama=ollama_status,
        backend="healthy",
        doctor_runner="active",
        port_11434_open=port_res["is_open"],
        active_incidents_count=len(active_incidents),
        timestamp=now_iso(),
        security={
            # Reported, never the value itself.
            "token_gate_enabled": TOKEN_GATE_ENABLED,
            "cors_origins": CORS_ORIGINS,
            "cors_allow_credentials": CORS_ALLOW_CREDENTIALS,
            "remediation_allowlist": sorted(REMEDIATION_ALLOWLIST),
        },
    )


@app.get("/api/incidents", response_model=List[Incident])
def list_incidents(limit: int = 50, status: Optional[str] = None):
    """Lists incidents with newest first."""
    return incident_repo.list_all(limit=limit, status=status)


@app.get("/api/incidents/latest", response_model=Optional[Incident])
def get_latest_incident():
    """Returns the most recent incident or null."""
    return incident_repo.get_latest()


@app.get("/api/incidents/{incident_id}", response_model=Incident)
def get_incident(incident_id: str):
    """Fetches details and evidence of a specific incident."""
    inc = incident_repo.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    return inc


@app.post("/api/diagnose")
def run_diagnosis(payload: DiagnoseRequest):
    """
    Collects real system evidence and identifies the root cause for an incident.
    """
    incident = None
    if payload.incident_id:
        incident = incident_repo.get(payload.incident_id)

    initial_error = payload.error_message or (incident.detected_error if incident else "Service failure")

    record_log("INFO", f"AI Doctor starting diagnostic investigation: {initial_error}", service="backend")

    evidence = doctor_runner.collect_evidence()
    diagnosis = doctor_runner.diagnose_root_cause(evidence, initial_error)

    if incident:
        # Update incident timeline with diagnosis
        now_ts = now_iso()
        incident.timeline.append(TimelineEvent(
            stage="INVESTIGATING",
            timestamp=now_ts,
            description="Diagnostic tools executed. Real system evidence collected.",
        ))
        incident.timeline.append(TimelineEvent(
            stage="ROOT CAUSE FOUND",
            timestamp=now_ts,
            description=diagnosis["root_cause"],
            details=diagnosis,
        ))
        incident.status = "ROOT CAUSE FOUND"
        incident.evidence = evidence
        incident.root_cause = diagnosis["root_cause"]
        incident.confidence = diagnosis.get("confidence")
        incident_repo.save(incident)

    return {
        "status": "success",
        "evidence": evidence,
        "diagnosis": diagnosis,
        "incident_id": incident.incident_id if incident else None,
    }


@app.post("/api/heal", dependencies=SENSITIVE_ROUTE_GUARD)
def run_heal(payload: HealRequest):
    """
    Executes the full autonomous recovery loop:
    DETECT -> DIAGNOSE -> FIX -> VERIFY -> RETRY
    """
    incident = incident_repo.get(payload.incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{payload.incident_id}' not found.")

    record_log("INFO", f"AI Doctor starting autonomous heal for incident {incident.incident_id}", service="backend")

    # Pass full incident model dict to doctor runner
    incident_dict = incident.model_dump()
    outcome = doctor_runner.heal_incident(incident_dict)

    # Persist updated incident state and timeline
    incident.status = outcome["status"]
    incident.root_cause = outcome.get("root_cause")
    incident.confidence = outcome.get("confidence")
    incident.evidence = outcome.get("evidence")
    incident.action_taken = outcome.get("action_taken")
    incident.verification = outcome.get("verification")
    incident.retry_result = outcome.get("retry_result")
    # Which stage broke, so a failed FIX is not misreported as a failed VERIFY.
    incident.failed_stage = outcome.get("failed_stage")
    incident.final_result = "Recovery Succeeded" if outcome["status"] == "RESOLVED" else "Recovery Failed"
    incident.resolved_at = outcome.get("resolved_at")

    # Map timeline events
    incident.timeline = [
        TimelineEvent(
            stage=t["stage"],
            timestamp=t["timestamp"],
            description=t["description"],
            details=t.get("details"),
            verified=t.get("verified"),
        )
        for t in outcome.get("timeline", [])
    ]

    incident_repo.save(incident)

    return {
        "incident": incident,
        "outcome": outcome,
    }


# =========================================================================
# Demo Application Endpoints with Intentional Failure Mechanism
# =========================================================================


@app.post("/api/demo/query")
def demo_query(payload: DemoQueryRequest):
    """
    Small demo application endpoint that depends on Ollama on port 11434.
    If Ollama is available -> returns HTTP 200 with model response.
    If Ollama is stopped -> produces a realistic HTTP 500 failure and records an incident!
    """
    ollama_url = "http://127.0.0.1:11434/api/generate"
    record_log("INFO", f"Demo application received request: '{payload.prompt[:30]}'", service="demo_app")

    try:
        req_data = json.dumps({"prompt": payload.prompt, "model": payload.model}).encode("utf-8")
        req = urllib.request.Request(
            ollama_url,
            data=req_data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            record_log("INFO", "Demo application query to Ollama succeeded.", service="demo_app")
            return {
                "status": "success",
                "app": "demo-inference-service",
                "model": payload.model,
                "response": data.get("response", "Success"),
            }
    except (urllib.error.URLError, ConnectionRefusedError, OSError) as e:
        error_msg = f"ConnectionRefusedError: Failed to connect to Ollama service at {ollama_url} (Connection refused). Is Ollama running on port 11434?"
        record_log("ERROR", f"CRITICAL APPLICATION FAILURE: {error_msg}", service="demo_app")

        # Automatically detect and register the incident!
        now_ts = now_iso()
        incident = Incident(
            status="DETECTED",
            http_status=500,
            detected_error=error_msg,
            service="demo-inference-service",
            request_context={
                "url": "http://127.0.0.1:8000/api/demo/query",
                "method": "POST",
                "payload": payload.model_dump(),
            },
            timeline=[
                TimelineEvent(
                    stage="DETECTED",
                    timestamp=now_ts,
                    description=f"HTTP 500 error intercepted: {error_msg}",
                )
            ],
        )
        incident_repo.save(incident)

        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "error",
                "http_status": 500,
                "error": error_msg,
                "incident_id": incident.incident_id,
                "incident_status": "DETECTED",
                "message": "AI Doctor has detected this application incident and logged it for investigation.",
            },
        )


@app.post("/api/demo/stop-ollama", dependencies=SENSITIVE_ROUTE_GUARD)
def trigger_intentional_failure():
    """
    Intentional failure trigger: stops the Ollama service to simulate an outage.
    """
    res = stop_ollama()
    return {
        "status": "outage_simulated",
        "message": "Ollama service was terminated. Port 11434 is now closed.",
        "details": res,
    }


@app.post("/api/demo/start-ollama", dependencies=SENSITIVE_ROUTE_GUARD)
def trigger_start_ollama():
    """Manually starts the Ollama service."""
    res = start_ollama()
    return {"status": "started", "details": res}


@app.post("/api/demo/simulate-incident", dependencies=SENSITIVE_ROUTE_GUARD)
def simulate_incident_workflow():
    """
    Convenience endpoint for live demo / testing:
    1. Stops Ollama (creates outage)
    2. Sends a request to trigger an authentic HTTP 500 incident
    3. Returns the detected incident object ready to be healed
    """
    stop_ollama()
    return demo_query(DemoQueryRequest(prompt="Urgent patient clinical triage assessment"))
