"""
FastAPI Backend Application for AI Doctor.
Exposes REST APIs for system status, incident tracking, diagnosis, and autonomous healing.
Includes the demo application endpoint with intentional failure generation.
"""

import os
import json
import secrets
import socket
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
    DeveloperErrorRequest,
    DemoQueryRequest,
    SystemStatus,
)
from .storage import incident_repo
from runner.timeutil import now_iso
from runner.diagnostics import (
    check_ollama,
    check_ollama_runtime,
    check_port,
    check_process,
    get_recent_logs,
    health_check,
    record_log,
)
from runner.ollama_runtime import OLLAMA_NOT_INSTALLED
from runner.redaction import sanitize_deep
from runner.doctor_runner import doctor_runner
from runner.remediation import start_ollama, stop_ollama
from runner.remediation_registry import REMEDIATION_ALLOWLIST
# Reports which diagnosis engine is configured. Imported at module scope because
# /api/system-status is polled; the module itself defers every AWS import, so
# loading it costs nothing when the SDK is absent.
from agent.diagnosis_agent import describe_agent

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

    runtime_state = ollama_res.get("runtime_state")
    if port_res["is_open"] and ollama_res["is_available"]:
        ollama_status = "healthy"
    elif runtime_state == OLLAMA_NOT_INSTALLED:
        # "down" would imply the daemon died and could be restarted. It is absent.
        ollama_status = "not_installed"
    else:
        ollama_status = "down"

    # Application status depends on its runtime dependency (Ollama)
    app_status = "healthy" if ollama_status == "healthy" else "degraded"

    active_incidents = [
        i for i in incident_repo.list_all()
        if i.status in ("DETECTED", "INVESTIGATING", "ROOT CAUSE FOUND", "REMEDIATION", "VERIFYING")
    ]

    return SystemStatus(
        application=app_status,
        ollama=ollama_status,
        runtime_state=runtime_state,
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
        # Which diagnosis engine is actually running. `llm_operational` is false
        # unless bedrock mode is configured, the SDK is installed and a
        # credential source exists, so the dashboard cannot claim an AI
        # diagnosis the backend is not able to perform.
        agent=describe_agent(),
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
    # Same engine-selection seam as the heal loop, so the two endpoints can
    # never disagree about who diagnosed the incident.
    diagnosis = doctor_runner.diagnose_incident(
        (incident.model_dump() if incident else {"detected_error": initial_error}),
        evidence,
        initial_error,
        incident_id=incident.incident_id if incident else None,
    )

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
        incident.runtime_state = diagnosis.get("runtime_state") or (evidence.get("runtime") or {}).get("state")
        incident.requires_human = bool(diagnosis.get("requires_human"))
        incident.root_cause = diagnosis["root_cause"]
        incident.confidence = diagnosis.get("confidence")
        _apply_agent_record(incident, diagnosis)
        incident_repo.save(incident)

    return {
        "status": "success",
        "evidence": evidence,
        "diagnosis": diagnosis,
        "incident_id": incident.incident_id if incident else None,
    }


def _apply_agent_record(incident: Incident, source: Dict[str, Any]) -> None:
    """
    Copies the agent-layer record onto an Incident.

    Single place that knows the field names, so the diagnose and heal paths
    cannot persist different subsets of it.
    """
    telemetry = source.get("agent_telemetry") or {}
    incident.agent_mode = source.get("agent_mode") or telemetry.get("agent_mode")
    incident.agent_status = source.get("agent_status")
    incident.diagnosis_outcome = source.get("diagnosis_outcome")
    # Absent from an older record means unknown, and unknown must not be shown as
    # true - so these default to False rather than None.
    incident.bedrock_invoked = bool(source.get("bedrock_invoked"))
    incident.used_llm = bool(source.get("used_llm"))
    incident.agent_note = source.get("agent_note")
    incident.model_id = telemetry.get("model_id")
    incident.aws_region = telemetry.get("aws_region")
    incident.agent_latency_ms = telemetry.get("agent_latency_ms")
    incident.diagnosis_confidence = telemetry.get("diagnosis_confidence")
    incident.agent_telemetry = telemetry or None
    incident.policy_decision = source.get("policy_decision")
    incident.bedrock_failure = source.get("bedrock_failure")


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
    # First-class outcome of the allowlisted action, distinct from the overall
    # recovery verdict (defect D5), and the incident-scoped allowlist audit
    # trail (defect D4). Both are persisted, not just returned to the caller.
    incident.action_result = outcome.get("action_result")
    incident.audit_log = outcome.get("audit_log") or []
    incident.runtime_state = outcome.get("runtime_state")
    incident.requires_human = outcome.get("requires_human")
    # Which engine diagnosed this incident, how long it took, what it cost, and
    # - if Bedrock was requested but unavailable - the real reason. Persisted
    # rather than only returned, so the record survives the request.
    _apply_agent_record(incident, outcome)
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

# Upstream call budget for the demo inference request.
OLLAMA_REQUEST_TIMEOUT = 30.0


def _classify_upstream_error(exc: BaseException, url: str, timeout: float) -> tuple:
    """
    Maps the REAL exception from the upstream Ollama call onto
    (error_class, error_detail).

    Defect D3: `demo_query` used to catch the exception, throw it away, and
    store a single hardcoded string - "ConnectionRefusedError: ... (Connection
    refused)" - for every possible failure. A timeout, a DNS failure, an HTTP
    500 from Ollama and a reset connection were all reported identically, so
    the incident record actively misled whoever read it.

    The classification is structural: it reads the exception type and, for
    HTTPError, the status code. Nothing is inferred from message text, and the
    detail is redacted before it is persisted or returned.
    """
    if isinstance(exc, SensitivePromptError):
        return "SensitivePromptError", str(exc)

    # urllib wraps the underlying cause in URLError.reason. Unwrap it so the
    # class reported is the one that actually occurred, not the wrapper.
    if isinstance(exc, urllib.error.HTTPError):
        return "HTTPError", f"Ollama at {url} returned HTTP {exc.code} ({exc.reason})."

    if isinstance(exc, urllib.error.URLError):
        reason = exc.reason
        if isinstance(reason, BaseException):
            return _classify_upstream_error(reason, url, timeout)
        return "URLError", f"Ollama at {url} could not be reached: {reason}."

    if isinstance(exc, ConnectionRefusedError):
        return (
            "ConnectionRefusedError",
            f"Connection refused by {url}: nothing accepted a TCP connection on that port.",
        )

    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "TimeoutError", f"Ollama at {url} did not respond within {timeout}s."

    if isinstance(exc, ConnectionResetError):
        return "ConnectionResetError", f"Connection to {url} was reset by the peer mid-request."

    if isinstance(exc, OSError):
        errno_value = getattr(exc, "errno", None)
        strerror = getattr(exc, "strerror", None) or str(exc) or exc.__class__.__name__
        suffix = f" (errno {errno_value})" if errno_value is not None else ""
        return exc.__class__.__name__, f"OS-level failure contacting {url}: {strerror}{suffix}"

    return exc.__class__.__name__, str(exc) or "No detail available."


class SensitivePromptError(Exception):
    """Raised when credential material is detected in a demo prompt."""


@app.post("/api/demo/query")
def demo_query(payload: DemoQueryRequest):
    """
    Small demo application endpoint that depends on Ollama on port 11434.
    If Ollama is available -> returns HTTP 200 with model response.
    If Ollama is stopped -> produces a realistic HTTP 500 failure and records an incident!
    """
    ollama_url = "http://127.0.0.1:11434/api/generate"
    safe_log_prompt = sanitize_deep(payload.prompt[:30])
    record_log("INFO", f"Demo application received request: '{safe_log_prompt}'", service="demo_app")

    try:
        safe_prompt = sanitize_deep(payload.prompt)
        if safe_prompt != payload.prompt:
            raise SensitivePromptError("Sensitive credential material detected in prompt.")

        # Use the requested model when it is installed. If the demo's default
        # model is not installed, use an actually installed Ollama model instead.
        # This does not fake recovery: the real Ollama API must still answer.
        selected_model = payload.model
        tags_req = urllib.request.Request(
            "http://127.0.0.1:11434/api/tags",
            method="GET",
        )
        with urllib.request.urlopen(tags_req, timeout=OLLAMA_REQUEST_TIMEOUT) as tags_resp:
            tags_data = json.loads(tags_resp.read().decode("utf-8"))
        installed_models = [
            item.get("name")
            for item in (tags_data.get("models") or [])
            if isinstance(item, dict) and item.get("name")
        ]
        if installed_models and selected_model not in installed_models:
            selected_model = installed_models[0]

        req_data = json.dumps({
            "prompt": payload.prompt,
            "model": selected_model,
            "stream": False,
        }).encode("utf-8")
        req = urllib.request.Request(
            ollama_url,
            data=req_data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=OLLAMA_REQUEST_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            record_log("INFO", "Demo application query to Ollama succeeded.", service="demo_app")
            return {
                "status": "success",
                "app": "demo-inference-service",
                "model": selected_model,
                "response": data.get("response", "Success"),
            }
    except Exception as e:  # noqa: BLE001 - the real exception is preserved, not flattened
        # Defect D3: classify what actually happened. Previously every failure
        # was reported as a hardcoded "ConnectionRefusedError ... (Connection
        # refused)" string and the caught exception was discarded.
        error_class, error_detail = _classify_upstream_error(e, ollama_url, OLLAMA_REQUEST_TIMEOUT)

        # Authoritative runtime state, so "Ollama is not installed" is never
        # presented as "Ollama is down" (both look identical on a socket probe).
        runtime = check_ollama_runtime()
        runtime_state = runtime.get("state")
        if runtime_state == OLLAMA_NOT_INSTALLED and error_class in (
            "ConnectionRefusedError",
            "URLError",
            "OSError",
        ):
            error_detail = (
                f"{error_detail} The Ollama runtime is NOT INSTALLED on this machine "
                "(no executable was found on PATH or in any standard location), so nothing "
                "can be listening on port 11434. This is an absent runtime, not an outage."
            )

        # Redact before the text is logged, stored or returned: exception detail
        # can embed a URL carrying credentials.
        error_detail = sanitize_deep(error_detail)
        error_msg = sanitize_deep(f"{error_class}: {error_detail}")

        record_log("ERROR", f"CRITICAL APPLICATION FAILURE: {error_msg}", service="demo_app")

        # Automatically detect and register the incident!
        now_ts = now_iso()
        incident = Incident(
            status="DETECTED",
            http_status=500,
            detected_error=error_msg,
            # Real exception identity, kept separate from the human-readable text.
            error_class=error_class,
            error_detail=error_detail,
            runtime_state=runtime_state,
            requires_human=(runtime_state == OLLAMA_NOT_INSTALLED),
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
                    details={
                        "error_class": error_class,
                        "runtime_state": runtime_state,
                        "ollama_installed": runtime.get("installed"),
                    },
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
                "error_class": error_class,
                "error_detail": error_detail,
                "runtime_state": runtime_state,
                "requires_human": bool(runtime_state == OLLAMA_NOT_INSTALLED),
                "incident_id": incident.incident_id,
                "incident_status": "DETECTED",
                "message": "AI Doctor has detected this application incident and logged it for investigation.",
            },
        )



@app.post("/api/integrations/report-error", response_model=Incident)
def report_developer_error(payload: DeveloperErrorRequest):
    """
    Receives a structured application error from a connected developer app
    and registers it as an AI Doctor incident.
    """
    now_ts = now_iso()

    error_text = sanitize_deep(
        payload.message or payload.error
    )

    logs = sanitize_deep(payload.logs) if payload.logs else None

    incident = Incident(
        status="DETECTED",
        http_status=500,
        detected_error=sanitize_deep(payload.error),
        error_class="DeveloperReportedError",
        error_detail=error_text,
        service=sanitize_deep(payload.application),
        requires_human=False,
        request_context={
            "url": sanitize_deep(payload.url) if payload.url else None,
            "method": sanitize_deep(payload.method) if payload.method else None,
            "environment": sanitize_deep(payload.environment),
        },
        evidence={
            "source": "developer_integration",
            "application": sanitize_deep(payload.application),
            "environment": sanitize_deep(payload.environment),
            "logs": logs,
        },
        timeline=[
            TimelineEvent(
                stage="DETECTED",
                timestamp=now_ts,
                description=f"Developer application reported an error: {error_text}",
                details={
                    "application": sanitize_deep(payload.application),
                    "environment": sanitize_deep(payload.environment),
                    "error": sanitize_deep(payload.error),
                },
            )
        ],
    )

    incident_repo.save(incident)
    return incident
@app.post("/api/demo/stop-ollama", dependencies=SENSITIVE_ROUTE_GUARD)
def trigger_intentional_failure():
    """
    Intentional failure trigger: stops the Ollama service to simulate an outage.
    """
    res = stop_ollama()
    stopped = bool(res.get("success"))
    return {
        "status": "outage_simulated" if stopped else "no_runtime_stopped",
        "success": stopped,
        "state": res.get("state"),
        "message": (
            "Ollama was terminated and port 11434 is closed."
            if stopped
            else res.get("detail") or "No Ollama process was found to stop."
        ),
        "details": res,
    }


@app.post("/api/demo/start-ollama", dependencies=SENSITIVE_ROUTE_GUARD)
def trigger_start_ollama():
    """
    Manually starts the real Ollama daemon.

    Defect D1 at the API layer: this used to answer {"status": "started"}
    unconditionally, so a failed start - or one where the spawned process died
    immediately - was reported to the operator and the dashboard as a success.
    The HTTP status now follows the action's own verdict.
    """
    res = start_ollama()
    succeeded = bool(res.get("success"))
    body = {
        "status": "started" if succeeded else "failed",
        "success": succeeded,
        "state": res.get("state"),
        "message": (
            "Ollama is running and its API answered."
            if succeeded
            else res.get("detail") or "Ollama did not reach the RUNNING state."
        ),
        "details": res,
    }
    if not succeeded:
        record_log("ERROR", f"start-ollama did not recover the runtime: {res.get('detail')}", service="backend")
    return JSONResponse(
        status_code=status.HTTP_200_OK if succeeded else status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=body,
    )


@app.post("/api/demo/simulate-incident", dependencies=SENSITIVE_ROUTE_GUARD)
def simulate_incident_workflow():
    """
    Convenience endpoint for live demo / testing:
    1. Stops Ollama (creates outage)
    2. Sends a request to trigger an authentic HTTP 500 incident
    3. Returns the detected incident object ready to be healed
    """
    stop_ollama()
    return demo_query(DemoQueryRequest(prompt="Urgent deployment rollback assessment"))
