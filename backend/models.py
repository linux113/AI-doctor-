"""
Pydantic Data Models for AI Doctor Backend.
Structured for 1:1 compatibility with Amazon DynamoDB document records.
"""

from pydantic import BaseModel, Field, model_validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from runner.timeutil import now_iso
from runner.redaction import sanitize_deep
import uuid


# Fields that can carry attacker- or user-supplied content, captured process
# output, HTTP bodies or exception text. These are the paths through which a
# credential could otherwise reach the store, the API and the dashboard.
_SENSITIVE_INCIDENT_FIELDS = (
    "detected_error",
    "root_cause",
    "final_result",
    "error_detail",
    "evidence",
    "verification",
    "retry_result",
    "request_context",
    "action_result",
    "audit_log",
)

_SENSITIVE_TIMELINE_FIELDS = ("description", "details")


class TimelineEvent(BaseModel):
    stage: str  # DETECTED, INVESTIGATING, ROOT CAUSE FOUND, REMEDIATION, VERIFYING, RESOLVED, FAILED
    timestamp: str
    description: str
    details: Optional[Dict[str, Any]] = None
    verified: Optional[bool] = None

    @model_validator(mode="after")
    def _redact_secrets(self) -> "TimelineEvent":
        """
        Timeline entries embed diagnostic output and remediation results, so they
        are sanitised on construction. Redaction is idempotent.
        """
        for name in _SENSITIVE_TIMELINE_FIELDS:
            value = getattr(self, name)
            if value is None:
                continue
            cleaned = sanitize_deep(value)
            if cleaned is not value:
                setattr(self, name, cleaned)
        return self


class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: f"inc-{uuid.uuid4().hex[:8]}")
    created_at: str = Field(default_factory=lambda: now_iso())
    status: str = "DETECTED"  # DETECTED, INVESTIGATING, ROOT CAUSE FOUND, REMEDIATION, VERIFYING, RESOLVED, FAILED
    http_status: int = 500
    detected_error: str
    service: str = "ollama-inference-service"
    root_cause: Optional[str] = None
    # Evidence-derived confidence in root_cause, 0..1. Deliberately low when
    # the infrastructure probes are all healthy and the failure is therefore
    # unexplained.
    confidence: Optional[float] = None
    # Real exception identity behind detected_error, so a timeout is never
    # reported as a refused connection (defect D3).
    error_class: Optional[str] = None
    error_detail: Optional[str] = None
    # Authoritative OllamaRuntime state at detection/heal time: OLLAMA_RUNNING,
    # OLLAMA_STOPPED, OLLAMA_UNHEALTHY, OLLAMA_NOT_INSTALLED, OLLAMA_START_FAILED.
    runtime_state: Optional[str] = None
    # True when no allowlisted remediation can fix the root cause.
    requires_human: Optional[bool] = None
    evidence: Optional[Dict[str, Any]] = None
    action_taken: Optional[str] = None
    # What the allowlisted action itself reported, kept separate from the
    # overall recovery verdict (defect D5).
    action_result: Optional[Dict[str, Any]] = None
    # Allowlist decisions for this incident: timestamp, incident_id, action,
    # allowed/blocked, status, result, error (defect D4).
    audit_log: List[Dict[str, Any]] = Field(default_factory=list)
    verification: Optional[Dict[str, Any]] = None
    retry_result: Optional[Dict[str, Any]] = None
    # "FIX" or "VERIFY" - which stage broke. None unless status is FAILED.
    failed_stage: Optional[str] = None
    final_result: Optional[str] = None
    timeline: List[TimelineEvent] = Field(default_factory=list)
    request_context: Optional[Dict[str, Any]] = None
    resolved_at: Optional[str] = None

    @model_validator(mode="after")
    def _redact_secrets(self) -> "Incident":
        """
        THE authoritative sanitisation boundary (defect D2).

        Every Incident passes through here before it can be saved, serialised to
        an API response, or handed to a future Bedrock/DynamoDB/S3 client, so
        there is exactly one place where redaction happens and no code path can
        forget it. `detected_error`, `request_context` and `evidence` are
        assembled from user input, captured HTTP payloads, process output and
        exception text - all of which can contain bearer tokens, API keys,
        passwords, AWS credentials or private keys.

        Assignment here does not re-trigger validation (validate_assignment is
        off), and `sanitize_deep` is idempotent, so this cannot recurse.
        """
        for name in _SENSITIVE_INCIDENT_FIELDS:
            value = getattr(self, name)
            if value is None or value == [] or value == "":
                continue
            cleaned = sanitize_deep(value)
            if cleaned is not value:
                setattr(self, name, cleaned)
        return self

    def to_dynamodb_item(self) -> Dict[str, Any]:
        """Converts model to a clean dictionary matching DynamoDB attribute format."""
        return self.model_dump()


class DiagnoseRequest(BaseModel):
    incident_id: Optional[str] = None
    error_message: Optional[str] = None


class HealRequest(BaseModel):
    incident_id: str


class DemoQueryRequest(BaseModel):
    # Infrastructure-domain demo prompt. This product is an autonomous
    # troubleshooting/recovery agent for the local Ollama runtime; it is not a
    # medical device, and the demo payload must not imply clinical use.
    # (The unrelated medical-triage prototype lives in ai_doctor/ - see
    # ai_doctor/QUARANTINE.md.)
    prompt: str = "Summarise the latest deployment health report"
    model: str = "llama3:latest"


class SystemStatus(BaseModel):
    application: str  # healthy, degraded, down
    ollama: str  # healthy, down
    backend: str  # healthy
    doctor_runner: str  # active
    port_11434_open: bool
    # Authoritative OllamaRuntime state: healthy / down / not_installed are
    # distinguished, because "not installed" is not an outage.
    runtime_state: Optional[str] = None
    active_incidents_count: int
    timestamp: str
    # Effective security posture: whether the token gate is on, the configured
    # CORS origins, and the remediation allowlist. Reports configuration state
    # only - never a secret value.
    security: Optional[Dict[str, Any]] = None
