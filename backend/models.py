"""
Pydantic Data Models for AI Doctor Backend.
Structured for 1:1 compatibility with Amazon DynamoDB document records.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid


class TimelineEvent(BaseModel):
    stage: str  # DETECTED, INVESTIGATING, ROOT CAUSE FOUND, REMEDIATION, VERIFYING, RESOLVED, FAILED
    timestamp: str
    description: str
    details: Optional[Dict[str, Any]] = None
    verified: Optional[bool] = None


class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: f"inc-{uuid.uuid4().hex[:8]}")
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    status: str = "DETECTED"  # DETECTED, INVESTIGATING, ROOT CAUSE FOUND, REMEDIATION, VERIFYING, RESOLVED, FAILED
    http_status: int = 500
    detected_error: str
    service: str = "ollama-inference-service"
    root_cause: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    action_taken: Optional[str] = None
    verification: Optional[Dict[str, Any]] = None
    final_result: Optional[str] = None
    timeline: List[TimelineEvent] = Field(default_factory=list)
    request_context: Optional[Dict[str, Any]] = None
    resolved_at: Optional[str] = None

    def to_dynamodb_item(self) -> Dict[str, Any]:
        """Converts model to a clean dictionary matching DynamoDB attribute format."""
        return self.model_dump()


class DiagnoseRequest(BaseModel):
    incident_id: Optional[str] = None
    error_message: Optional[str] = None


class HealRequest(BaseModel):
    incident_id: str


class DemoQueryRequest(BaseModel):
    prompt: str = "Analyze patient triage vital signs"
    model: str = "llama3:latest"


class SystemStatus(BaseModel):
    application: str  # healthy, degraded, down
    ollama: str  # healthy, down
    backend: str  # healthy
    doctor_runner: str  # active
    port_11434_open: bool
    active_incidents_count: int
    timestamp: str
