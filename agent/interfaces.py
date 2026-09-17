"""
Agent Interfaces & Protocols for AI Doctor.
Defines clean contracts for the future AWS Strands Agents + Amazon Bedrock integration.
DO NOT fake AWS integration: clean dataclasses and interfaces ready for AWS Phase 2.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class IncidentContext:
    incident_id: str
    error_message: str
    http_status: int
    service: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    request_url: Optional[str] = None
    request_payload: Optional[Dict[str, Any]] = None


@dataclass
class DiagnosticReport:
    incident_id: str
    evidence: Dict[str, Any]
    detected_root_cause: str
    confidence_score: float
    recommended_action: str
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


class BedrockClientInterface(ABC):
    """
    Interface for Amazon Bedrock foundation model invocations (Claude 3.5 Sonnet / Llama 3).
    To be wired in Phase 2 via boto3.client('bedrock-runtime').
    """

    @abstractmethod
    def invoke_model(
        self,
        prompt: str,
        model_id: str = "anthropic.claude-3-5-sonnet-20241022-v2:0",
        system_prompt: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.1,
    ) -> Dict[str, Any]:
        """Invoke an Amazon Bedrock foundation model with structured inputs."""
        pass


class StrandsAgentInterface(ABC):
    """
    Interface for AWS Strands Agents orchestration framework.
    To be wired in Phase 2 with AWS Agent Runtime and action groups.
    """

    @abstractmethod
    def plan_investigation(self, context: IncidentContext) -> List[str]:
        """Plans the sequence of safe diagnostic tools to execute."""
        pass

    @abstractmethod
    def evaluate_root_cause(self, context: IncidentContext, evidence: Dict[str, Any]) -> DiagnosticReport:
        """Evaluates collected evidence against the incident symptoms to determine root cause."""
        pass

    @abstractmethod
    def select_remediation(self, report: DiagnosticReport, allowlist: List[str]) -> str:
        """Selects an approved remediation action strictly adhering to the allowlist."""
        pass
