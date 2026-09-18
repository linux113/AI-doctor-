"""
Plain data holders for the agent layer.

This module used to declare `BedrockClientInterface` and `StrandsAgentInterface`
- abstractions whose only implementation was a local placeholder. Those were
removed: the real integration lives in `agent/strands_agent.py` and talks to the
actual AWS Strands Agents SDK, so an interface that could be satisfied without
touching AWS was a way to hide that fact rather than a way to extend the system.

What remains here are value objects with no behaviour to fake.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class IncidentContext:
    """Incident metadata handed to the agent. Error text arrives pre-redacted."""

    incident_id: str
    error_message: str
    http_status: Optional[int] = None
    service: str = "unknown"


@dataclass
class DiagnosticReport:
    """Diagnosis summary. `recommended_action` is a suggestion only."""

    detected_root_cause: str
    recommended_action: str
    confidence_score: float
    evidence: Dict[str, Any] = field(default_factory=dict)
    contradictory_evidence: List[str] = field(default_factory=list)
    notes: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "detected_root_cause": self.detected_root_cause,
            "recommended_action": self.recommended_action,
            "confidence_score": self.confidence_score,
            "evidence": self.evidence,
            "contradictory_evidence": self.contradictory_evidence,
            "notes": self.notes,
        }
