"""
Structured output schemas for the Bedrock-backed diagnosis agent.

The model's reply is data, not an instruction. Everything here exists to make
that concrete:

* `DiagnosisResult` is the strict schema the agent must satisfy. Unknown fields
  are rejected (`extra="forbid"`), confidence is bounded, `recommended_action`
  must be a bare snake_case identifier so no shell metacharacter can ever ride
  through the model into a command line, and at least one evidence citation is
  required so a diagnosis cannot be asserted from nothing.
* `AgentTelemetry` records what actually happened - which mode, which model, how
  long, how many turns and tool calls, how many tokens. It never contains a
  prompt, a credential or raw evidence.
* `PolicyDecision` is the verdict of the allowlist gate that sits between the
  model and the remediation registry.

Schema validation answers "is this well formed?". Policy validation answers "is
this permitted?". They are deliberately separate layers: a syntactically perfect
`recommended_action` of "run_command" is valid schema and must still be refused.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Evidence citations are handed to the model as E1..En. Normalising case means a
# lower-case reply is accepted rather than rejected on a formatting technicality,
# while anything else is still refused.
EVIDENCE_ID_PATTERN = r"^E[0-9]{1,3}$"

# A bare identifier: letters, digits, underscore. No spaces, no quotes, no
# separators, no shell metacharacters. This is the shape check only - membership
# of the remediation allowlist is enforced separately in agent/policy.py.
ACTION_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"


class DiagnosisResult(BaseModel):
    """The only shape of answer the agent is allowed to give."""

    model_config = ConfigDict(extra="forbid", validate_assignment=False)

    hypothesis: str = Field(min_length=3, max_length=200)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: List[str] = Field(min_length=1, max_length=20)
    contradictory_evidence_ids: List[str] = Field(default_factory=list, max_length=20)
    recommended_action: str = Field(pattern=ACTION_PATTERN)
    investigation_needed: List[str] = Field(default_factory=list, max_length=10)
    explanation: str = Field(min_length=10, max_length=2000)
    requires_human: bool = False

    @field_validator("evidence_ids", "contradictory_evidence_ids", mode="before")
    @classmethod
    def _normalise_ids(cls, value: Any) -> Any:
        if isinstance(value, str):
            value = [value]
        if isinstance(value, list):
            return [v.strip().upper() if isinstance(v, str) else v for v in value]
        return value

    @field_validator("hypothesis", "explanation", mode="before")
    @classmethod
    def _coerce_text(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip()
        return value

    @field_validator("recommended_action", mode="before")
    @classmethod
    def _normalise_action(cls, value: Any) -> Any:
        # Lower-case and strip surrounding whitespace/quotes so a well-meaning
        # reply like `"Start_Ollama"` is normalised rather than rejected. Anything
        # containing a separator or metacharacter still fails the pattern.
        if isinstance(value, str):
            return value.strip().strip("\"'").lower().replace("-", "_").replace(" ", "_")
        return value

    @field_validator("investigation_needed", mode="before")
    @classmethod
    def _coerce_investigation(cls, value: Any) -> Any:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return value


class AgentTelemetry(BaseModel):
    """
    What the agent invocation actually did. Persisted on the Incident.

    Contains no prompt text, no evidence payload and no credentials - only the
    identifiers and counters an operator needs to audit a model-assisted
    diagnosis and to see its cost.
    """

    model_config = ConfigDict(extra="forbid")

    agent_mode: str
    model_id: Optional[str] = None
    aws_region: Optional[str] = None
    agent_latency_ms: Optional[int] = None
    diagnosis_confidence: Optional[float] = None
    # Per-tool invocation counts, e.g. {"check_port": 2, "check_ollama": 1}.
    tool_calls: Dict[str, int] = Field(default_factory=dict)
    tool_call_count: int = 0
    turns: int = 0
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    total_tokens: Optional[int] = None
    bedrock_request_id: Optional[str] = None
    stop_reason: Optional[str] = None
    strands_sdk_version: Optional[str] = None
    # Set only when the Bedrock path failed. Names the real cause.
    error_class: Optional[str] = None
    error_detail: Optional[str] = None
    # Machine-readable failure category from agent.strands_agent.FAILURE_KINDS,
    # plus the raw AWS service code when Bedrock returned one. A dashboard or
    # alarm can branch on `failure_kind` without parsing prose, and the code is
    # what an operator searches for in CloudTrail.
    failure_kind: Optional[str] = None
    aws_error_code: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class PolicyDecision(BaseModel):
    """Verdict of the allowlist gate between the model and the remediation registry."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    requested_action: str
    approved_action: Optional[str] = None
    reason: str
    # Set when the request was refused for a security reason, e.g.
    # "not_in_allowlist", "forbidden_action", "shell_metacharacters",
    # "evidence_not_found", "tool_budget_exceeded".
    violation: Optional[str] = None
    requires_human: bool = False

    def audit_event(self, incident_id: Optional[str] = None) -> Dict[str, Any]:
        """A sanitisation-safe audit record of this decision."""
        return {
            "incident_id": incident_id,
            "layer": "agent_policy",
            "allowed": self.allowed,
            "requested_action": self.requested_action,
            "approved_action": self.approved_action,
            "violation": self.violation,
            "reason": self.reason,
            "requires_human": self.requires_human,
        }
