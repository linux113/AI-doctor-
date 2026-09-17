"""
Agent layer: real AWS Strands Agents + Amazon Bedrock, with an explicit
deterministic mode beside it.

Two honest modes, selected by `AI_DOCTOR_AGENT_MODE` and never mixed silently:

  bedrock        a real model invocation through the Strands SDK against
                 Amazon Bedrock, returning a schema-validated DiagnosisResult
                 that the policy layer gates before any action is taken.
  deterministic  the offline rule engine in `runner/diagnosis.py`.

If Bedrock is unavailable in bedrock mode the incident records that failure. It
does not substitute a deterministic result and label it as an agent diagnosis.
"""

from .config import (
    MODE_BEDROCK,
    MODE_DETERMINISTIC,
    AgentConfig,
    AgentConfigurationError,
    boto3_version,
    load_agent_config,
    strands_sdk_version,
)
from .evidence import (
    EvidenceCatalog,
    build_evidence_catalog,
    build_incident_summary,
    describe_catalog_for_telemetry,
)
from .interfaces import DiagnosticReport, IncidentContext
from .policy import (
    MODEL_PERMITTED_ACTIONS,
    PolicyDecision,
    permitted_actions_for_prompt,
    summarise_for_incident,
    validate_diagnosis,
)
from .prompts import EVIDENCE_FENCE, SYSTEM_PROMPT, build_user_prompt
from .schemas import AgentTelemetry, DiagnosisResult
from .strands_agent import (
    STATUS_DIAGNOSED,
    STATUS_FAILED,
    STATUS_REQUIRES_HUMAN,
    AgentDiagnosis,
    BedrockDiagnosisAgent,
    BedrockUnavailableError,
)
from .tools import ALLOWED_TOOL_NAMES, ToolBudget, ToolBudgetExceeded, build_diagnostic_tools, summarise_tool_use

__all__ = [
    "ALLOWED_TOOL_NAMES",
    "AgentConfig",
    "AgentConfigurationError",
    "AgentDiagnosis",
    "AgentTelemetry",
    "BedrockDiagnosisAgent",
    "BedrockUnavailableError",
    "DiagnosisResult",
    "DiagnosticReport",
    "EVIDENCE_FENCE",
    "EvidenceCatalog",
    "IncidentContext",
    "MODE_BEDROCK",
    "MODE_DETERMINISTIC",
    "MODEL_PERMITTED_ACTIONS",
    "PolicyDecision",
    "STATUS_DIAGNOSED",
    "STATUS_FAILED",
    "STATUS_REQUIRES_HUMAN",
    "SYSTEM_PROMPT",
    "ToolBudget",
    "ToolBudgetExceeded",
    "boto3_version",
    "build_diagnostic_tools",
    "build_evidence_catalog",
    "build_incident_summary",
    "build_user_prompt",
    "describe_catalog_for_telemetry",
    "load_agent_config",
    "permitted_actions_for_prompt",
    "strands_sdk_version",
    "summarise_for_incident",
    "summarise_tool_use",
    "validate_diagnosis",
]
