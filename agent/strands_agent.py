"""
AWS Strands Agent implementation placeholder.
Provides local deterministic reasoning for the MVP while preserving the exact contract
for AWS Strands Agents in Phase 2.
"""

from typing import List, Dict, Any, Optional
from .interfaces import StrandsAgentInterface, IncidentContext, DiagnosticReport


class StrandsAgentPlaceholder(StrandsAgentInterface):
    """
    Local implementation of the Strands Agent interface.
    Executes rule-based deterministic diagnostics for local reliability.
    Phase 2 will replace the inner reasoning with the AWS Strands Agent Runtime.
    """

    def __init__(self, agent_id: Optional[str] = None):
        self.agent_id = agent_id or "local-doctor-agent-v1"

    def plan_investigation(self, context: IncidentContext) -> List[str]:
        """
        Returns the ordered list of diagnostic tools needed to investigate this incident.
        """
        # If failure mentions Ollama, port, or connection refused, prioritize those diagnostics
        return ["get_recent_logs", "check_port", "check_process", "check_ollama"]

    def evaluate_root_cause(self, context: IncidentContext, evidence: Dict[str, Any]) -> DiagnosticReport:
        """
        Evaluates collected evidence against the incident symptoms.

        Delegates to runner.diagnosis, the single source of truth for the
        decision table. This class previously carried its own private copy of
        that table; the two had already diverged (different branch order,
        different wording, different confidence values), so a fix applied to
        one silently did not apply to the other.

        Phase 2: this is the seam to replace. Swap the deterministic engine for
        an Amazon Bedrock call that receives the same evidence bundle and must
        return the same DiagnosticReport shape - and keep the deterministic
        path as the fallback for when the model is unreachable or returns an
        action outside the allowlist.
        """
        # Imported lazily so the agent package stays importable without the
        # local runner's native dependencies (psutil). runner.diagnosis itself
        # is dependency-free; it is runner/__init__ that pulls them in.
        from runner.diagnosis import diagnose

        d = diagnose(evidence, context.error_message)
        return DiagnosticReport(
            incident_id=context.incident_id,
            evidence=evidence,
            detected_root_cause=d.root_cause,
            confidence_score=d.confidence,
            recommended_action=d.recommended_remediation,
            hypothesis=d.hypothesis,
            corroborating_probes=d.corroborating_probes,
            contradicting_probes=d.contradicting_probes,
            evidence_consistent=d.evidence_consistent,
            notes=d.notes,
        )

    def select_remediation(self, report: DiagnosticReport, allowlist: List[str]) -> str:
        """
        Selects an allowlisted action. If recommended action is not in allowlist, falls back to safe retry.
        """
        if report.recommended_action in allowlist:
            return report.recommended_action
        return "retry_request"
