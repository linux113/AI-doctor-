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
        Deterministic evidence evaluation matching the local Ollama failure scenario.
        Phase 2: Passes evidence to Amazon Bedrock for generative root cause synthesis.
        """
        port_open = evidence.get("port_11434", {}).get("is_open", False)
        proc_running = evidence.get("process_ollama", {}).get("is_running", False)
        ollama_available = evidence.get("ollama_api", {}).get("is_available", False)

        if not proc_running and not port_open:
            root_cause = (
                "Ollama daemon process is terminated. Port 11434 is closed. "
                "The application cannot reach the local AI runtime."
            )
            recommended_action = "start_ollama"
            confidence = 0.99
        elif not ollama_available:
            root_cause = "Ollama API endpoint failed to respond to health probes on port 11434."
            recommended_action = "start_ollama"
            confidence = 0.95
        else:
            root_cause = f"Application error: {context.error_message}"
            recommended_action = "retry_request"
            confidence = 0.80

        return DiagnosticReport(
            incident_id=context.incident_id,
            evidence=evidence,
            detected_root_cause=root_cause,
            confidence_score=confidence,
            recommended_action=recommended_action,
        )

    def select_remediation(self, report: DiagnosticReport, allowlist: List[str]) -> str:
        """
        Selects an allowlisted action. If recommended action is not in allowlist, falls back to safe retry.
        """
        if report.recommended_action in allowlist:
            return report.recommended_action
        return "retry_request"
