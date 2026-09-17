"""
Deterministic root-cause engine for AI Doctor.

Single source of truth
----------------------
The root-cause decision table used to be implemented twice: once in
`runner/doctor_runner.py` (the live path, called by `backend/main.py`) and
once in `agent/strands_agent.py` (`StrandsAgentPlaceholder`, which nothing
imported). The two had already drifted - different branch ordering, different
wording, and different confidence values. Both now delegate here, so the
Phase 2 Strands/Bedrock swap has exactly one seam to replace.

Evidence-derived confidence
---------------------------
`DoctorRunner.diagnose_root_cause` previously returned a hardcoded
`confidence: 0.98` on *every* branch, including the "unknown application-level
error" fallback. A constant is not a confidence score: it asserted near-certainty
about the one case where the engine has no idea what is wrong.

Confidence is now computed from the three independent probes that make up the
evidence bundle:

    check_port     -> raw TCP socket connect to :11434
    check_process  -> OS process table via psutil
    check_ollama   -> HTTP GET /api/tags

Each hypothesis states how many of those probes corroborate it and how many
contradict it, and `_score_confidence` turns that into a number. When all
probes agree the score is high; when they disagree, or when the infrastructure
looks healthy and the failure is therefore unexplained, the score is low.
Low confidence is a real signal to the caller, not a decoration.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

# Probe count. Corroboration is expressed as a fraction of this.
_TOTAL_PROBES = 3

# A probe that actively contradicts the chosen hypothesis is worse than a
# merely absent one, so it costs more than it would contribute.
_CONTRADICTION_PENALTY = 0.22

_FLOOR = 0.05
_CEILING = 0.97


def _score_confidence(corroborating: int, contradicting: int = 0) -> float:
    """
    Maps probe agreement onto a 0..1 confidence score.

    0.30 is the "no evidence either way" baseline; full corroboration from all
    three independent probes adds 0.60. Each contradicting probe subtracts
    0.22, which is deliberately more than the ~0.20 a single probe can add, so
    disagreement always pulls the score down.
    """
    share = max(0, min(_TOTAL_PROBES, corroborating)) / _TOTAL_PROBES
    score = 0.30 + 0.60 * share - (_CONTRADICTION_PENALTY * max(0, contradicting))
    return round(max(_FLOOR, min(_CEILING, score)), 2)


@dataclass
class Diagnosis:
    """Outcome of a deterministic root-cause evaluation."""

    root_cause: str
    recommended_remediation: str
    confidence: float
    hypothesis: str
    corroborating_probes: List[str]
    contradicting_probes: List[str]
    evidence_consistent: bool = True
    notes: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        """
        Serialises to the shape callers already consume.

        `root_cause`, `recommended_remediation` and `confidence` are preserved
        verbatim for backwards compatibility with `backend/main.py`, the
        frontend timeline and the existing assertions in
        `tests/test_api_endpoints.py`. The remaining fields are additive and
        explain *why* the score is what it is.
        """
        return {
            "root_cause": self.root_cause,
            "recommended_remediation": self.recommended_remediation,
            "confidence": self.confidence,
            "hypothesis": self.hypothesis,
            "corroborating_probes": self.corroborating_probes,
            "contradicting_probes": self.contradicting_probes,
            "evidence_consistent": self.evidence_consistent,
            "notes": self.notes,
        }


def _probe_flags(evidence: Dict[str, Any]) -> Dict[str, bool]:
    """Extracts the three boolean probe signals from an evidence bundle."""
    return {
        "port_open": bool(evidence.get("port_11434", {}).get("is_open", False)),
        "proc_running": bool(evidence.get("process_ollama", {}).get("is_running", False)),
        "api_available": bool(evidence.get("ollama_api", {}).get("is_available", False)),
    }


def diagnose(evidence: Dict[str, Any], initial_error: str = "") -> Diagnosis:
    """
    Evaluates collected system evidence and returns a root cause plus the
    allowlisted remediation that follows from it.

    Branch order matters: the most specific, most fully corroborated
    hypothesis is tested first.
    """
    p = _probe_flags(evidence)
    port_open, proc_running, api_available = p["port_open"], p["proc_running"], p["api_available"]

    # ------------------------------------------------------------------
    # H0: IMPOSSIBLE COMBINATION - checked first, before any hypothesis that
    #     could otherwise absorb it and report high confidence.
    #
    #     check_ollama reaches the API *through* port 11434. A closed socket
    #     and a successful HTTP response cannot both be true, so at least one
    #     probe is lying: a race between the two probes, a service bound to a
    #     different interface, or a stale/cached result. No root cause should
    #     be asserted on top of that.
    # ------------------------------------------------------------------
    if not port_open and api_available:
        return Diagnosis(
            hypothesis="contradictory_probes",
            root_cause=(
                "Diagnostic probes contradict each other: the TCP socket to port 11434 is "
                "reported closed while the Ollama HTTP API on that same port answered "
                "successfully. No reliable root cause can be inferred from inconsistent evidence."
            ),
            recommended_remediation="start_ollama",
            confidence=_score_confidence(corroborating=1, contradicting=1),
            corroborating_probes=["check_ollama"],
            contradicting_probes=["check_port"],
            evidence_consistent=False,
            notes=(
                "Low confidence by construction. Re-collect evidence before acting; the "
                "usual cause is a probe race during a service restart."
            ),
        )

    # ------------------------------------------------------------------
    # H1: daemon is gone. All three probes agree independently.
    # ------------------------------------------------------------------
    if not proc_running and not port_open and not api_available:
        return Diagnosis(
            hypothesis="ollama_daemon_terminated",
            root_cause=(
                "Ollama daemon process is terminated. TCP port 11434 is closed. "
                "The application cannot reach the local AI runtime."
            ),
            recommended_remediation="start_ollama",
            confidence=_score_confidence(corroborating=3),
            corroborating_probes=["check_process", "check_port", "check_ollama"],
            contradicting_probes=[],
        )

    # ------------------------------------------------------------------
    # H2: process exists but is not serving. Port closed and API down
    #     corroborate; the live process rules out H1 rather than this.
    # ------------------------------------------------------------------
    if proc_running and not port_open:
        return Diagnosis(
            hypothesis="ollama_process_hung_or_unbound",
            root_cause=(
                "Ollama process exists but has not bound to port 11434 or is hanging. "
                "Restarting Ollama service is required."
            ),
            recommended_remediation="start_ollama",
            # Slightly below H1: a process caught mid-startup also presents
            # this way, so the evidence is marginally less decisive.
            confidence=round(_score_confidence(corroborating=3) - 0.05, 2),
            corroborating_probes=["check_process", "check_port", "check_ollama"],
            contradicting_probes=[],
            notes=(
                "A daemon still in its startup window can present identically. "
                "Verification polling after remediation distinguishes the two."
            ),
        )

    # ------------------------------------------------------------------
    # H3: port closed and API down, process probe inconclusive.
    # ------------------------------------------------------------------
    if not port_open and not api_available:
        return Diagnosis(
            hypothesis="ollama_unreachable",
            root_cause=(
                "Ollama is unreachable on port 11434: the port is closed and the HTTP "
                "API did not respond. Starting the service is required."
            ),
            recommended_remediation="start_ollama",
            confidence=_score_confidence(corroborating=2),
            corroborating_probes=["check_port", "check_ollama"],
            contradicting_probes=[],
        )

    # ------------------------------------------------------------------
    # H4: port open but the API is unhealthy (non-200, malformed JSON,
    #     timeout). The listener is up, the application behind it is not.
    # ------------------------------------------------------------------
    if port_open and not api_available:
        return Diagnosis(
            hypothesis="ollama_api_unhealthy",
            root_cause=(
                "Ollama API returned an error or timeout during health check. "
                "Restarting Ollama service is required."
            ),
            recommended_remediation="start_ollama",
            confidence=_score_confidence(corroborating=2),
            corroborating_probes=["check_port", "check_ollama"],
            contradicting_probes=[],
        )

    # ------------------------------------------------------------------
    # H5: infrastructure is healthy. The failure is NOT explained by any
    #     probe, so confidence must be low. This is the branch that used to
    #     claim 0.98.
    # ------------------------------------------------------------------
    # The HTTP API answered, so the service is demonstrably working. If the
    # process probe nevertheless found nothing, that probe is blind (a
    # container or namespace boundary, or insufficient permission) rather than
    # evidence of an outage - flag it instead of silently trusting it.
    process_probe_blind = not proc_running

    return Diagnosis(
        hypothesis="unexplained_application_error",
        root_cause=f"Unknown application-level error: {initial_error}",
        recommended_remediation="retry_request",
        confidence=_score_confidence(corroborating=0),
        corroborating_probes=[],
        contradicting_probes=[],
        evidence_consistent=not process_probe_blind,
        notes=(
            "Port 11434 is open, the Ollama process is running and the HTTP API is "
            "healthy, so no infrastructure probe explains this failure. Confidence is "
            "low on purpose: the cause is above the transport layer and needs "
            "application-level evidence this engine does not collect."
            if not process_probe_blind
            else "The Ollama HTTP API answered, so the service is running, but the process "
            "probe found no matching PID - it is likely blind to the process (container or "
            "namespace boundary, or insufficient permission). Treat check_process as "
            "unreliable here. No infrastructure probe explains the reported failure, so "
            "confidence is low on purpose."
        ),
    )
