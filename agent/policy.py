"""
Policy validation between the model and the remediation allowlist.

The flow is fixed and cannot be short-circuited by anything the model says:

    Bedrock  ->  DiagnosisResult (schema validation)
             ->  policy validation  (THIS MODULE)
             ->  runner.remediation_registry (existing allowlist)
             ->  execution

Schema validation answers "is the reply well formed?". This module answers "is it
permitted?". They are separate because a syntactically perfect
`recommended_action` of `run_command` passes Pydantic and must still be refused.

Three deliberate choices:

* **The approved action is never the model's string.** When a recommendation is
  accepted, `approved_action` is set from a module constant, not copied from the
  reply. Even a normalised match cannot carry unexpected characters downstream.
* **`stop_ollama` is not model-recommendable.** It remains in the runner's
  allowlist because the intentional-failure trigger uses it, but a model has no
  legitimate reason to recommend terminating the daemon as a *remedy*. Asking for
  it is recorded as a violation.
* **Every refusal is a security audit event**, logged through the existing
  `record_log("SECURITY", ...)` path and returned in the decision so it lands on
  the incident's audit trail.

Nothing here executes anything. This module cannot start, stop, signal or call
anything; it returns a verdict.
"""

from typing import Any, Dict, List, Optional, Sequence

from runner.diagnostics import record_log
from runner.remediation_registry import REMEDIATION_ALLOWLIST
from .schemas import DiagnosisResult, PolicyDecision

# What the model may recommend. A subset of the runner's allowlist by design:
# `stop_ollama` is excluded because terminating the daemon is a chaos-testing
# trigger, not a recovery.
MODEL_PERMITTED_ACTIONS = frozenset({"start_ollama", "retry_request", "none"})

# Canonical constants, so the value handed downstream never originates in model
# text.
ACTION_START_OLLAMA = "start_ollama"
ACTION_RETRY_REQUEST = "retry_request"
ACTION_NONE = "none"
_CANONICAL = {
    ACTION_START_OLLAMA: ACTION_START_OLLAMA,
    ACTION_RETRY_REQUEST: ACTION_RETRY_REQUEST,
    ACTION_NONE: ACTION_NONE,
}

# Command-execution vocabulary. A recommendation containing any of these is
# refused outright and audited, regardless of whether it happens to resemble an
# allowlisted name.
FORBIDDEN_ACTION_TOKENS = (
    "run_command",
    "runcommand",
    "run",
    "shell",
    "bash",
    "sh",
    "zsh",
    "cmd",
    "powershell",
    "curl",
    "wget",
    "nc",
    "netcat",
    "python",
    "python3",
    "pip",
    "node",
    "perl",
    "ruby",
    "exec",
    "execute",
    "eval",
    "system",
    "subprocess",
    "popen",
    "spawn",
    "rm",
    "rmdir",
    "del",
    "kill",
    "sudo",
    "chmod",
    "chown",
    "dd",
    "mkfs",
    "reboot",
    "shutdown",
    "apt",
    "yum",
    "brew",
    "docker",
    "kubectl",
    "aws",
    "iam",
    "credential",
    "secret",
    "token",
    "password",
    "env",
    "printenv",
    "cat",
    "open",
    "read_file",
    "write_file",
    "download",
    "upload",
    "http",
    "request",
    "fetch",
    "get_url",
    "disable",
    "bypass",
    "override",
    "stop_ollama",
)

# Characters that must never appear in an action name. The schema already forbids
# them; this is a second, independent check so a schema change cannot silently
# open a shell-injection path.
FORBIDDEN_CHARACTERS = set(" \t\n\r;|&$`'\"\\/<>(){}[]*?!~#%^+=")


def _audit(message: str, decision_context: Optional[Dict[str, Any]] = None) -> None:
    """Records a security event through the existing audit log path."""
    record_log("SECURITY", message, service="agent_policy")


def validate_diagnosis(
    result: Any,
    evidence_ids: Sequence[str],
    incident_id: Optional[str] = None,
    budget_exhausted: bool = False,
    iteration_limit_hit: bool = False,
) -> PolicyDecision:
    """
    Validates a model reply and returns the policy verdict.

    Accepts anything so that a malformed reply produces a *policy* refusal with an
    audit trail rather than an unhandled exception in the request path.
    """
    context = {"incident_id": incident_id}

    # --- 0. Must be a validated DiagnosisResult ---------------------------
    if not isinstance(result, DiagnosisResult):
        reason = (
            "Model reply did not satisfy the DiagnosisResult schema; refusing to act on "
            "unvalidated free-form output."
        )
        _audit(reason, context)
        return PolicyDecision(
            allowed=False,
            requested_action=str(getattr(result, "recommended_action", "<unparsed>"))[:64],
            reason=reason,
            violation="schema_validation_failed",
            requires_human=True,
        )

    requested = (result.recommended_action or "").strip()
    context["requested_action"] = requested

    # --- 1. Budget / iteration ceilings -----------------------------------
    # Requirement: hitting the iteration cap is REQUIRES_HUMAN, never RESOLVED.
    if iteration_limit_hit or budget_exhausted:
        reason = (
            "The agent reached its iteration or tool-call budget without producing a "
            "conclusive diagnosis. Escalating to a human rather than guessing."
        )
        _audit(f"Agent budget exhausted for incident {incident_id}; escalating.", context)
        return PolicyDecision(
            allowed=False,
            requested_action=requested,
            reason=reason,
            violation="iteration_limit",
            requires_human=True,
        )

    # --- 2. Shell metacharacters ------------------------------------------
    if any(ch in FORBIDDEN_CHARACTERS for ch in requested):
        reason = f"Recommended action contains forbidden characters: {requested[:64]!r}."
        _audit(f"Refused action with shell metacharacters: {requested[:64]!r}", context)
        return PolicyDecision(
            allowed=False,
            requested_action=requested[:64],
            reason=reason,
            violation="shell_metacharacters",
            requires_human=True,
        )

    # --- 3. Command-execution vocabulary ----------------------------------
    lowered = requested.lower()
    matched_tokens = [t for t in FORBIDDEN_ACTION_TOKENS if t == lowered or t in lowered.split("_")]
    if matched_tokens and lowered not in _CANONICAL:
        reason = (
            f"Recommended action {requested!r} is a command-execution or forbidden request "
            f"(matched: {', '.join(sorted(set(matched_tokens))[:5])}). The agent has no such tool."
        )
        _audit(f"BLOCKED forbidden action recommendation from model: {requested[:64]!r}", context)
        return PolicyDecision(
            allowed=False,
            requested_action=requested[:64],
            reason=reason,
            violation="forbidden_action",
            requires_human=True,
        )

    # --- 4. Must be model-permitted ---------------------------------------
    canonical = _CANONICAL.get(lowered)
    if canonical is None:
        reason = (
            f"Recommended action {requested!r} is not one the model may recommend "
            f"({', '.join(sorted(MODEL_PERMITTED_ACTIONS))})."
        )
        _audit(f"Refused non-permitted model recommendation: {requested[:64]!r}", context)
        return PolicyDecision(
            allowed=False,
            requested_action=requested[:64],
            reason=reason,
            violation="not_permitted_for_model",
            requires_human=True,
        )

    # --- 5. Must also exist in the runner's remediation allowlist ----------
    # "none" means "take no action", so it is not looked up in the allowlist.
    if canonical != ACTION_NONE and canonical not in REMEDIATION_ALLOWLIST:
        reason = (
            f"Action {canonical!r} is not registered in REMEDIATION_ALLOWLIST; refusing "
            "to forward it to the remediation registry."
        )
        _audit(f"Refused action absent from the remediation allowlist: {canonical!r}", context)
        return PolicyDecision(
            allowed=False,
            requested_action=requested[:64],
            reason=reason,
            violation="not_in_allowlist",
            requires_human=True,
        )

    # --- 6. Evidence citations must be real --------------------------------
    known = set(evidence_ids or ())
    cited = list(result.evidence_ids or []) + list(result.contradictory_evidence_ids or [])
    hallucinated = sorted({cid for cid in cited if cid not in known})
    if hallucinated:
        reason = (
            f"Diagnosis cites evidence that was never provided: {', '.join(hallucinated[:8])}. "
            "Refusing to act on a hallucinated evidence trail."
        )
        _audit(f"Refused diagnosis citing non-existent evidence: {hallucinated[:8]}", context)
        return PolicyDecision(
            allowed=False,
            requested_action=canonical,
            reason=reason,
            violation="evidence_not_found",
            requires_human=True,
        )

    # --- 7. Accepted -------------------------------------------------------
    if canonical == ACTION_NONE:
        reason = "Model recommended no action; nothing will be executed."
        return PolicyDecision(
            allowed=True,
            requested_action=requested,
            approved_action=ACTION_NONE,
            reason=reason,
            requires_human=bool(result.requires_human) or result.confidence < 0.5,
        )

    reason = (
        f"Action {canonical!r} is in the model-permitted set and in REMEDIATION_ALLOWLIST. "
        "Forwarding to the existing allowlisted executor; the runner still decides whether "
        "it actually runs."
    )
    return PolicyDecision(
        allowed=True,
        requested_action=requested,
        approved_action=canonical,
        reason=reason,
        requires_human=bool(result.requires_human),
    )


def summarise_for_incident(decision: PolicyDecision, incident_id: Optional[str] = None) -> Dict[str, Any]:
    """The audit record persisted on the Incident for this policy decision."""
    return decision.audit_event(incident_id)


def permitted_actions_for_prompt() -> List[str]:
    """Stable, sorted list used when building prompts and docs."""
    return sorted(MODEL_PERMITTED_ACTIONS)
