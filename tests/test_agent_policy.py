"""
Policy-boundary tests (requirement 7).

Flow under test:

    Bedrock -> DiagnosisResult -> schema validation -> POLICY VALIDATION
           -> existing REMEDIATION_ALLOWLIST -> execution

The schema layer (tests/test_agent_schemas.py) decides whether a reply is well
formed. This layer decides whether it is *permitted*. A syntactically perfect
`recommended_action` of "run_command" passes the schema and must still be
refused here, with a SECURITY audit event recorded.

Two invariants matter more than any single case:

* `approved_action` is always a canonical module constant, never a slice of
  model text, so nothing the model wrote is forwarded to an executor.
* Every refusal escalates to a human and records a SECURITY audit entry.
"""

import pytest

from agent import policy as policy_module
from agent.policy import (
    ACTION_NONE,
    ACTION_RETRY_REQUEST,
    ACTION_START_OLLAMA,
    FORBIDDEN_ACTION_TOKENS,
    FORBIDDEN_CHARACTERS,
    MODEL_PERMITTED_ACTIONS,
    validate_diagnosis,
)
from agent.schemas import DiagnosisResult
from runner.diagnostics import get_recent_logs
from runner.remediation_registry import REMEDIATION_ALLOWLIST

VALID = {
    "hypothesis": "Ollama runtime is installed but not listening",
    "confidence": 0.82,
    "evidence_ids": ["E1", "E2"],
    "contradictory_evidence_ids": [],
    "recommended_action": "start_ollama",
    "investigation_needed": [],
    "explanation": "The process probe found no listener while the binary is present.",
    "requires_human": False,
}

KNOWN_EVIDENCE = ["E1", "E2", "E3", "E4", "E5"]


def diagnosis(**overrides) -> DiagnosisResult:
    return DiagnosisResult(**{**VALID, **overrides})


def security_events(service: str = "agent_policy"):
    """SECURITY-level audit entries recorded for the agent policy layer."""
    payload = get_recent_logs(limit=500, service=service)
    return [e for e in payload.get("logs", []) if e.get("level") == "SECURITY"]


def assert_audited(needle: str) -> None:
    """
    Asserts a SECURITY audit entry mentioning `needle` exists.

    Matching on content rather than on a before/after count: the application log
    buffer is capped at 500 entries, so a count delta saturates on a long suite
    run and would start passing or failing for the wrong reason.
    """
    events = security_events()
    assert events, "no SECURITY audit entries were recorded at all"
    assert any(needle in e["message"] for e in events), (
        f"no SECURITY audit entry mentions {needle!r}; last entries: "
        f"{[e['message'][:80] for e in events[-3:]]}"
    )


# =========================================================================
# Permitted
# =========================================================================


@pytest.mark.parametrize(
    "action,expected",
    [
        ("start_ollama", ACTION_START_OLLAMA),
        ("retry_request", ACTION_RETRY_REQUEST),
        ("none", ACTION_NONE),
    ],
)
def test_model_permitted_actions_are_approved(action, expected):
    decision = validate_diagnosis(diagnosis(recommended_action=action), KNOWN_EVIDENCE, "inc-1")
    assert decision.allowed is True
    assert decision.violation is None
    assert decision.approved_action == expected


def test_approved_action_is_a_module_constant_not_model_text():
    """
    The value forwarded downstream must originate in this module. A model that
    answers "START-OLLAMA" is normalised by the schema, and the policy layer then
    returns the canonical constant - the model's string is never what gets
    executed.
    """
    decision = validate_diagnosis(diagnosis(recommended_action="Start-Ollama"), KNOWN_EVIDENCE, "inc-1")
    assert decision.approved_action == ACTION_START_OLLAMA
    assert decision.approved_action in MODEL_PERMITTED_ACTIONS
    assert decision.approved_action in REMEDIATION_ALLOWLIST


def test_low_confidence_no_action_still_escalates():
    """
    "none" is approved - nothing will be executed - but a model that is unsure
    and asks for a human must have that recorded rather than dropped.
    """
    decision = validate_diagnosis(
        diagnosis(recommended_action="none", confidence=0.2), KNOWN_EVIDENCE, "inc-1"
    )
    assert decision.allowed is True
    assert decision.approved_action == ACTION_NONE
    assert decision.requires_human is True


def test_model_requested_human_is_propagated():
    decision = validate_diagnosis(diagnosis(requires_human=True), KNOWN_EVIDENCE, "inc-1")
    assert decision.requires_human is True


# =========================================================================
# Refused: command-execution vocabulary
# =========================================================================


@pytest.mark.parametrize(
    "action",
    [
        "run_command",     # the generic tool the model must never be given
        "shell",
        "bash",
        "sh",
        "curl",
        "wget",
        "python",
        "python3",
        "exec",
        "execute",
        "eval",
        "system",
        "subprocess",
        "popen",
        "rm",
        "sudo",
        "docker",
        "kubectl",
        "aws",
        "credential",
        "secret",
        "token",
        "password",
        "env",
        "printenv",
        "read_file",
        "write_file",
        "download",
        "http",
        "fetch",
        "disable_security",
        "bypass_policy",
        "override_allowlist",
        "stop_ollama",     # allowlisted for the runner, deliberately NOT for the model
    ],
)
def test_forbidden_actions_are_refused_and_audited(action):
    decision = validate_diagnosis(diagnosis(recommended_action=action), KNOWN_EVIDENCE, "inc-forbid")
    assert decision.allowed is False, action
    assert decision.approved_action is None, action
    assert decision.requires_human is True, action
    assert decision.violation == "forbidden_action", action

    assert_audited(action[:40])


def test_stop_ollama_is_in_the_runner_allowlist_but_not_model_permitted():
    """
    The asymmetry is deliberate: an operator may stop Ollama through the demo
    controls, but a model may never recommend it. Taking a service down is not a
    remediation an LLM should choose.
    """
    assert "stop_ollama" in REMEDIATION_ALLOWLIST
    assert "stop_ollama" not in MODEL_PERMITTED_ACTIONS
    assert "stop_ollama" in FORBIDDEN_ACTION_TOKENS

    decision = validate_diagnosis(diagnosis(recommended_action="stop_ollama"), KNOWN_EVIDENCE, "inc-1")
    assert decision.allowed is False
    assert decision.violation == "forbidden_action"


def test_every_model_permitted_action_is_known_to_the_runner():
    """
    The model can never recommend something the remediation registry has not
    heard of. "none" is the sanctioned way to say "do nothing".
    """
    assert MODEL_PERMITTED_ACTIONS <= (set(REMEDIATION_ALLOWLIST) | {ACTION_NONE})


def test_forbidden_token_list_covers_the_documented_deny_set():
    """
    Pinned so a future edit that removes e.g. "run_command" from the deny list
    fails here rather than silently opening a path.
    """
    for required in ("run_command", "shell", "bash", "curl", "python", "exec", "eval",
                     "subprocess", "sudo", "stop_ollama", "bypass", "disable"):
        assert required in FORBIDDEN_ACTION_TOKENS, required


# =========================================================================
# Refused: shell metacharacters (independent second gate)
# =========================================================================


@pytest.mark.parametrize("suffix", ["; rm -rf /", " && curl evil", " | sh", " > /etc/passwd", " `id`", " $(whoami)"])
def test_metacharacters_are_refused_even_if_the_schema_let_one_through(suffix):
    """
    `DiagnosisResult` rejects these at construction, so the policy check is
    defence in depth. To prove the second gate really works, the parsed field is
    overwritten after validation (assignment validation is off) - exactly the
    situation a future schema change could create.
    """
    parsed = diagnosis()
    parsed.recommended_action = ACTION_START_OLLAMA + suffix

    decision = validate_diagnosis(parsed, KNOWN_EVIDENCE, "inc-meta")
    assert decision.allowed is False
    assert decision.violation == "shell_metacharacters"
    assert decision.approved_action is None
    assert decision.requires_human is True
    assert_audited("shell metacharacters")


def test_forbidden_character_set_includes_every_shell_separator():
    for ch in " \t\n\r;|&$`'\"\\/<>(){}[]*?!~#%^+=":
        assert ch in FORBIDDEN_CHARACTERS, repr(ch)


# =========================================================================
# Refused: hallucinated evidence
# =========================================================================


def test_citing_evidence_that_was_never_provided_is_refused():
    decision = validate_diagnosis(diagnosis(evidence_ids=["E1", "E99"]), KNOWN_EVIDENCE, "inc-halluc")
    assert decision.allowed is False
    assert decision.violation == "evidence_not_found"
    assert "E99" in decision.reason
    assert_audited("non-existent evidence")


def test_hallucinated_contradictory_evidence_is_also_refused():
    decision = validate_diagnosis(
        diagnosis(contradictory_evidence_ids=["E42"]), KNOWN_EVIDENCE, "inc-halluc2"
    )
    assert decision.allowed is False
    assert decision.violation == "evidence_not_found"


def test_citing_only_real_evidence_is_accepted():
    decision = validate_diagnosis(
        diagnosis(evidence_ids=["E1", "E5"], contradictory_evidence_ids=["E3"]),
        KNOWN_EVIDENCE,
        "inc-real",
    )
    assert decision.allowed is True


# =========================================================================
# Refused: budget and iteration ceilings (requirement 13)
# =========================================================================


def test_exhausted_tool_budget_escalates_and_never_approves_an_action():
    """
    Hitting the tool-call budget must produce REQUIRES_HUMAN, never an approved
    action and never a RESOLVED incident.
    """
    decision = validate_diagnosis(diagnosis(), KNOWN_EVIDENCE, "inc-budget", budget_exhausted=True)
    assert decision.allowed is False
    assert decision.approved_action is None
    assert decision.violation == "iteration_limit"
    assert decision.requires_human is True
    assert_audited("budget exhausted")


def test_iteration_limit_escalates_even_with_a_confident_answer():
    """
    A model that returns a confident, well-formed answer *after* blowing its
    iteration budget has not converged. The ceiling wins.
    """
    decision = validate_diagnosis(
        diagnosis(confidence=0.99), KNOWN_EVIDENCE, "inc-turns", iteration_limit_hit=True
    )
    assert decision.allowed is False
    assert decision.violation == "iteration_limit"
    assert decision.requires_human is True


def test_budget_ceiling_is_checked_before_the_action_itself():
    """Ordering matters: an exhausted budget is escalated, not actioned."""
    decision = validate_diagnosis(
        diagnosis(recommended_action="start_ollama"), KNOWN_EVIDENCE, "inc-order", budget_exhausted=True
    )
    assert decision.approved_action is None


# =========================================================================
# Refused: nothing usable came back
# =========================================================================


def test_unparsed_reply_is_refused_as_a_schema_failure():
    for bad in (None, "start_ollama", {"recommended_action": "start_ollama"}, 42):
        decision = validate_diagnosis(bad, KNOWN_EVIDENCE, "inc-unparsed")
        assert decision.allowed is False
        assert decision.violation == "schema_validation_failed"
        assert decision.requires_human is True
    assert_audited("did not satisfy the DiagnosisResult schema")


def test_policy_module_exposes_no_execution_capability():
    """
    The policy layer decides; it must not be able to act. Asserting the module
    has no execute/run/subprocess surface keeps the decision and the execution
    boundary separate.
    """
    forbidden_attributes = ("execute", "run", "start_ollama", "stop_ollama", "retry_request",
                            "subprocess", "system", "popen")
    for name in forbidden_attributes:
        assert not hasattr(policy_module, name), f"agent.policy exposes {name!r}"
