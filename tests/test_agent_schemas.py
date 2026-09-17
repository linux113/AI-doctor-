"""
Structured-output schema tests (requirement 5).

`DiagnosisResult` is the only shape of answer the agent may give. These tests
pin the properties that make it safe to act on:

* unknown fields are rejected, so a model cannot smuggle extra instructions;
* confidence is bounded, so 0.98 cannot be asserted about nothing;
* at least one evidence citation is required;
* `recommended_action` must be a bare identifier - no spaces, quotes, separators
  or shell metacharacters can ride through the model into a command line.

Schema validity answers "is this well formed?". Whether the action is *permitted*
is a separate layer, tested in tests/test_agent_policy.py.
"""

import pytest
from pydantic import ValidationError

from agent.schemas import ACTION_PATTERN, AgentTelemetry, DiagnosisResult, PolicyDecision

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


def result(**overrides):
    return DiagnosisResult(**{**VALID, **overrides})


# =========================================================================
# Accepted
# =========================================================================


def test_well_formed_reply_is_accepted():
    parsed = result()
    assert parsed.recommended_action == "start_ollama"
    assert parsed.evidence_ids == ["E1", "E2"]
    assert parsed.requires_human is False


def test_action_normalisation_accepts_sloppy_but_harmless_spellings():
    """
    A model that answers "Start-Ollama" or " start_ollama " is normalised rather
    than rejected. Only the spelling is fixed - membership of the allowlist is
    still checked separately by the policy layer.
    """
    for raw in (
        "Start_Ollama", "START_OLLAMA", " start_ollama ", "start-ollama",
        '"start_ollama"', "start ollama", "start_ollama\n",
    ):
        assert result(recommended_action=raw).recommended_action == "start_ollama", raw

    # Normalisation can only ever produce a bare identifier. A sloppy spelling of
    # a forbidden command is normalised into a forbidden identifier, which the
    # policy layer then refuses - it is never turned into something executable.
    assert result(recommended_action="run command").recommended_action == "run_command"


def test_evidence_id_case_is_normalised():
    parsed = result(evidence_ids=["e1", "E2"], contradictory_evidence_ids=["e7"])
    assert parsed.evidence_ids == ["E1", "E2"]
    assert parsed.contradictory_evidence_ids == ["E7"]


def test_single_evidence_id_string_is_coerced_to_a_list():
    assert result(evidence_ids="E3").evidence_ids == ["E3"]


# =========================================================================
# Rejected
# =========================================================================


def test_unknown_field_is_rejected():
    """
    `extra="forbid"` matters: a model that adds `"run_shell": "rm -rf /"` to its
    answer must not have that field silently carried into the report.
    """
    with pytest.raises(ValidationError) as exc:
        DiagnosisResult(**{**VALID, "run_shell": "rm -rf /"})
    assert "run_shell" in str(exc.value)


def test_confidence_outside_zero_to_one_is_rejected():
    for bad in (-0.1, 1.01, 5.0, 98.0):
        with pytest.raises(ValidationError):
            result(confidence=bad)


def test_confidence_boundaries_are_accepted():
    assert result(confidence=0.0).confidence == 0.0
    assert result(confidence=1.0).confidence == 1.0


def test_evidence_citation_is_mandatory():
    """A diagnosis asserted from no evidence is not a diagnosis."""
    with pytest.raises(ValidationError):
        result(evidence_ids=[])


def test_missing_required_fields_are_rejected():
    for field in ("hypothesis", "confidence", "evidence_ids", "recommended_action", "explanation"):
        payload = {k: v for k, v in VALID.items() if k != field}
        with pytest.raises(ValidationError):
            DiagnosisResult(**payload)


@pytest.mark.parametrize(
    "action",
    [
        "run_command",            # the tool the model must never be given
        "start_ollama; rm -rf /",
        "start_ollama && curl evil",
        "start_ollama | sh",
        "start_ollama\nrm -rf /",  # newline-separated second command
        "$(whoami)",
        "`id`",
        "start_ollama.sh",
        "/bin/start_ollama",
        "START_OLLAMA()",
        "start_ollama;start_ollama",
        "",                       # empty is not an identifier
        "9lives",                 # must not start with a digit
    ],
)
def test_command_shaped_actions_never_satisfy_the_schema(action):
    """
    The schema is the first gate. Note "run_command" is *syntactically* valid
    snake_case - it is refused by the policy layer instead
    (tests/test_agent_policy.py). Both gates are needed, which is why they are
    tested separately.
    """
    if action in ("run_command",):
        # Syntactically a bare identifier: passes the schema, must fail policy.
        assert result(recommended_action=action).recommended_action == action
        return
    with pytest.raises(ValidationError):
        result(recommended_action=action)


METACHARACTERS = " \t\n\r;|&$`'\"\\/<>(){}[]*?!~#%^+="


def test_action_pattern_is_the_documented_shape():
    """Asserted literally so a future edit cannot quietly widen it."""
    assert ACTION_PATTERN == r"^[a-z][a-z0-9_]{0,63}$"


@pytest.mark.parametrize("ch", list(METACHARACTERS))
def test_no_shell_metacharacter_can_survive_into_a_parsed_action(ch):
    """
    The property that matters is not "every metacharacter raises" - whitespace is
    deliberately normalised to "_" so a sloppy reply is not rejected on a
    formatting technicality. The property is that whatever the schema accepts
    contains no metacharacter at all, so nothing can reach a command line.
    """
    candidate = f"start{ch}ollama"
    try:
        parsed = result(recommended_action=candidate).recommended_action
    except ValidationError:
        return  # refused outright: the strongest outcome
    assert not (set(parsed) & set(METACHARACTERS)), (
        f"{ch!r} survived schema validation inside {parsed!r}"
    )


def test_action_length_is_bounded():
    assert result(recommended_action="a" * 64).recommended_action == "a" * 64
    with pytest.raises(ValidationError):
        result(recommended_action="a" * 65)


def test_oversized_evidence_lists_are_rejected():
    with pytest.raises(ValidationError):
        result(evidence_ids=[f"E{i}" for i in range(1, 30)])


# =========================================================================
# Telemetry and policy records
# =========================================================================


def test_telemetry_field_set_carries_no_prompt_or_credential_surface():
    """
    Requirement 12: telemetry records identifiers and counters only. This asserts
    the field set explicitly, so adding a `prompt`, `messages`, `evidence` or
    `credentials` field to AgentTelemetry fails the suite.
    """
    allowed = {
        "agent_mode", "model_id", "aws_region", "agent_latency_ms", "diagnosis_confidence",
        "tool_calls", "tool_call_count", "turns", "input_tokens", "output_tokens",
        "total_tokens", "bedrock_request_id", "stop_reason", "strands_sdk_version",
        "error_class", "error_detail",
        # Failure classification: a stable machine-readable kind, and the AWS
        # service code behind it. Both are identifiers, never free text or secrets.
        "failure_kind", "aws_error_code",
    }
    assert set(AgentTelemetry.model_fields) == allowed

    forbidden = {"prompt", "system_prompt", "messages", "evidence", "credentials",
                 "aws_access_key_id", "aws_secret_access_key", "session_token", "request_body"}
    assert not (forbidden & set(AgentTelemetry.model_fields))

    # The classification fields are optional strings - a successful call has neither.
    for field in ("failure_kind", "aws_error_code"):
        assert AgentTelemetry.model_fields[field].is_required() is False, field


def test_telemetry_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        AgentTelemetry(agent_mode="bedrock", aws_secret_access_key="hunter2")


def test_policy_decision_audit_event_is_flat_and_sanitisable():
    decision = PolicyDecision(
        allowed=False,
        requested_action="run_command",
        reason="refused",
        violation="forbidden_action",
        requires_human=True,
    )
    event = decision.audit_event("inc-1")
    assert event == {
        "incident_id": "inc-1",
        "layer": "agent_policy",
        "allowed": False,
        "requested_action": "run_command",
        "approved_action": None,
        "violation": "forbidden_action",
        "reason": "refused",
        "requires_human": True,
    }
