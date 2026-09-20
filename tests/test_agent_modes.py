"""
Agent-mode and honesty tests (requirements 11, 12, 16).

The central rule: an incident must never claim a model produced its diagnosis
unless a model actually did. These tests pin that from both directions -

* deterministic mode never reports itself as bedrock;
* bedrock mode that succeeds reports bedrock, with the real model, region,
  latency, turns, tool calls and tokens;
* bedrock mode that CANNOT reach the model reports the real AWS error, labels the
  result deterministic, and carries no model_id - because attributing a
  rule-engine conclusion to a model that was never called is the specific
  failure this phase exists to prevent;
* with `AI_DOCTOR_AGENT_FALLBACK=fail`, no substitution happens at all.

The failure paths here make a REAL boto3 credential-chain resolution. The
environment is pinned empty (`no_credentials` fixture) so boto3 raises
`NoCredentialsError` locally in well under a second, on any machine, without a
network call.
"""

import pytest

from agent.config import (
    MODE_BEDROCK,
    MODE_DETERMINISTIC,
    MODE_OPENROUTER,
    AgentConfig,
    AgentConfigurationError,
    load_agent_config,
)
from agent.diagnosis_agent import (
    REPORT_CONTRACT_KEYS,
    STATUS_DETERMINISTIC,
    STATUS_FALLBACK_DETERMINISTIC,
    describe_agent,
    run_diagnosis,
)
from agent.strands_agent import (
    FAILURE_ACCESS_DENIED,
    FAILURE_SCHEMA_REFUSED,
    FAILURE_SERVICE_UNAVAILABLE,
    FAILURE_VALIDATION_ERROR,
    FAILURE_INVALID_MODEL,
    FAILURE_KINDS,
    FAILURE_NO_CREDENTIALS,
    FAILURE_PARTIAL_CREDENTIALS,
    FAILURE_THROTTLED,
    FAILURE_TIMEOUT,
    FAILURE_UNKNOWN,
    STATUS_BEDROCK_SUCCESS,
    STATUS_BEDROCK_UNAVAILABLE,
    STATUS_DIAGNOSED,
    STATUS_REQUIRES_HUMAN,
    BedrockUnavailableError,
)
from backend.models import Incident
from runner.doctor_runner import doctor_runner

from _fake_bedrock import (
    BASELINE,
    DOWN_EVIDENCE,
    INCIDENT,
    WELL_FORMED_REPLY,
    FakeBedrockTransport,
    bedrock_config,
    make_transport_agent,
)

DETERMINISTIC_EVIDENCE = {
    "runtime": {"installed": True, "state": "OLLAMA_STOPPED"},
    "port_11434": {"is_open": False, "status": "closed"},
    "process_ollama": {"is_running": False, "pids": []},
    "ollama_api": {"is_available": False},
    "recent_logs": [{"level": "ERROR", "message": "connect refused"}],
}


@pytest.fixture
def no_credentials(monkeypatch):
    """
    Empties the AWS credential chain so a real boto3 resolution fails locally.

    `AWS_EC2_METADATA_DISABLED` matters: without it boto3 would try the instance
    metadata service and the test would take seconds (or hang) on an EC2 host.
    """
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                 "AWS_SECURITY_TOKEN", "AWS_PROFILE", "AWS_ROLE_ARN",
                 "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
                 "AWS_CONTAINER_CREDENTIALS_FULL_URI"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent-aws-config")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent-aws-credentials")
    return True


# =========================================================================
# Configuration
# =========================================================================


def test_mode_defaults_to_deterministic():
    """The safe default: no AWS, no model, no surprise cost."""
    config = load_agent_config({})
    assert config.mode == MODE_DETERMINISTIC
    assert config.is_bedrock is False
    assert config.model_id is None and config.aws_region is None


@pytest.mark.parametrize("raw,expected", [("bedrock", MODE_BEDROCK), ("BEDROCK", MODE_BEDROCK),
                                           (" bedrock ", MODE_BEDROCK),
                                           ("deterministic", MODE_DETERMINISTIC),
                                           ("offline", MODE_DETERMINISTIC)])
def test_mode_is_read_from_the_environment(raw, expected):
    if raw.strip().lower() == "offline":
        with pytest.raises(AgentConfigurationError):
            load_agent_config({"AI_DOCTOR_AGENT_MODE": raw})
        return
    config = load_agent_config({"AI_DOCTOR_AGENT_MODE": raw})
    assert config.mode == expected


@pytest.mark.parametrize("bad", ["llm", "gpt", "bedrocks", "auto", "true", "claude", "bedrock-agent"])
def test_unknown_mode_is_a_loud_configuration_error(bad):
    """
    Guessing here would be the worst outcome: an operator who typo'd "bedrocks"
    must be told, not silently given the rule engine.
    """
    with pytest.raises(AgentConfigurationError) as exc:
        load_agent_config({"AI_DOCTOR_AGENT_MODE": bad})
    assert "AI_DOCTOR_AGENT_MODE" in str(exc.value)


@pytest.mark.parametrize("raw", [" bedrock ", "BEDROCK", "\tBedrock\n"])
def test_mode_value_is_trimmed_and_case_folded(raw):
    """Tolerating whitespace and case is deliberate; tolerating a typo is not."""
    assert load_agent_config({"AI_DOCTOR_AGENT_MODE": raw}).mode == MODE_BEDROCK


def test_empty_mode_means_unset_not_a_typo():
    """
    An empty value is how an unset variable arrives from most shell and container
    setups (`AI_DOCTOR_AGENT_MODE=` in a compose file), so it is treated as
    "not configured" and yields the safe default rather than an error.
    """
    assert load_agent_config({"AI_DOCTOR_AGENT_MODE": ""}).mode == MODE_DETERMINISTIC


def test_fallback_policy_is_configurable_and_validated():
    assert load_agent_config({"AI_DOCTOR_AGENT_MODE": "bedrock"}).fallback == "deterministic"
    assert load_agent_config(
        {"AI_DOCTOR_AGENT_MODE": "bedrock", "AI_DOCTOR_AGENT_FALLBACK": "fail"}
    ).allow_fallback is False
    with pytest.raises(AgentConfigurationError):
        load_agent_config({"AI_DOCTOR_AGENT_MODE": "bedrock", "AI_DOCTOR_AGENT_FALLBACK": "sometimes"})


def test_all_cost_and_size_budgets_are_configurable():
    """Requirement 13: every ceiling is operator-controlled, none is hardcoded."""
    config = load_agent_config({
        "AI_DOCTOR_AGENT_MODE": "bedrock",
        "AI_DOCTOR_AGENT_MAX_TURNS": "3",
        "AI_DOCTOR_AGENT_MAX_TOOL_CALLS": "4",
        "AI_DOCTOR_AGENT_MAX_TOTAL_TOKENS": "5000",
        "AI_DOCTOR_MAX_EVIDENCE_BYTES": "4096",
        "AI_DOCTOR_MAX_LOG_LINES": "5",
        "AI_DOCTOR_MAX_PROMPT_CHARS": "8000",
        "AI_DOCTOR_AGENT_MAX_OUTPUT_TOKENS": "512",
    })
    assert (config.max_turns, config.max_tool_calls, config.max_total_tokens) == (3, 4, 5000)
    assert (config.max_evidence_bytes, config.max_log_lines, config.max_prompt_chars) == (4096, 5, 8000)
    assert config.max_output_tokens == 512


# =========================================================================
# Deterministic mode says it is deterministic
# =========================================================================


def test_deterministic_mode_labels_itself_and_invokes_no_model():
    outcome = run_diagnosis(
        INCIDENT, DETERMINISTIC_EVIDENCE, "inc-det", config=AgentConfig(mode=MODE_DETERMINISTIC)
    )
    assert outcome.status == STATUS_DETERMINISTIC
    assert outcome.agent_mode == MODE_DETERMINISTIC
    assert outcome.used_llm is False
    assert outcome.telemetry.model_id is None
    assert outcome.telemetry.aws_region is None
    assert outcome.telemetry.total_tokens is None
    assert "no model was invoked" in outcome.report["agent_note"]
    assert outcome.bedrock_failure is None


def test_deterministic_mode_reproduces_the_rule_engine_exactly():
    """
    Adding the agent layer must not change offline behaviour: the report is the
    engine's report, plus labelling fields.
    """
    from runner.diagnosis import diagnose

    outcome = run_diagnosis(
        INCIDENT, DETERMINISTIC_EVIDENCE, "inc-parity", config=AgentConfig(mode=MODE_DETERMINISTIC)
    )
    engine = diagnose(DETERMINISTIC_EVIDENCE, INCIDENT["detected_error"]).as_dict()
    for key, value in engine.items():
        assert outcome.report[key] == value, key


# =========================================================================
# Bedrock mode, model reachable (fake transport)
# =========================================================================


def test_successful_bedrock_call_is_attributed_to_bedrock():
    transport = FakeBedrockTransport(fields=dict(WELL_FORMED_REPLY), request_id="REQ-mode-42")
    agent = make_transport_agent(bedrock_config(), transport)
    result = agent.diagnose(INCIDENT, DOWN_EVIDENCE, BASELINE, "inc-bedrock-ok")

    assert result.status == STATUS_DIAGNOSED
    assert result.telemetry.agent_mode == MODE_BEDROCK
    assert result.telemetry.model_id == bedrock_config().model_id
    assert result.telemetry.aws_region == bedrock_config().aws_region
    assert result.telemetry.agent_latency_ms >= 0
    assert result.telemetry.diagnosis_confidence == pytest.approx(0.82)
    assert result.telemetry.input_tokens == 1234
    assert result.telemetry.output_tokens == 210
    assert result.telemetry.total_tokens == 1444
    assert result.telemetry.tool_call_count >= 1
    assert result.telemetry.strands_sdk_version
    assert result.telemetry.error_class is None


def test_run_diagnosis_in_bedrock_mode_reports_a_model_diagnosis(monkeypatch):
    """
    The mode switch, driven end to end: `run_diagnosis` must hand back a bedrock
    attribution when a model really answered.
    """
    transport = FakeBedrockTransport(fields=dict(WELL_FORMED_REPLY))
    # The mode switch constructs the agent itself, so the seam under test is the
    # class it instantiates. Everything behind that seam - real Agent, real
    # BedrockModel, real request building - is unchanged; only the socket is
    # answered locally.
    monkeypatch.setattr(
        "agent.diagnosis_agent.BedrockDiagnosisAgent",
        lambda config: make_transport_agent(config, transport),
    )

    outcome = run_diagnosis(INCIDENT, DOWN_EVIDENCE, "inc-mode-bedrock",
                            config=bedrock_config())
    assert outcome.agent_mode == MODE_BEDROCK
    assert outcome.used_llm is True
    # The round trip succeeded AND the pipeline reached a decision. Two separate
    # facts, two separate fields - see test_status_split_is_not_collapsed.
    assert outcome.status == STATUS_BEDROCK_SUCCESS
    assert outcome.diagnosis_outcome == STATUS_DIAGNOSED
    assert outcome.bedrock_invoked is True
    assert outcome.report["recommended_remediation"] == "start_ollama"
    assert outcome.policy_event["layer"] == "agent_policy"
    assert "Amazon Bedrock" in outcome.report["agent_note"]


def test_schema_refusal_is_not_reported_as_an_aws_outage():
    """
    A model that answered in the wrong shape is a refusal, not an outage. The
    distinction matters: the incident says a model was reached, and the
    deterministic engine is NOT substituted.
    """
    transport = FakeBedrockTransport(fields=None, text="just restart everything", stop_reason="end_turn")
    result = make_transport_agent(bedrock_config(), transport).diagnose(
        INCIDENT, DOWN_EVIDENCE, BASELINE, "inc-schema-refusal"
    )
    assert result.status == STATUS_REQUIRES_HUMAN
    assert result.telemetry.agent_mode == MODE_BEDROCK
    assert result.telemetry.stop_reason == "structured_output_failed"
    assert result.policy.violation == "schema_validation_failed"
    assert result.report["recommended_remediation"] == "none"
    assert result.report["requires_human"] is True


# =========================================================================
# Bedrock mode, model NOT reachable - the honesty tests
# =========================================================================


def test_missing_credentials_fall_back_loudly_and_never_claim_bedrock(no_credentials):
    """
    Real boto3 credential resolution, really failing. The result must be labelled
    deterministic, must name the real error, and must carry no model_id - naming
    a model that was never called is exactly the dishonesty this phase forbids.
    """
    outcome = run_diagnosis(INCIDENT, DOWN_EVIDENCE, "inc-nocreds", config=bedrock_config())

    assert outcome.status == STATUS_FALLBACK_DETERMINISTIC
    assert outcome.agent_mode == MODE_DETERMINISTIC, "a fallback claimed bedrock attribution"
    assert outcome.used_llm is False
    assert outcome.bedrock_failure is not None
    assert outcome.bedrock_failure["error_class"] == "NoCredentialsError"
    assert "credentials" in outcome.bedrock_failure["error_detail"].lower()
    assert outcome.bedrock_failure["attempted_model_id"] == bedrock_config().model_id
    assert outcome.telemetry.model_id is None
    assert outcome.telemetry.aws_region is None
    assert outcome.telemetry.error_class == "NoCredentialsError"
    # The offline engine's own reasoning is preserved verbatim.
    assert outcome.report["recommended_remediation"] == "start_ollama"
    assert "not from a model" in outcome.report["agent_note"]


def test_fallback_disabled_means_no_action_and_no_substitution(no_credentials):
    config = bedrock_config(fallback="fail")
    outcome = run_diagnosis(INCIDENT, DOWN_EVIDENCE, "inc-nofallback", config=config)

    assert outcome.status == "BEDROCK_UNAVAILABLE", "the round trip did not happen"
    assert outcome.diagnosis_outcome == "FAILED", "and nothing substituted for it"
    assert outcome.bedrock_invoked is False
    assert outcome.agent_mode == MODE_BEDROCK, "the incident should still record that bedrock was asked for"
    assert outcome.used_llm is False
    assert outcome.report["recommended_remediation"] == "none"
    assert outcome.report["requires_human"] is True
    assert outcome.report["confidence"] == 0.0
    assert "AI_DOCTOR_AGENT_FALLBACK=fail" in outcome.report["agent_note"]
    # No rule-engine conclusion is smuggled in.
    assert outcome.report["root_cause"] != BASELINE["root_cause"]


def test_runner_path_with_fallback_disabled_approves_no_action(no_credentials, monkeypatch):
    """
    End to end through the runner, driven purely by environment variables - the
    way an operator would actually configure it. With bedrock requested, no
    credentials, and fallback disabled, the runner must approve NO remediation
    rather than manufacture a recovery from the rule engine.
    """
    monkeypatch.setenv("AI_DOCTOR_AGENT_MODE", "bedrock")
    monkeypatch.setenv("AI_DOCTOR_AGENT_FALLBACK", "fail")
    monkeypatch.setenv("AI_DOCTOR_AWS_REGION", "us-east-1")
    monkeypatch.setenv("AI_DOCTOR_BEDROCK_MODEL_ID", "anthropic.claude-3-5-haiku-20241022-v1:0")

    report = doctor_runner.diagnose_incident(INCIDENT, DETERMINISTIC_EVIDENCE, "boom", "inc-nofb")
    assert report["agent_mode"] == MODE_BEDROCK
    assert report["agent_status"] == "BEDROCK_UNAVAILABLE"
    assert report["diagnosis_outcome"] == "FAILED"
    assert report["bedrock_invoked"] is False
    assert report["used_llm"] is False
    assert report["recommended_remediation"] == "none"
    assert report["requires_human"] is True
    assert report["bedrock_failure"]["error_class"] == "NoCredentialsError"
    assert report["agent_telemetry"]["model_id"] is None


@pytest.mark.parametrize("forbidden_action", ["arbitrary_shell_command", "delete_everything"])
def test_a_forbidden_recommendation_is_blocked_and_visible_in_the_timeline(
    forbidden_action, monkeypatch
):
    """
    The two layers of requirement 8, end to end through the runner.

    A model that recommends a destructive or command-execution action must be
    refused by the policy gate BEFORE anything executes, the refusal must be its
    own visible timeline stage, and the incident must end unresolved with no
    action taken. Nothing here can start, stop or delete anything.
    """
    transport = FakeBedrockTransport(
        fields={**WELL_FORMED_REPLY, "recommended_action": forbidden_action}
    )
    # The seam is the class the runner instantiates; behind it the real Agent, the
    # real BedrockModel and the real request building are unchanged.
    monkeypatch.setattr(
        "agent.diagnosis_agent.BedrockDiagnosisAgent",
        lambda config: make_transport_agent(config, transport),
    )
    monkeypatch.setenv("AI_DOCTOR_AGENT_MODE", "bedrock")
    monkeypatch.setenv("AI_DOCTOR_AWS_REGION", "us-east-1")
    monkeypatch.setenv("AI_DOCTOR_BEDROCK_MODEL_ID", "anthropic.claude-3-5-haiku-20241022-v1:0")

    result = doctor_runner.heal_incident({
        "incident_id": "inc-forbidden-timeline",
        "detected_error": "connection refused on 127.0.0.1:11434",
    })

    # The gate refused it, and named why.
    assert result["policy_decision"]["allowed"] is False
    assert result["policy_decision"]["violation"] == "forbidden_action"
    assert result["policy_decision"]["approved_action"] is None

    # Nothing executed.
    assert result["action_taken"] == "none"
    assert result["status"] == "FAILED"
    assert result["resolved_at"] is None
    assert result["used_llm"] is True, "a model did answer; it was simply overruled"
    assert result["requires_human"] is True
    assert [e["action"] for e in result["audit_log"] if e.get("executed")] == []

    # And the refusal is a stage a reader can see, not a buried detail.
    policy_entry = next(
        e for e in result["timeline"] if e["stage_code"] == "POLICY_CHECK"
    )
    assert policy_entry["details"]["allowed"] is False
    assert policy_entry["details"]["requested_action"] == forbidden_action
    assert policy_entry["details"]["violation"] == "forbidden_action"
    assert "BLOCKED" in policy_entry["description"]
    assert forbidden_action in policy_entry["description"]

    # The AI_DIAGNOSIS stage records what the model asked for and that a model
    # really answered - the refusal is not presented as an outage.
    ai_entry = next(e for e in result["timeline"] if e["stage_code"] == "AI_DIAGNOSIS")
    assert ai_entry["details"]["ai_diagnosis"]["recommended_action"] == "none", (
        "the refused action must not be echoed as the recommendation"
    )
    assert ai_entry["details"]["ai_diagnosis"]["used_llm"] is True
    assert "Amazon Bedrock model" in ai_entry["description"]


def test_runner_path_in_default_mode_stays_deterministic(monkeypatch):
    """No environment at all: the offline engine, labelled as such."""
    for name in ("AI_DOCTOR_AGENT_MODE", "AI_DOCTOR_AGENT_FALLBACK"):
        monkeypatch.delenv(name, raising=False)

    report = doctor_runner.diagnose_incident(INCIDENT, DETERMINISTIC_EVIDENCE, "boom", "inc-default")
    assert report["agent_mode"] == MODE_DETERMINISTIC
    assert report["agent_status"] == STATUS_DETERMINISTIC
    assert report["used_llm"] is False
    assert report["bedrock_failure"] is None
    assert report["recommended_remediation"] == "start_ollama"
    for key in REPORT_CONTRACT_KEYS:
        assert key in report


def test_runner_path_labels_a_bedrock_fallback(monkeypatch, no_credentials):
    """Bedrock requested, unreachable, fallback allowed: labelled, never claimed."""
    monkeypatch.setenv("AI_DOCTOR_AGENT_MODE", "bedrock")
    monkeypatch.setenv("AI_DOCTOR_AWS_REGION", "us-east-1")
    monkeypatch.setenv("AI_DOCTOR_BEDROCK_MODEL_ID", "anthropic.claude-3-5-haiku-20241022-v1:0")

    report = doctor_runner.diagnose_incident(INCIDENT, DETERMINISTIC_EVIDENCE, "boom", "inc-fb")
    assert report["agent_mode"] == MODE_DETERMINISTIC
    assert report["agent_status"] == STATUS_FALLBACK_DETERMINISTIC
    assert report["used_llm"] is False
    assert report["bedrock_failure"]["error_class"] == "NoCredentialsError"
    # The offline engine's real conclusion is still delivered - just not credited
    # to a model.
    assert report["recommended_remediation"] == "start_ollama"


def test_unreachable_endpoint_is_reported_as_unreachable(no_credentials, monkeypatch):
    """
    Credentials present but the endpoint unroutable: a different error class, and
    still no bedrock attribution.
    """
    from botocore.exceptions import EndpointConnectionError

    # Built from pieces at runtime so the source never contains a complete AWS
    # access-key-ID pattern. A fixture that looks like a real key is both a
    # scanner magnet and the habit that eventually leaks one; boto3 only needs
    # *something* present to get past the credential chain.
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA" + "TESTONLY" + "00000000")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-only-not-a-real-secret-value")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

    transport = FakeBedrockTransport(
        error=EndpointConnectionError(endpoint_url="https://bedrock-runtime.us-east-1.amazonaws.com")
    )
    with pytest.raises(BedrockUnavailableError) as exc:
        make_transport_agent(bedrock_config(), transport).diagnose(
            INCIDENT, DOWN_EVIDENCE, BASELINE, "inc-unreachable"
        )
    assert exc.value.error_class == "EndpointConnectionError"
    assert "could not be reached" in str(exc.value)


# Every documented error of BedrockRuntime.Converse, verified against the service
# model shipped with the installed botocore, plus the botocore/credential classes
# that can fail the call before or instead of a service response.
#
# (AWS failure, message, stable machine-readable kind, human fragment)
#
# The kind is what a dashboard branches on; the fragment is what an operator
# reads. Both are asserted, because a message alone cannot be acted on by code
# and a code alone cannot be acted on by a human.
AWS_FAILURE_CASES = [
    # --- the nine documented Converse errors (HTTP status in the comment) ------
    ("AccessDeniedException", "not authorised",           # 403
     FAILURE_ACCESS_DENIED, "bedrock:InvokeModelWithResponseStream"),
    ("InternalServerException", "internal error",         # 500
     FAILURE_SERVICE_UNAVAILABLE, "could not serve model"),
    ("ModelErrorException", "model errored",              # 424
     FAILURE_SERVICE_UNAVAILABLE, "could not serve model"),
    ("ModelNotReadyException", "still onboarding",        # 429
     FAILURE_SERVICE_UNAVAILABLE, "retry after a short backoff"),
    ("ModelTimeoutException", "model timed out",          # 408
     FAILURE_TIMEOUT, "AI_DOCTOR_AGENT_TIMEOUT_SECONDS"),
    ("ResourceNotFoundException", "no such model here",   # 404
     FAILURE_INVALID_MODEL, "AI_DOCTOR_BEDROCK_MODEL_ID"),
    ("ServiceUnavailableException", "try later",          # 503
     FAILURE_SERVICE_UNAVAILABLE, "retry after a short backoff"),
    # Strands re-raises Bedrock throttling as ModelThrottledException once the
    # bounded retry budget is spent. The AWS code must still be recoverable from
    # the chain - see test_a_strands_wrapper_does_not_erase_the_aws_error_code.
    ("ThrottlingException", "rate exceeded",              # 429
     FAILURE_THROTTLED, "throttled"),
    ("ValidationException", "bad request shape",          # 400
     FAILURE_VALIDATION_ERROR, "Bedrock rejected the request"),
    # A ValidationException about the model id is an operator-fixable config bug,
    # not a generic 400.
    ("ValidationException", "The provided model identifier is invalid",
     FAILURE_INVALID_MODEL, "is not valid or not enabled"),
    # --- credential problems raised by botocore itself, never a service code ---
    ("NoCredentialsError", "Unable to locate credentials",
     FAILURE_NO_CREDENTIALS, "No AWS credentials were found"),
    ("PartialCredentialsError", "Incomplete credentials",
     FAILURE_PARTIAL_CREDENTIALS, "incomplete credential set"),
    # --- AWS-wide SigV4/STS rejections that can precede any Bedrock response ---
    ("ExpiredToken", "token expired",
     FAILURE_ACCESS_DENIED, "bedrock:InvokeModelWithResponseStream"),
    ("SignatureDoesNotMatch", "bad signature",
     FAILURE_ACCESS_DENIED, "bedrock:InvokeModelWithResponseStream"),
]

# Codes botocore carries in the ClientError payload rather than as a Python class.
_BOTOCORE_CODED = {case[0] for case in AWS_FAILURE_CASES} - {
    "NoCredentialsError", "PartialCredentialsError"}


@pytest.mark.parametrize(
    "error_class,message,expected_kind,expected_fragment", AWS_FAILURE_CASES,
    ids=[case[2] + ":" + case[0] + ":" + case[1][:12].replace(" ", "_") for case in AWS_FAILURE_CASES],
)
def test_aws_failures_are_classified_and_translated(error_class, message, expected_kind,
                                                    expected_fragment):
    """
    "The model failed" is not something an operator can act on, and "AWS_ERROR" is
    not something a dashboard can branch on. Every real AWS failure must produce
    BOTH a stable machine-readable kind AND a message naming the fix.
    """
    if error_class in _BOTOCORE_CODED:
        from botocore.exceptions import ClientError

        exc = ClientError({"Error": {"Code": error_class, "Message": message}}, "Converse")
    else:
        # botocore raises these as real exception classes, not as ClientError.
        exc = type(error_class, (Exception,), {})(message)

    agent = make_transport_agent(bedrock_config(), FakeBedrockTransport(error=exc))
    with pytest.raises(BedrockUnavailableError) as raised:
        agent.diagnose(INCIDENT, DOWN_EVIDENCE, BASELINE, "inc-translate")

    failure = raised.value
    # Machine-readable: a stable, published kind; the AWS code preserved not lost.
    assert failure.failure_kind == expected_kind
    assert failure.failure_kind in FAILURE_KINDS
    assert failure.as_record()["failure_kind"] == expected_kind
    if error_class in _BOTOCORE_CODED:
        assert failure.aws_error_code == error_class, "the AWS code must survive"
        assert failure.error_class == error_class
    # Human-readable: names the fix.
    assert expected_fragment in str(failure), str(failure)
    # And nothing in any of it may carry the secret-bearing message text unredacted.
    assert "AKIA" not in str(failure)


def test_a_strands_wrapper_does_not_erase_the_aws_error_code():
    """
    Strands re-raises some Bedrock errors as its own exception types. If we read
    only the outermost exception, the AWS service code is lost and the incident
    record can no longer be cross-referenced against CloudTrail. The chain must be
    walked - but only for the code, never to override what the wrapper means.
    """
    from botocore.exceptions import ClientError

    inner = ClientError({"Error": {"Code": "ThrottlingException", "Message": "rate"}}, "Converse")
    try:
        raise ClientError({"Error": {"Code": "ThrottlingException", "Message": "rate"}}, "Converse") from inner
    except Exception as wrapped:  # noqa: BLE001 - the point is the chain
        agent = make_transport_agent(bedrock_config(), FakeBedrockTransport(error=wrapped))
        with pytest.raises(BedrockUnavailableError) as raised:
            agent.diagnose(INCIDENT, DOWN_EVIDENCE, BASELINE, "inc-chain")

    assert raised.value.failure_kind == FAILURE_THROTTLED
    assert raised.value.aws_error_code == "ThrottlingException"


def test_a_schema_refusal_is_never_relabelled_as_an_aws_validation_error():
    """
    Precedence guard. `StructuredOutputException` means the model answered in the
    wrong shape - a real round trip happened. Even with an AWS-looking error in its
    chain, the kind must stay SCHEMA_REFUSED, otherwise the incident would claim an
    outage where a model reply actually arrived.
    """
    from botocore.exceptions import ClientError

    inner = ClientError({"Error": {"Code": "ValidationException", "Message": "x"}}, "Converse")
    try:
        raise type("StructuredOutputException", (Exception,), {})("bad shape") from inner
    except Exception as wrapped:  # noqa: BLE001
        agent = make_transport_agent(bedrock_config(), FakeBedrockTransport(error=wrapped))
        with pytest.raises(BedrockUnavailableError) as raised:
            agent.diagnose(INCIDENT, DOWN_EVIDENCE, BASELINE, "inc-precedence")

    assert raised.value.failure_kind == FAILURE_SCHEMA_REFUSED
    assert raised.value.aws_error_code == "ValidationException", "the code is still recorded"


def test_an_unrecognised_aws_code_is_named_not_collapsed():
    """
    AWS adds error codes without asking. An unrecognised code must still be
    classified (UNKNOWN_AWS_ERROR), must still carry the original code so nothing
    is lost, and must still produce a readable message. Collapsing every surprise
    into one opaque "AWS error" is exactly the failure mode this prevents.
    """
    from botocore.exceptions import ClientError

    code = "SomeBrandNewBedrockCode"
    exc = ClientError({"Error": {"Code": code, "Message": "the future"}}, "Converse")
    agent = make_transport_agent(bedrock_config(), FakeBedrockTransport(error=exc))
    with pytest.raises(BedrockUnavailableError) as raised:
        agent.diagnose(INCIDENT, DOWN_EVIDENCE, BASELINE, "inc-new-code")

    failure = raised.value
    assert failure.failure_kind == FAILURE_UNKNOWN
    assert failure.aws_error_code == code, "the original AWS code must survive classification"
    assert code in str(failure), "and must be visible to the operator"


# =========================================================================
# The invariant that ties it together
# =========================================================================


@pytest.mark.parametrize("mode", [MODE_DETERMINISTIC, MODE_BEDROCK])
def test_agent_mode_bedrock_only_ever_appears_with_a_real_model_call(mode, no_credentials):
    """
    The single most important assertion in this file. Across both configured
    modes, in an environment where Bedrock cannot be reached, no outcome may
    present itself as a model diagnosis.
    """
    config = AgentConfig(mode=mode) if mode == MODE_DETERMINISTIC else bedrock_config()
    outcome = run_diagnosis(INCIDENT, DETERMINISTIC_EVIDENCE, "inc-invariant", config=config)

    if outcome.telemetry.agent_mode == MODE_BEDROCK:
        assert outcome.used_llm or outcome.diagnosis_outcome == "FAILED"
        assert outcome.bedrock_failure is not None or outcome.telemetry.model_id
        # used_llm is only ever true with a real round trip behind it.
        assert not outcome.used_llm or outcome.bedrock_invoked
    else:
        assert outcome.used_llm is False
        assert outcome.telemetry.model_id is None


def test_report_contract_is_complete_in_every_mode(no_credentials):
    for config in (AgentConfig(mode=MODE_DETERMINISTIC), bedrock_config(), bedrock_config(fallback="fail")):
        outcome = run_diagnosis(INCIDENT, DETERMINISTIC_EVIDENCE, "inc-contract", config=config)
        for key in REPORT_CONTRACT_KEYS:
            assert key in outcome.report, f"{config.mode}/{config.fallback} omitted {key}"
        assert outcome.report["agent_mode"] in (MODE_BEDROCK, MODE_DETERMINISTIC, MODE_OPENROUTER)


def test_telemetry_is_persistable_on_an_incident(no_credentials):
    """Requirement 12: the Incident record carries the agent telemetry."""
    outcome = run_diagnosis(INCIDENT, DETERMINISTIC_EVIDENCE, "inc-persist", config=bedrock_config())
    incident = Incident(
        detected_error=INCIDENT["detected_error"],
        agent_mode=outcome.agent_mode,
        agent_status=outcome.status,
        agent_note=outcome.report.get("agent_note"),
        model_id=outcome.telemetry.model_id,
        aws_region=outcome.telemetry.aws_region,
        agent_latency_ms=outcome.telemetry.agent_latency_ms,
        diagnosis_confidence=outcome.telemetry.diagnosis_confidence,
        agent_telemetry=outcome.telemetry.as_dict(),
        bedrock_failure=outcome.bedrock_failure,
    )
    saved = incident.model_dump()
    assert saved["agent_mode"] == MODE_DETERMINISTIC
    assert saved["agent_status"] == STATUS_FALLBACK_DETERMINISTIC
    assert saved["model_id"] is None
    assert saved["bedrock_failure"]["error_class"] == "NoCredentialsError"
    assert saved["agent_telemetry"]["agent_mode"] == MODE_DETERMINISTIC


# =========================================================================
# /api/system-status
# =========================================================================


def test_describe_agent_reports_the_configured_mode():
    described = describe_agent(AgentConfig(mode=MODE_DETERMINISTIC))
    assert described["agent_mode"] == MODE_DETERMINISTIC
    assert described["mode_uses_llm"] is False
    assert described["llm_operational"] is False
    assert described["model_id"] is None
    assert any("deterministic offline mode" in w for w in described["warnings"])


def test_describe_agent_warns_when_bedrock_cannot_work(no_credentials):
    described = describe_agent(bedrock_config())
    assert described["agent_mode"] == MODE_BEDROCK
    assert described["mode_uses_llm"] is True
    # Configured, but no credential source: the dashboard must not imply a model
    # is answering.
    assert described["llm_operational"] is False
    assert described["credential_sources"] == []
    assert any("no AWS credential source" in w for w in described["warnings"])
    assert described["model_id"] == bedrock_config().model_id
    assert described["aws_region"] == bedrock_config().aws_region


def test_describe_agent_reports_a_broken_configuration(monkeypatch):
    """
    A typo'd mode must surface as a broken configuration, not as a silently
    working deterministic engine.
    """
    monkeypatch.setenv("AI_DOCTOR_AGENT_MODE", "gpt")
    broken = describe_agent()
    assert broken["configured"] is False
    assert broken["agent_mode"] is None
    assert broken["llm_operational"] is False
    assert "AI_DOCTOR_AGENT_MODE" in broken["warnings"][0]


def test_system_status_endpoint_exposes_the_agent_block():
    from fastapi.testclient import TestClient

    from backend.main import app

    payload = TestClient(app).get("/api/system-status").json()
    assert "agent" in payload
    agent = payload["agent"]
    assert agent["agent_mode"] in (MODE_BEDROCK, MODE_DETERMINISTIC, MODE_OPENROUTER)
    assert "llm_operational" in agent and "mode_uses_llm" in agent
    assert "warnings" in agent
    # Configuration state only - never a credential value.
    assert "aws_secret_access_key" not in str(agent).lower()
    assert "AKIA" not in str(agent)
