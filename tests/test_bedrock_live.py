"""
LIVE Amazon Bedrock tests (requirement 14).

These are the only tests in the suite that make a real, billable AWS call. They
are opt-in on purpose: a normal `pytest` run must not spend money, hit the
network, or fail because the machine has no credentials.

To run them:

    pip install -r requirements-aws.txt
    export AWS_REGION=us-east-1                      # or AWS_DEFAULT_REGION
    export AI_DOCTOR_AGENT_MODE=bedrock
    export AI_DOCTOR_AWS_REGION=us-east-1
    export AI_DOCTOR_BEDROCK_MODEL_ID=anthropic.claude-3-5-haiku-20241022-v1:0
    export AI_DOCTOR_RUN_LIVE_BEDROCK=1
    pytest tests/test_bedrock_live.py -v

Credentials come from the standard boto3 chain (environment, shared config, IAM
role, IMDS). Nothing is read from source, and nothing is committed.

Why the assertions look the way they do
---------------------------------------
A real Bedrock call must be *visibly distinguishable* from a deterministic
offline run and from a fake-transport contract test. Three things are only true
after a genuine AWS round trip:

    bedrock_request_id   assigned by the service, echoed from ResponseMetadata
    total_tokens > 0     billed usage reported by the model
    agent_latency_ms     wall time of a real network call

`tests/test_bedrock_contract.py` asserts the same telemetry is None/absent when
the transport is faked, so the two cannot be confused - and
`test_live_markers_are_absent_without_a_real_call` below pins that explicitly in
an environment with no credentials.
"""

import os
import uuid

import pytest

from agent.config import (
    MODE_BEDROCK,
    AgentConfig,
    credential_source_hint,
    load_agent_config,
    strands_sdk_available,
)
from agent.schemas import DiagnosisResult
from agent.strands_agent import BedrockDiagnosisAgent, BedrockUnavailableError
from runner.remediation_registry import REMEDIATION_ALLOWLIST

from _fake_bedrock import (
    BASELINE,
    DOWN_EVIDENCE,
    INCIDENT,
    FakeBedrockTransport,
    bedrock_config,
    make_transport_agent,
)


def live_opt_in() -> str:
    """Truthy only when the operator explicitly asked for a real, billable call."""
    return os.environ.get("AI_DOCTOR_RUN_LIVE_BEDROCK", "").strip().lower() in ("1", "true", "yes", "on")


def live_skip_reason() -> str:
    """
    Returns why a live call cannot be made, or "" when it can.

    Every branch names the missing prerequisite so a skip is actionable rather
    than mysterious.
    """
    if not live_opt_in():
        return (
            "live Bedrock call not requested: set AI_DOCTOR_RUN_LIVE_BEDROCK=1 "
            "(this test makes a real, billable AWS call)"
        )
    if not strands_sdk_available():
        return "the AWS Strands Agents SDK is not installed (pip install -r requirements-aws.txt)"
    if not credential_source_hint():
        return (
            "no AWS credential source was found in the default chain (environment, "
            "shared config, IAM role, IMDS)"
        )
    return ""


@pytest.fixture(scope="module")
def live_config() -> AgentConfig:
    """The operator's real configuration, or a skip naming what is missing."""
    reason = live_skip_reason()
    if reason:
        pytest.skip(reason)
    config = load_agent_config()
    if not config.is_bedrock:
        pytest.skip(
            "AI_DOCTOR_AGENT_MODE is not 'bedrock'; a live model test is meaningless "
            "in deterministic mode"
        )
    return config


# =========================================================================
# The live path
# =========================================================================


def test_live_bedrock_returns_a_real_structured_diagnosis(live_config):
    """
    A genuine end-to-end invocation: real credentials, real endpoint, real model,
    real structured output.
    """
    agent = BedrockDiagnosisAgent(live_config)
    result = agent.diagnose(INCIDENT, DOWN_EVIDENCE, BASELINE, "inc-live")

    # --- proof a real AWS round trip happened -----------------------------
    assert result.telemetry.bedrock_request_id, (
        "no Bedrock request ID: the service was never reached, so this is not a live result"
    )
    # Service-assigned request IDs are UUID-shaped; assert the shape without
    # making the test brittle if AWS ever changes the format.
    request_id = result.telemetry.bedrock_request_id
    assert len(request_id) >= 8 and " " not in request_id
    assert not request_id.startswith("REQ-fake"), "a fabricated request ID was reported"
    try:
        uuid.UUID(request_id)
    except ValueError:
        pass  # unusual but service-assigned; the assertions above are the point
    assert (result.telemetry.total_tokens or 0) > 0, "the model reported no token usage"
    assert (result.telemetry.input_tokens or 0) > 0
    assert (result.telemetry.output_tokens or 0) > 0
    assert result.telemetry.agent_latency_ms > 0
    assert result.telemetry.model_id == live_config.model_id
    assert result.telemetry.aws_region == live_config.aws_region
    assert result.telemetry.error_class is None

    # --- and the diagnosis itself is real, validated output ---------------
    assert result.telemetry.agent_mode == MODE_BEDROCK
    assert isinstance(result.structured, DiagnosisResult)
    assert result.status in ("DIAGNOSED", "REQUIRES_HUMAN")
    assert result.report["recommended_remediation"] in (set(REMEDIATION_ALLOWLIST) | {"none"})
    assert result.policy is not None
    assert 0.0 <= result.report["confidence"] <= 1.0
    assert result.report["explanation"]


def test_live_bedrock_request_used_the_configured_model_and_region(live_config):
    """The model ID and region are not hardcoded anywhere; they come from config."""
    model = BedrockDiagnosisAgent(live_config).build_model()
    assert model.config["model_id"] == live_config.model_id
    assert model.client.meta.region_name == live_config.aws_region
    assert model.client.meta.service_model.service_name == "bedrock-runtime"


def test_live_bedrock_tool_calls_are_real_and_bounded(live_config):
    """
    The agent may call the read-only tools mid-conversation. Whatever it calls,
    the budget must hold and only registered tools may appear in the metrics.
    """
    from agent.tools import ALLOWED_TOOL_NAMES

    agent = BedrockDiagnosisAgent(live_config)
    result = agent.diagnose(INCIDENT, DOWN_EVIDENCE, BASELINE, "inc-live-tools")

    called = set(result.telemetry.tool_calls or {})
    # The structured-output pseudo-tool is expected alongside any diagnostics.
    assert called <= set(ALLOWED_TOOL_NAMES) | {DiagnosisResult.__name__}, called
    assert result.telemetry.tool_call_count <= live_config.max_tool_calls + 1
    assert result.telemetry.turns <= live_config.max_turns + 1


# =========================================================================
# The distinction itself - always runs, no credentials needed
# =========================================================================


def test_live_markers_are_absent_without_a_real_call():
    """
    The inverse of the test above, and the one that runs in CI. With a faked
    transport there is no request ID and no billed usage, which is exactly how a
    reader tells a contract test from a live result.

    If this ever starts passing with a request ID present, something has begun
    fabricating service metadata.
    """
    transport = FakeBedrockTransport(emit_request_id_event=False)
    result = make_transport_agent(bedrock_config(), transport).diagnose(
        INCIDENT, DOWN_EVIDENCE, BASELINE, "inc-not-live"
    )
    assert result.telemetry.bedrock_request_id is None
    assert result.telemetry.agent_mode == MODE_BEDROCK


def test_deterministic_mode_never_produces_live_markers():
    """The offline engine cannot invent a request ID or token counts."""
    from agent.diagnosis_agent import run_diagnosis

    outcome = run_diagnosis(
        INCIDENT, DOWN_EVIDENCE, "inc-offline", config=AgentConfig(mode="deterministic")
    )
    telemetry = outcome.telemetry.as_dict()
    assert telemetry["bedrock_request_id"] is None
    assert telemetry["total_tokens"] is None
    assert telemetry["input_tokens"] is None
    assert telemetry["output_tokens"] is None
    assert telemetry["model_id"] is None
    assert outcome.used_llm is False


def test_a_real_call_without_credentials_fails_honestly(monkeypatch):
    """
    Always runs, on any machine, and never reaches the network: the credential
    chain is pinned empty, so a REAL boto3 resolution fails locally.

    This is the negative control for everything above. It is what makes an
    honest "Bedrock was not invoked" distinguishable from a fabricated success -
    the code path raises `BedrockUnavailableError` naming the real AWS error
    class instead of returning a plausible-looking diagnosis.
    """
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                 "AWS_SECURITY_TOKEN", "AWS_PROFILE", "AWS_ROLE_ARN",
                 "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
                 "AWS_CONTAINER_CREDENTIALS_FULL_URI"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent-aws-config")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent-aws-credentials")

    agent = BedrockDiagnosisAgent(bedrock_config())
    with pytest.raises(BedrockUnavailableError) as exc:
        agent.diagnose(INCIDENT, DOWN_EVIDENCE, BASELINE, "inc-no-creds")
    assert exc.value.error_class == "NoCredentialsError"
    assert "credentials" in str(exc.value).lower()
    assert "AI_DOCTOR_AGENT_MODE=deterministic" in str(exc.value)
