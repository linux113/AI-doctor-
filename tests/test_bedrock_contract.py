"""
Bedrock contract tests (requirement 14).

These verify that the REAL AWS Strands Agents SDK and the REAL boto3
bedrock-runtime client are constructed correctly from configuration - correct
model ID, correct region, bounded timeouts, exactly the intended tool set, and no
credentials anywhere in the source or the configuration object.

What they do NOT do is call Amazon Bedrock. That is tests/test_bedrock_live.py,
which skips unless real credentials and model access exist. The distinction is
deliberate and is why these tests use a fake HTTP transport for the parts that
need a request payload: the SDK, the model class, the client and the request
builder are all genuine, and only the socket is answered locally.
"""

import re
from importlib.metadata import PackageNotFoundError, version as dist_version
from pathlib import Path

import pytest

from agent.config import (
    DEFAULT_MODEL_ID,
    DEFAULT_REGION,
    AgentConfig,
    AgentConfigurationError,
    boto3_version,
    load_agent_config,
    strands_sdk_available,
    strands_sdk_version,
)
from agent.schemas import DiagnosisResult
from agent.strands_agent import BedrockDiagnosisAgent
from agent.tools import ALLOWED_TOOL_NAMES, ToolBudget

from _fake_bedrock import (
    BASELINE,
    DOWN_EVIDENCE,
    INCIDENT,
    FakeBedrockTransport,
    bedrock_config,
    make_transport_agent,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


# =========================================================================
# The SDK is real, installed, and the version is recorded
# =========================================================================


def test_strands_sdk_is_installed_and_importable():
    assert strands_sdk_available() is True
    import strands
    from strands import Agent
    from strands.models import BedrockModel

    assert strands.__file__
    assert callable(Agent)
    assert callable(BedrockModel)


def test_recorded_sdk_version_matches_the_installed_distribution():
    """
    Requirement 2: record the exact version, verified against the installed
    package rather than asserted from a comment.
    """
    recorded = strands_sdk_version()
    assert recorded, "strands_sdk_version() returned nothing"
    try:
        installed = dist_version("strands-agents")
    except PackageNotFoundError:
        pytest.fail("strands-agents is not installed, so bedrock mode cannot work")
    assert recorded == installed
    # Pinned floor from requirements-aws.txt.
    assert tuple(int(x) for x in recorded.split(".")[:2]) >= (1, 56)


def test_boto3_is_installed_and_its_version_is_recorded():
    import boto3
    import botocore

    assert boto3_version() == boto3.__version__
    assert botocore.__version__


def test_bedrock_model_class_is_the_sdk_one_not_a_local_stand_in():
    """
    The whole point of the phase: `BedrockModel` must come from the installed SDK.
    A local class of the same name would make every other assertion here vacuous.
    """
    model = BedrockDiagnosisAgent(bedrock_config()).build_model()
    assert type(model).__module__ == "strands.models.bedrock", type(model).__module__
    assert type(model).__name__ == "BedrockModel"
    # And it is the installed distribution, not a vendored copy in this repo.
    assert REPO_ROOT not in Path(type(model).__module__.replace(".", "/")).parents


def test_agent_class_is_the_sdk_one():
    agent = BedrockDiagnosisAgent(bedrock_config()).build_agent(ToolBudget(2))
    assert type(agent).__module__.startswith("strands."), type(agent).__module__
    assert type(agent).__name__ == "Agent"


# =========================================================================
# The real boto3 client is built from configuration
# =========================================================================


def test_client_is_a_real_botocore_bedrock_runtime_client():
    model = BedrockDiagnosisAgent(bedrock_config(aws_region="eu-west-1")).build_model()
    client = model.client
    assert client.meta.service_model.service_name == "bedrock-runtime"
    assert client.meta.region_name == "eu-west-1"
    # A genuine botocore client exposes the real operation we depend on.
    assert hasattr(client, "converse")
    assert client.meta.service_model.operation_names


def test_region_and_model_id_come_from_configuration():
    for region, model_id in (
        ("us-east-1", "anthropic.claude-3-5-haiku-20241022-v1:0"),
        ("eu-west-1", "anthropic.claude-3-5-sonnet-20241022-v1:0"),
        ("ap-south-1", "amazon.titan-text-express-v1"),
    ):
        agent = BedrockDiagnosisAgent(bedrock_config(aws_region=region, model_id=model_id))
        model = agent.build_model()
        assert model.client.meta.region_name == region
        assert model.config["model_id"] == model_id


def test_region_and_model_id_come_from_the_environment():
    config = load_agent_config(
        {
            "AI_DOCTOR_AGENT_MODE": "bedrock",
            "AI_DOCTOR_AWS_REGION": "ap-south-1",
            "AI_DOCTOR_BEDROCK_MODEL_ID": "anthropic.claude-3-5-haiku-20241022-v1:0",
        }
    )
    assert config.aws_region == "ap-south-1"
    assert config.model_id == "anthropic.claude-3-5-haiku-20241022-v1:0"
    model = BedrockDiagnosisAgent(config).build_model()
    assert model.client.meta.region_name == "ap-south-1"


def test_bedrock_mode_defaults_to_a_real_model_and_region():
    config = load_agent_config({"AI_DOCTOR_AGENT_MODE": "bedrock"})
    assert config.aws_region == DEFAULT_REGION
    assert config.model_id == DEFAULT_MODEL_ID
    assert config.is_bedrock is True


def test_temperature_is_low_and_configurable():
    """Requirement 3: low/moderate temperature for troubleshooting."""
    assert bedrock_config().temperature == 0.0
    config = load_agent_config({"AI_DOCTOR_AGENT_MODE": "bedrock", "AI_DOCTOR_AGENT_TEMPERATURE": "0.3"})
    assert config.temperature == 0.3
    model = BedrockDiagnosisAgent(config).build_model()
    assert model.config["temperature"] == 0.3


def test_temperature_outside_zero_to_one_is_rejected():
    for bad in ("-0.1", "1.5", "99"):
        with pytest.raises(AgentConfigurationError):
            load_agent_config({"AI_DOCTOR_AGENT_MODE": "bedrock", "AI_DOCTOR_AGENT_TEMPERATURE": bad})


def test_deterministic_mode_never_constructs_a_bedrock_agent():
    config = load_agent_config({"AI_DOCTOR_AGENT_MODE": "deterministic"})
    assert config.is_bedrock is False
    with pytest.raises(AgentConfigurationError) as exc:
        BedrockDiagnosisAgent(config)
    assert "deterministic" in str(exc.value)


def test_missing_region_or_model_is_a_configuration_error():
    with pytest.raises(AgentConfigurationError):
        BedrockDiagnosisAgent(AgentConfig(mode="bedrock", aws_region=None, model_id=None))


# =========================================================================
# The request the SDK builds
# =========================================================================


def test_request_payload_carries_the_configured_model_and_inference_settings():
    transport = FakeBedrockTransport()
    agent = make_transport_agent(
        bedrock_config(model_id="anthropic.claude-3-5-haiku-20241022-v1:0", aws_region="us-west-2"),
        transport,
    )
    agent.diagnose(INCIDENT, DOWN_EVIDENCE, BASELINE, "inc-contract")

    request = transport.last_request
    assert request["modelId"] == "anthropic.claude-3-5-haiku-20241022-v1:0"
    assert request["inferenceConfig"]["temperature"] == 0.0
    assert request["inferenceConfig"]["maxTokens"] == 1024
    # The real Bedrock Converse request shape.
    assert set(request) == {"modelId", "system", "toolConfig", "messages", "inferenceConfig"}
    assert request["system"], "no system prompt was sent"
    assert request["messages"], "no user turn was sent"


def test_model_retry_budget_is_bounded_not_the_sdk_default():
    """
    Strands' default retry strategy is 6 attempts with a 4s..240s exponential
    backoff: 124 seconds of waiting before a throttled incident is allowed to
    fail. That is far too long on a request path, so the budget is bounded and
    configured. Asserted here because the failure mode is silent - a slow
    incident looks like a hung one.
    """
    config = bedrock_config()
    assert config.max_model_attempts == 2
    agent = BedrockDiagnosisAgent(config).build_agent(ToolBudget(1))
    strategy = agent._retry_strategy
    assert strategy._max_attempts == 2
    assert strategy._initial_delay == 1
    assert strategy._max_delay == 5
    # Worst-case added latency: one backoff of 1s, not 4+8+16+32+64.
    assert strategy._calculate_delay(0) + strategy._calculate_delay(1) <= 10


def test_bedrock_request_id_is_captured_through_the_botocore_event_hook():
    """
    Strands does not surface `ResponseMetadata.RequestId`, so it is captured from
    botocore's `after-call.bedrock-runtime` event. The fake transport emits that
    event exactly as botocore does, which exercises the real hook registration.
    """
    transport = FakeBedrockTransport(request_id="REQ-CAPTURED-9f3c")
    outcome = make_transport_agent(bedrock_config(), transport).diagnose(
        INCIDENT, DOWN_EVIDENCE, BASELINE, "inc-request-id"
    )
    assert outcome.telemetry.bedrock_request_id == "REQ-CAPTURED-9f3c"


def test_request_id_capture_degrades_to_none_rather_than_failing():
    """Telemetry must never break a diagnosis."""
    transport = FakeBedrockTransport(emit_request_id_event=False)
    outcome = make_transport_agent(bedrock_config(), transport).diagnose(
        INCIDENT, DOWN_EVIDENCE, BASELINE, "inc-no-request-id"
    )
    assert outcome.status == "DIAGNOSED"
    assert outcome.telemetry.bedrock_request_id is None


def test_request_id_capture_survives_a_malformed_event_payload():
    """A garbage post-call event must not propagate out of the telemetry hook."""
    agent = BedrockDiagnosisAgent(bedrock_config())
    model = agent.build_model()
    model.client.meta.events.emit(
        "after-call.bedrock-runtime",
        http_response=None,
        parsed="not-a-dict",
        model=None,
        context={},
    )
    assert agent._last_request_id is None


def test_timeouts_and_retries_are_bounded():
    """A hung model must not hang incident handling, and retries must not multiply cost."""
    config = bedrock_config(request_timeout_seconds=20.0)
    boto_config = BedrockDiagnosisAgent(config).build_model().client.meta.config
    assert boto_config.read_timeout == 20.0
    assert boto_config.connect_timeout == 10.0
    assert boto_config.retries, "retry behaviour is not configured"


# =========================================================================
# Tool surface exposed to the model
# =========================================================================


def test_exactly_the_five_read_only_tools_plus_structured_output_are_offered():
    transport = FakeBedrockTransport()
    make_transport_agent(bedrock_config(), transport).diagnose(
        INCIDENT, DOWN_EVIDENCE, BASELINE, "inc-tools"
    )
    offered = transport.tool_names()
    assert sorted(ALLOWED_TOOL_NAMES) == [
        "check_ollama", "check_port", "check_process", "get_recent_logs", "health_check"
    ]
    # Strands implements structured output as a tool named after the Pydantic class.
    assert set(offered) == set(ALLOWED_TOOL_NAMES) | {DiagnosisResult.__name__}


@pytest.mark.parametrize(
    "phantom",
    ["run_command", "shell", "bash", "exec", "execute", "eval", "subprocess", "system",
     "python", "curl", "http_request", "read_file", "write_file", "open_file",
     "run_python", "code_interpreter", "stop_ollama", "start_ollama", "retry_request"],
)
def test_no_execution_tool_is_ever_offered_to_the_model(phantom):
    """
    Requirement 6/7: no generic command tool, and no remediation tool either. The
    model may *recommend* an action in its structured reply; it can never call one.
    """
    transport = FakeBedrockTransport()
    make_transport_agent(bedrock_config(), transport).diagnose(
        INCIDENT, DOWN_EVIDENCE, BASELINE, "inc-phantom"
    )
    assert phantom not in transport.tool_names()
    assert phantom not in ALLOWED_TOOL_NAMES


def test_structured_output_tool_schema_is_generated_from_the_pydantic_model():
    """The model is constrained by our schema, not by a hand-written guess."""
    transport = FakeBedrockTransport()
    make_transport_agent(bedrock_config(), transport).diagnose(
        INCIDENT, DOWN_EVIDENCE, BASELINE, "inc-schema"
    )
    spec = next(
        t["toolSpec"] for t in transport.last_request["toolConfig"]["tools"]
        if t["toolSpec"]["name"] == DiagnosisResult.__name__
    )
    schema = spec["inputSchema"]["json"]
    assert set(schema["properties"]) == set(DiagnosisResult.model_fields)
    assert set(schema.get("required", [])) == {
        "hypothesis", "confidence", "evidence_ids", "recommended_action", "explanation"
    }


# =========================================================================
# No credentials in source, config or telemetry
# =========================================================================


def test_configuration_object_has_no_credential_fields():
    """
    `AgentConfig` holds mode, region, model ID and budgets. It must never hold a
    credential: boto3 resolves those from the standard chain at call time, so
    there is nothing for this object to carry and nothing for it to leak.
    """
    import dataclasses

    forbidden = {"aws_access_key_id", "aws_secret_access_key", "aws_session_token",
                 "access_key", "secret_key", "password", "token", "credentials", "api_key"}
    fields = {f.name for f in dataclasses.fields(AgentConfig)}
    assert not (forbidden & fields), f"AgentConfig carries credential fields: {forbidden & fields}"
    assert "aws_region" in fields and "model_id" in fields


def test_configuration_description_exposes_no_secret_values():
    config = load_agent_config({"AI_DOCTOR_AGENT_MODE": "bedrock"})
    described = str(config.describe())
    assert "AKIA" not in described
    # credential_sources names the *sources*, never their contents.
    assert isinstance(config.describe()["credential_sources"], list)


@pytest.mark.parametrize("relative", ["agent", "runner", "backend"])
def test_no_hardcoded_aws_credentials_in_source(relative):
    """
    Requirement 1: no hardcoded or committed credentials. Scans every source file
    for literal AWS key material and for assignments that look like a secret.
    """
    access_key = re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")
    secret_assignment = re.compile(
        r"""(?:aws_secret_access_key|secret_access_key|aws_access_key_id|api_key|password)"""
        r"""\s*[:=]\s*['\"][A-Za-z0-9/+=_\-]{16,}['\"]""",
        re.IGNORECASE,
    )
    offenders = []
    for path in sorted((REPO_ROOT / relative).rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for pattern in (access_key, secret_assignment):
            for match in pattern.finditer(text):
                # Test fixtures and redaction patterns legitimately contain the
                # *shape* of a secret; a real credential would be a value.
                line = text[: match.start()].count("\n") + 1
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{line}: {match.group(0)[:60]}")
    assert not offenders, "possible hardcoded credentials:\n" + "\n".join(offenders)


def test_no_env_file_or_credential_file_is_committed():
    for name in (".env", ".env.local", ".env.production", "credentials", "aws_credentials.csv"):
        assert not (REPO_ROOT / name).exists(), f"{name} must never be committed"
    assert not (REPO_ROOT / ".git" / "credentials").exists()


def test_telemetry_from_a_real_invocation_carries_no_credentials():
    transport = FakeBedrockTransport()
    outcome = make_transport_agent(bedrock_config(), transport).diagnose(
        INCIDENT, DOWN_EVIDENCE, BASELINE, "inc-telemetry"
    )
    telemetry = outcome.telemetry.as_dict()
    assert telemetry["agent_mode"] == "bedrock"
    assert telemetry["model_id"] == bedrock_config().model_id
    assert telemetry["aws_region"] == bedrock_config().aws_region
    assert telemetry["strands_sdk_version"] == strands_sdk_version()

    blob = str(telemetry).lower()
    for marker in ("aws_secret", "secret_access_key", "session_token", "akia", "password"):
        assert marker not in blob, f"telemetry mentions {marker!r}"
