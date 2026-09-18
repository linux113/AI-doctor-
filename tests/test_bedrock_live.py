"""
LIVE Amazon Bedrock tests - suite C of the three separated end-to-end tests.

    A  tests/test_e2e_offline_deterministic.py   no AWS, no Ollama, runs in CI
    B  tests/test_bedrock_contract.py            real Agent + real BedrockModel,
                                                 only client.converse answered locally
    C  tests/test_bedrock_live.py  (THIS FILE)   a real, billable AWS request

This file makes the only real network calls in the suite, so it is opt-in: a
normal `pytest` run must not spend money, must not hit the network, and must not
fail because the machine has no credentials.

To run it:

    pip install -r requirements-aws.txt
    export AI_DOCTOR_AGENT_MODE=bedrock
    export AI_DOCTOR_AWS_REGION=us-east-1
    export AI_DOCTOR_BEDROCK_MODEL_ID=anthropic.claude-3-5-haiku-20241022-v1:0
    export AI_DOCTOR_RUN_LIVE_BEDROCK=1
    pytest tests/test_bedrock_live.py -v

Credentials come from the standard boto3 chain (environment, shared config, IAM
role, IMDS). Nothing is read from source and nothing is committed.

Fail, do not skip
-----------------
Once the operator has set `AI_DOCTOR_RUN_LIVE_BEDROCK=1`, a missing prerequisite
is a FAILED test, not a skip. A skipped live test is indistinguishable from a
live test that was never run, and that ambiguity is exactly how "we tested it
against real Bedrock" gets claimed without ever having happened. `pytest.fail`
names every unmet prerequisite at once so one run is enough to fix them all.

Only when the operator did NOT opt in is skipping correct: CI must stay free.

Nothing in this file may fake the transport
-------------------------------------------
This module deliberately does not import `tests/_fake_bedrock.py`, and
`test_this_module_never_fakes_the_transport` reads this file's own source to
enforce that. The live tests additionally assert that the client they used is a
genuine botocore client whose `converse` is botocore's own method, so a live
result cannot be produced by a stub even by accident.

How a real round trip is proved
-------------------------------
Three things are only true after a genuine AWS call:

    bedrock_request_id   assigned by the service, echoed from ResponseMetadata
    total_tokens > 0     billed usage reported by the model
    agent_latency_ms     wall time of a real network call

Suite B asserts the same telemetry is None when the transport is faked, so a
contract result and a live result cannot be confused - and the two always-run
negative controls at the bottom of this file pin that without credentials.
"""

import inspect
import os
import sys
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

LIVE_OPT_IN_ENV = "AI_DOCTOR_RUN_LIVE_BEDROCK"
TRUTHY = ("1", "true", "yes", "on")

# The incident/evidence used for a live diagnosis. Defined here rather than
# imported from the contract helpers, so this file cannot pull the fake transport
# in through a shared import.
LIVE_INCIDENT = {
    "incident_id": "inc-live",
    "failure_type": "service_down",
    "summary": "Ollama is not answering on 127.0.0.1:11434 during a live Bedrock test.",
    "detected_at": "2026-01-01T00:00:00Z",
}
LIVE_EVIDENCE = {
    "runtime_state": "DOWN",
    "probes": [
        {"id": "probe-http", "name": "http_get_api_tags", "ok": False,
         "detail": "connection refused on 127.0.0.1:11434"},
        {"id": "probe-process", "name": "process_lookup", "ok": False,
         "detail": "no ollama process found"},
    ],
    "logs": ["ollama serve exited with code 1"],
    "baseline": {"expected_runtime_state": "OLLAMA_RUNNING", "root_cause": "ollama_not_running"},
}
LIVE_BASELINE = {"expected_runtime_state": "OLLAMA_RUNNING", "root_cause": "ollama_not_running"}


def live_opt_in() -> bool:
    """Truthy only when the operator explicitly asked for a real, billable call."""
    return os.environ.get(LIVE_OPT_IN_ENV, "").strip().lower() in TRUTHY


def live_prerequisite_problems() -> list:
    """
    Every reason a live call cannot be made right now, as human-readable strings.

    Empty means "go ahead and call AWS". This is a pure function of the
    environment so it can be asserted in a test without spending money.
    """
    problems = []

    if not strands_sdk_available():
        problems.append(
            "the AWS Strands Agents SDK is not installed "
            "(pip install -r requirements-aws.txt)"
        )

    if not credential_source_hint():
        problems.append(
            "no AWS credential source was found in the default chain (environment, "
            "shared config, IAM role, IMDS) - a live Bedrock call cannot authenticate"
        )

    mode = (os.environ.get("AI_DOCTOR_AGENT_MODE") or "").strip().lower()
    if mode != MODE_BEDROCK:
        problems.append(
            f"AI_DOCTOR_AGENT_MODE is {mode or 'unset'!r}, not 'bedrock'; a live model "
            "test is meaningless in any other mode"
        )

    try:
        config = load_agent_config()
    except Exception as exc:  # noqa: BLE001 - any config error is a prerequisite failure
        problems.append(f"the agent configuration could not be loaded: {exc}")
        return problems

    if not config.aws_region:
        problems.append("AI_DOCTOR_AWS_REGION is not set")
    if not config.model_id:
        problems.append("AI_DOCTOR_BEDROCK_MODEL_ID is not set")
    return problems


def resolve_live_config() -> AgentConfig:
    """
    The operator's real configuration - or a failure naming what is missing.

    Skips only when the live call was never requested. Once it was requested,
    unmet prerequisites FAIL the test rather than hiding behind a skip.
    """
    if not live_opt_in():
        pytest.skip(
            f"live Bedrock call not requested: set {LIVE_OPT_IN_ENV}=1 "
            "(this test makes a real, billable AWS call)"
        )

    problems = live_prerequisite_problems()
    if problems:
        pytest.fail(
            f"{LIVE_OPT_IN_ENV}=1 was set, so a real Bedrock call was requested, but it "
            "cannot be made:\n  - " + "\n  - ".join(problems)
            + "\nA live test that skips here would be indistinguishable from one that "
            "never ran, which is how an unverified integration gets reported as tested."
        )

    config = load_agent_config()
    assert config.is_bedrock
    return config


# Module-scoped: one real configuration resolution for all the live tests.
live_config = pytest.fixture(scope="module")(resolve_live_config)


def _assert_real_botocore_transport(client) -> None:
    """
    Proves `client` is a genuine botocore client, not a test stub.

    Suite B swaps in a `_StubClient` whose `converse` is defined in
    `tests/_fake_bedrock.py`. Both discriminators are checked, because the point
    of a live test is that nothing between the agent and AWS is ours.
    """
    kind = type(client)
    assert kind.__name__ != "_StubClient", "the contract-test stub answered this call"
    assert kind.__module__ == "botocore.client", f"client class came from {kind.__module__}"
    converse = getattr(client, "converse", None)
    assert converse is not None, "the client has no converse method"
    module = getattr(converse, "__module__", "")
    assert module == "botocore.client", (
        f"client.converse is defined in {module or '<unknown>'}, not in botocore - "
        "the live test would be asserting against a mock"
    )
    assert "_fake_bedrock" not in str(inspect.getsourcefile(type(client)) or "")
    host = getattr(getattr(client, "_endpoint", None), "host", "") or ""
    assert host.startswith("https://bedrock-runtime."), f"unexpected endpoint {host!r}"


# =========================================================================
# The live path - runs only on explicit opt-in, and really calls AWS
# =========================================================================


def test_live_call_reaches_bedrock_through_the_real_transport(live_config):
    """
    The client the live call would use is a real botocore BedrockRuntime client
    pointed at the real regional endpoint, with botocore's own `converse`.
    """
    model = BedrockDiagnosisAgent(live_config).build_model()
    _assert_real_botocore_transport(model.client)
    assert model.config["model_id"] == live_config.model_id
    assert model.client.meta.region_name == live_config.aws_region
    assert model.client.meta.service_model.service_name == "bedrock-runtime"
    assert model.client._endpoint.host == (
        f"https://bedrock-runtime.{live_config.aws_region}.amazonaws.com"
    )


def test_live_bedrock_returns_a_real_structured_diagnosis(live_config):
    """
    A genuine end-to-end invocation: real credentials, real endpoint, real model,
    real structured output. Nothing in this path is ours to fake.
    """
    agent = BedrockDiagnosisAgent(live_config)
    model = agent.build_model()
    _assert_real_botocore_transport(model.client)

    result = agent.diagnose(LIVE_INCIDENT, LIVE_EVIDENCE, LIVE_BASELINE, "inc-live")

    # --- proof a real AWS round trip happened -----------------------------
    assert result.bedrock_status == "BEDROCK_SUCCESS", (
        f"the round trip did not succeed ({result.bedrock_status}); "
        f"failure_kind={result.telemetry.failure_kind}"
    )
    assert result.bedrock_invoked is True
    assert result.used_llm is True
    assert result.telemetry.bedrock_request_id, (
        "no Bedrock request ID: the service was never reached, so this is not a live result"
    )
    request_id = result.telemetry.bedrock_request_id
    # Service-assigned request IDs are UUID-shaped; assert the shape without
    # making the test brittle if AWS ever changes the format.
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
    assert result.telemetry.failure_kind is None, "a successful call has no failure kind"

    # --- and the diagnosis itself is real, validated output ---------------
    assert result.telemetry.agent_mode == MODE_BEDROCK
    assert isinstance(result.structured, DiagnosisResult)
    assert result.status in ("DIAGNOSED", "REQUIRES_HUMAN")
    assert result.report["recommended_remediation"] in (set(REMEDIATION_ALLOWLIST) | {"none"})
    assert result.policy is not None
    assert 0.0 <= result.report["confidence"] <= 1.0
    assert result.report["explanation"]

    # --- no secret may appear anywhere in what the call produced ----------
    from runner.redaction import sanitize_deep

    serialised = str(sanitize_deep(result.as_dict()))
    for marker in ("AKIA", "aws_secret_access_key", "AWS_SECRET_ACCESS_KEY", "session_token"):
        assert marker not in serialised, f"{marker} leaked into the live result"


def test_live_bedrock_tool_calls_are_real_and_bounded(live_config):
    """
    The agent may call the read-only tools mid-conversation. Whatever it calls,
    the budget must hold and only registered tools may appear in the metrics.
    """
    from agent.tools import ALLOWED_TOOL_NAMES

    agent = BedrockDiagnosisAgent(live_config)
    result = agent.diagnose(LIVE_INCIDENT, LIVE_EVIDENCE, LIVE_BASELINE, "inc-live-tools")

    called = set(result.telemetry.tool_calls or {})
    # The structured-output pseudo-tool is expected alongside any diagnostics.
    assert called <= set(ALLOWED_TOOL_NAMES) | {DiagnosisResult.__name__}, called
    assert result.telemetry.tool_call_count <= live_config.max_tool_calls + 1
    assert result.telemetry.turns <= live_config.max_turns + 1


# =========================================================================
# The distinction itself - always runs, no credentials, no network
# =========================================================================


FAKE_TRANSPORT_NAMES = ("FakeBedrockTransport", "make_transport_agent")


def test_this_module_never_fakes_the_transport():
    """
    Structural guarantee: this file must not import or call the contract-test fake.

    A live test that quietly used `FakeBedrockTransport` would report a green suite
    while never contacting AWS - the single most dangerous way this project could
    lie about itself. Parsing this module's own AST makes the rule self-enforcing
    rather than a matter of reviewer attention.

    The AST is used rather than a text search on purpose: the docstring above
    discusses the fake by name, and prose must not be able to trip the check (nor
    to hide a real call behind a comment).
    """
    import ast

    tree = ast.parse(inspect.getsource(sys.modules[__name__]))

    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")
    offending_imports = [name for name in imported if "_fake_bedrock" in name]
    assert not offending_imports, f"the live test imports the fake transport: {offending_imports}"

    referenced = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    referenced |= {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    offending_calls = sorted(referenced & set(FAKE_TRANSPORT_NAMES))
    assert not offending_calls, f"the live test uses the fake transport: {offending_calls}"

    # And no test here may patch the client method the live path depends on.
    patched = [node for node in ast.walk(tree)
               if isinstance(node, ast.Call)
               and "monkeypatch.setattr" in ast.unparse(node.func)]
    assert not patched, f"a live test monkeypatched an attribute: {patched}"


def test_opting_in_without_credentials_fails_rather_than_skipping(monkeypatch):
    """
    The behaviour the whole file depends on.

    With the opt-in set and no credential source available, the gate must FAIL -
    loudly, naming the missing prerequisite. If it skipped instead, an operator
    could run the "live" suite on a machine that cannot reach AWS and see the same
    green result as a genuine live run.
    """
    assert_no_credential_source(monkeypatch)
    monkeypatch.setenv(LIVE_OPT_IN_ENV, "1")
    monkeypatch.setenv("AI_DOCTOR_AGENT_MODE", "bedrock")

    problems = live_prerequisite_problems()
    assert any("credential" in problem for problem in problems), problems

    # The gate must raise a failure, not a skip.
    with pytest.raises(pytest.fail.Exception) as failed:
        resolve_live_config()
    message = str(failed.value)
    assert "cannot be made" in message
    assert "credential" in message
    assert LIVE_OPT_IN_ENV in message


def assert_no_credential_source(monkeypatch, tmp_home=None) -> None:
    """
    Pins every input `credential_source_hint()` reads to "nothing configured".

    `HOME` is redirected as well, because the hint also looks for `~/.aws/config`
    and `~/.aws/credentials`: on a developer machine that has them, a test that
    only cleared environment variables would prove nothing at all.
    """
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                 "AWS_SECURITY_TOKEN", "AWS_PROFILE", "AWS_ROLE_ARN",
                 "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
                 "AWS_CONTAINER_CREDENTIALS_FULL_URI"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent-aws-config")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent-aws-credentials")
    monkeypatch.setenv("HOME", "/nonexistent-home")
    monkeypatch.setenv("USERPROFILE", "/nonexistent-home")
    assert credential_source_hint() == [], (
        "the test environment still exposes a credential source, so this test "
        "would not be proving the fail-not-skip behaviour"
    )


def test_not_opting_in_skips_rather_than_failing(monkeypatch):
    """
    The other half: CI must stay free. Without the opt-in the gate skips, and the
    skip reason tells the operator exactly which variable to set.
    """
    monkeypatch.delenv(LIVE_OPT_IN_ENV, raising=False)
    assert live_opt_in() is False
    with pytest.raises(pytest.skip.Exception) as skipped:
        resolve_live_config()
    assert LIVE_OPT_IN_ENV in str(skipped.value)
    assert "billable" in str(skipped.value)


def test_a_real_call_without_credentials_fails_honestly(monkeypatch):
    """
    Always runs, on any machine, and never reaches the network: the credential
    chain is pinned empty, so a REAL boto3 resolution fails locally.

    This is the negative control for everything above. It is what makes an honest
    "Bedrock was not invoked" distinguishable from a fabricated success - the code
    path raises `BedrockUnavailableError` naming the real AWS error class and the
    stable failure kind instead of returning a plausible-looking diagnosis.
    """
    assert_no_credential_source(monkeypatch)

    config = AgentConfig(mode=MODE_BEDROCK, aws_region="us-east-1",
                         model_id="anthropic.claude-3-5-haiku-20241022-v1:0")
    agent = BedrockDiagnosisAgent(config)
    with pytest.raises(BedrockUnavailableError) as exc:
        agent.diagnose(LIVE_INCIDENT, LIVE_EVIDENCE, LIVE_BASELINE, "inc-no-creds")

    failure = exc.value
    assert failure.failure_kind == "NO_CREDENTIALS"
    assert failure.error_class == "NoCredentialsError"
    assert "credentials" in str(failure).lower()
    assert "AI_DOCTOR_AGENT_MODE=deterministic" in str(failure)
    # Nothing was invoked, so no live marker may exist.
    assert failure.as_record()["aws_error_code"] is None
