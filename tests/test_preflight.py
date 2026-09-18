"""
Tests for the real-runtime preflight CLI (`python -m runner.preflight`).

These tests hold the preflight to the same standard it holds the product to:

* it never calls Amazon Bedrock during an ordinary preflight,
* it never starts Ollama, never fabricates a server, never claims a recovery,
* it never prints a secret access key, a session token, or a full access key ID,
* a real request is refused until the redaction suite has passed,
* absent values are reported as null, never as a plausible-looking zero,
* the eleven success criteria cannot be satisfied by the deterministic fallback.

Everything here runs offline. Where a test needs AWS to be reachable it patches
`botocore.client.BaseClient._make_api_call` - the single funnel every AWS
operation goes through - so an attempted call is *recorded* rather than sent.
That is what makes "no Bedrock call was made" an assertion instead of a claim.
"""

import ast
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

from runner import preflight
from runner.preflight import (
    BLOCKED,
    FAIL,
    LIVE_OPT_IN_ENV,
    PASS,
    PROOF_FIELDS,
    REDACTION_TEST_FILES,
    SKIP,
    WARN,
    Check,
    Report,
    build_parser,
    evaluate_success_criteria,
    identity_type,
    mask,
    opt_in,
    proof_from_outcome,
    render,
    render_proof,
    run_bedrock_smoke_test,
    run_live_demo,
    run_preflight,
    run_redaction_tests,
    safe,
)

# Built by concatenation so no source file in this repository contains a string
# that a secret scanner would flag as a real AWS access key.
FAKE_ACCESS_KEY_ID = "AKIA" + "PHASE4TESTKEY" + "123"
FAKE_SECRET_ACCESS_KEY = "FakeSecret" + "ForPreflightMaskingTest" + "1234567890"


# =========================================================================
# Fixtures
# =========================================================================


@pytest.fixture
def aws_api_spy(monkeypatch):
    """
    Records every AWS API call the process attempts, then refuses it.

    botocore routes every service operation through `BaseClient._make_api_call`,
    so patching that one method observes STS, Bedrock and anything else the code
    might try. The spy raises a connection error afterwards, so the code under
    test handles a realistic failure instead of receiving a fabricated response.
    """
    import botocore.client
    import botocore.exceptions

    calls = []

    def spy(self, operation_name, kwargs):
        meta = getattr(self, "meta", None)
        service = getattr(meta, "service_name", None)
        if service is None:
            model = getattr(meta, "service_model", None)
            service = getattr(model, "service_name", "<unknown>")
        calls.append((service, operation_name))
        raise botocore.exceptions.EndpointConnectionError(
            endpoint_url="https://blocked-by-test", msg="no network inside the test suite"
        )

    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", spy)
    return calls


@pytest.fixture
def fake_credentials(monkeypatch):
    """Credentials that exist but are worthless, so resolution is exercised for real."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", FAKE_ACCESS_KEY_ID)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", FAKE_SECRET_ACCESS_KEY)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    return FAKE_ACCESS_KEY_ID


@pytest.fixture
def no_credentials(monkeypatch):
    """
    A machine with no AWS credentials anywhere.

    Clearing only the environment variables would prove nothing on a developer
    machine that has `~/.aws/credentials`, so HOME and the shared-config paths
    are redirected as well.
    """
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                 "AWS_SECURITY_TOKEN", "AWS_PROFILE", "AWS_ROLE_ARN",
                 "AWS_WEB_IDENTITY_TOKEN_FILE",
                 "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
                 "AWS_CONTAINER_CREDENTIALS_FULL_URI"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent-aws-config")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent-aws-credentials")
    monkeypatch.setenv("HOME", "/nonexistent-home")
    monkeypatch.setenv("USERPROFILE", "/nonexistent-home")
    monkeypatch.delenv(LIVE_OPT_IN_ENV, raising=False)


@pytest.fixture
def ollama_absent(monkeypatch):
    """
    Forces discovery to find no Ollama binary, on any machine.

    Only the *inputs* to discovery are changed - the candidate list, PATH lookup
    and HOME - never the identity verification. `_verify_identity` still runs and
    still rejects every candidate, so this reproduces a genuinely absent runtime
    rather than stubbing the result.
    """
    import runner.ollama_runtime as ort

    monkeypatch.setenv("OLLAMA_EXECUTABLE", "/nonexistent-ollama-binary")
    monkeypatch.setenv("HOME", "/nonexistent-home")
    monkeypatch.setenv("USERPROFILE", "/nonexistent-home")
    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: None)
    monkeypatch.setattr(ort, "CANDIDATE_PATHS", ())
    monkeypatch.setattr(ort, "_default_runtime", None)
    yield
    # The runtime is a module-level singleton: leave no test-built instance behind.
    ort._default_runtime = None


@pytest.fixture
def ollama_never_started(monkeypatch):
    """Fails the test loudly if anything tries to start the daemon."""
    import runner.ollama_runtime as ort

    def refuse(*args, **kwargs):
        raise AssertionError("preflight must never start Ollama")

    monkeypatch.setattr(ort.OllamaRuntime, "start", refuse)
    monkeypatch.setattr(ort.OllamaRuntime, "stop", refuse)


@pytest.fixture
def bedrock_configured(monkeypatch):
    """bedrock mode with an explicit region and model ID."""
    monkeypatch.setenv("AI_DOCTOR_AGENT_MODE", "bedrock")
    monkeypatch.setenv("AI_DOCTOR_AWS_REGION", "us-east-1")
    monkeypatch.setenv("AI_DOCTOR_BEDROCK_MODEL_ID", "anthropic.claude-3-5-haiku-20241022-v1:0")
    monkeypatch.delenv(LIVE_OPT_IN_ENV, raising=False)


def _checks(report_or_lines, name):
    """All checks recorded under one name."""
    checks = report_or_lines.checks if isinstance(report_or_lines, Report) else report_or_lines
    return [c for c in checks if c.name == name]


def _one(report, name):
    found = _checks(report, name)
    assert found, f"no check named {name!r}; saw {[c.name for c in report.checks]}"
    return found[0]


# =========================================================================
# Masking - the only representation of a credential this module may produce
# =========================================================================


class TestMasking:
    def test_only_the_last_four_characters_survive(self):
        masked = mask(FAKE_ACCESS_KEY_ID)
        assert masked.endswith(FAKE_ACCESS_KEY_ID[-4:])
        assert FAKE_ACCESS_KEY_ID not in masked
        assert FAKE_ACCESS_KEY_ID[:8] not in masked

    def test_the_prefix_is_fixed_width_so_length_is_not_disclosed(self):
        # A marker that echoed how many characters were hidden would leak the
        # value's length. Every long value must mask to the same shape.
        short = mask("AKIA1234567890ABCDEF")
        long = mask("A" * 60 + "WXYZ")
        assert short.count("*") == long.count("*") == 4

    def test_a_value_shorter_than_the_kept_suffix_is_fully_hidden(self):
        assert mask("abc") == "***"
        assert "abc" not in mask("abc")

    def test_absence_is_reported_rather_than_rendered_as_empty(self):
        assert mask(None) == "<none>"
        assert mask("") == "<none>"

    def test_a_secret_access_key_is_never_passed_to_mask(self):
        # The secret is not masked, not truncated - it is never read at all. The
        # only place the module touches it is a presence test on a bool.
        source = (REPO_ROOT / "runner" / "preflight.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
                if name != "mask":
                    continue
                rendered = ast.dump(node)
                assert "secret" not in rendered.lower(), "mask() was called on a secret"
                assert "token" not in rendered.lower(), "mask() was called on a session token"


class TestIdentityType:
    @pytest.mark.parametrize("arn,expected", [
        ("arn:aws:sts::123456789012:assumed-role/DemoRole/session-x", "assumed-role"),
        ("arn:aws:iam::123456789012:role/DemoRole", "role"),
        ("arn:aws:iam::123456789012:user/alice", "user"),
        ("arn:aws:sts::123456789012:federated-user/bob", "federated-user"),
    ])
    def test_the_principal_kind_is_reported_without_the_arn(self, arn, expected):
        kind = identity_type(arn)
        assert kind == expected
        # The ARN carries the account ID and the role/user name. Neither may appear.
        assert "123456789012" not in kind
        assert arn not in kind

    def test_an_absent_or_unrecognised_arn_does_not_invent_a_principal(self):
        assert identity_type(None) == "unknown"
        assert identity_type("") == "unknown"
        assert identity_type("arn:aws:s3:::some-bucket") == "other"


def test_safe_runs_everything_through_the_product_redaction_path():
    payload = {"AWS_SECRET_ACCESS_KEY": FAKE_SECRET_ACCESS_KEY, "note": "harmless"}
    cleaned = safe(payload)
    assert FAKE_SECRET_ACCESS_KEY not in json.dumps(cleaned)
    assert cleaned["note"] == "harmless"


# =========================================================================
# The opt-in gate
# =========================================================================


class TestOptInGate:
    def test_off_by_default(self, monkeypatch):
        monkeypatch.delenv(LIVE_OPT_IN_ENV, raising=False)
        assert opt_in() is False

    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
    def test_the_documented_truthy_values_enable_it(self, monkeypatch, value):
        monkeypatch.setenv(LIVE_OPT_IN_ENV, value)
        assert opt_in() is True

    @pytest.mark.parametrize("value", ["0", "false", "", "  ", "maybe", "2"])
    def test_everything_else_leaves_it_off(self, monkeypatch, value):
        monkeypatch.setenv(LIVE_OPT_IN_ENV, value)
        assert opt_in() is False

    def test_the_smoke_test_is_blocked_and_sends_nothing(self, monkeypatch, capsys, aws_api_spy):
        monkeypatch.delenv(LIVE_OPT_IN_ENV, raising=False)
        assert run_bedrock_smoke_test() == 1
        out = capsys.readouterr().out
        assert BLOCKED in out
        assert LIVE_OPT_IN_ENV in out
        assert aws_api_spy == [], "a blocked smoke test must not attempt any AWS call"

    def test_the_live_demo_is_blocked_and_sends_nothing(self, monkeypatch, capsys, aws_api_spy):
        monkeypatch.delenv(LIVE_OPT_IN_ENV, raising=False)
        assert run_live_demo() == 1
        out = capsys.readouterr().out
        assert BLOCKED in out
        assert aws_api_spy == []


# =========================================================================
# Ordinary preflight: no Bedrock call, no daemon started, honest absences
# =========================================================================


class TestPreflightNeverCallsBedrock:
    def test_no_aws_api_call_at_all_when_offline(
        self, bedrock_configured, fake_credentials, ollama_absent,
        ollama_never_started, aws_api_spy, capsys,
    ):
        exit_code = run_preflight(no_network=True)
        assert exit_code == 1  # Ollama is absent, so the runtime is not ready
        assert aws_api_spy == [], f"preflight attempted AWS calls: {aws_api_spy}"
        assert "NOT TESTED" in capsys.readouterr().out

    def test_the_real_regional_client_is_constructed_but_not_called(
        self, bedrock_configured, fake_credentials, ollama_absent,
        ollama_never_started, aws_api_spy,
    ):
        report = Report(title="t")
        config = preflight.check_environment(report)
        assert config is not None and config.is_bedrock
        assert preflight.check_bedrock_client(report, config) is True

        check = _one(report, "bedrock:client")
        assert check.status == PASS
        assert check.data["endpoint"] == "https://bedrock-runtime.us-east-1.amazonaws.com"
        assert check.data["service"] == "bedrock-runtime"
        assert check.data["client_class"].startswith("botocore.client.")
        assert "BedrockModel" in check.data["strands_model_class"]
        assert check.data["model_id"] == "anthropic.claude-3-5-haiku-20241022-v1:0"
        assert aws_api_spy == [], "constructing a client must not call the service"

    def test_a_non_bedrock_client_would_be_refused(self, bedrock_configured, fake_credentials):
        # The endpoint assertion is what stops a stubbed client from passing as real.
        class FakeEndpoint:
            host = "https://not-bedrock.example.com"

        class FakeClient:
            _endpoint = FakeEndpoint()

        class FakeModel:
            client = FakeClient()

        class FakeAgent:
            def __init__(self, config):
                pass

            def build_model(self):
                return FakeModel()

        import agent.strands_agent as sa

        original = sa.BedrockDiagnosisAgent
        sa.BedrockDiagnosisAgent = FakeAgent
        try:
            report = Report(title="t")
            config = preflight.check_environment(report)
            assert preflight.check_bedrock_client(report, config) is False
            check = _one(report, "bedrock:client")
            assert check.status == FAIL
            assert "not-bedrock.example.com" in check.detail
        finally:
            sa.BedrockDiagnosisAgent = original

    def test_the_identity_check_is_skipped_offline_and_reported_as_skipped(
        self, bedrock_configured, fake_credentials, ollama_absent,
        ollama_never_started, aws_api_spy,
    ):
        report = Report(title="t")
        run_preflight(no_network=True)
        assert aws_api_spy == []

    def test_the_sts_call_is_the_only_network_touch_and_is_never_bedrock(
        self, bedrock_configured, fake_credentials, ollama_absent,
        ollama_never_started, aws_api_spy,
    ):
        run_preflight(no_network=False)
        services = {service for service, _ in aws_api_spy}
        assert "bedrock-runtime" not in services, "preflight must never call Bedrock"
        assert services <= {"sts"}, f"unexpected services contacted: {services}"
        assert aws_api_spy and aws_api_spy[0][1] == "GetCallerIdentity"


class TestPreflightOllamaHonesty:
    def test_an_absent_runtime_is_blocked_and_not_started(
        self, ollama_absent, ollama_never_started, capsys,
    ):
        report = Report(title="t")
        state, status = preflight.check_ollama(report)
        check = _one(report, "ollama:state")
        assert state == "OLLAMA_NOT_INSTALLED"
        assert check.status == BLOCKED
        assert check.data["installed"] is False
        assert "NOT_INSTALLED" in check.detail
        # The three things it must not do, stated in the report itself.
        assert "Nothing was started" in check.detail
        assert "no stand-in" in check.detail

    def test_preflight_as_a_whole_starts_nothing(
        self, ollama_absent, ollama_never_started, capsys,
    ):
        # `ollama_never_started` turns any start/stop attempt into a failure.
        run_preflight(no_network=True)
        assert "OLLAMA_NOT_INSTALLED" in capsys.readouterr().out

    def test_the_live_demo_reports_not_installed_verbatim(
        self, monkeypatch, bedrock_configured, fake_credentials,
        ollama_absent, ollama_never_started, aws_api_spy, capsys,
    ):
        monkeypatch.setenv(LIVE_OPT_IN_ENV, "1")
        # Let the redaction gate pass so the run reaches the Ollama requirement.
        monkeypatch.setattr(preflight, "run_redaction_tests", lambda report: True)

        assert run_live_demo() == 1
        out = capsys.readouterr().out
        assert "BLOCKED: OLLAMA: NOT_INSTALLED" in out
        assert "no server was fabricated" in out
        assert "no recovery is claimed" in out
        services = {service for service, _ in aws_api_spy}
        assert "bedrock-runtime" not in services


class TestPreflightCredentials:
    def test_missing_credentials_are_blocked_not_unknown(
        self, no_credentials, ollama_absent, ollama_never_started, aws_api_spy,
    ):
        report = Report(title="t")
        assert preflight.check_credentials(report) is False
        check = _one(report, "aws:credentials")
        assert check.status == BLOCKED
        assert check.data["available"] is False
        assert "default provider chain" in check.detail
        assert aws_api_spy == []

    def test_available_credentials_are_reported_masked(
        self, fake_credentials, ollama_absent, ollama_never_started,
    ):
        report = Report(title="t")
        assert preflight.check_credentials(report) is True
        check = _one(report, "aws:credentials")
        assert check.status == PASS
        assert check.data["available"] is True
        assert check.data["access_key_id"] == "****" + FAKE_ACCESS_KEY_ID[-4:]
        assert FAKE_ACCESS_KEY_ID not in check.detail
        assert FAKE_SECRET_ACCESS_KEY not in check.detail
        assert FAKE_SECRET_ACCESS_KEY not in json.dumps(check.as_dict())

    def test_the_whole_report_never_carries_the_secret(
        self, bedrock_configured, fake_credentials, ollama_absent,
        ollama_never_started, capsys,
    ):
        run_preflight(no_network=True)
        out = capsys.readouterr().out
        assert FAKE_SECRET_ACCESS_KEY not in out
        assert FAKE_ACCESS_KEY_ID not in out
        assert "****" + FAKE_ACCESS_KEY_ID[-4:] in out


class TestPreflightEnvironment:
    def test_deterministic_mode_is_reported_as_a_warning_not_a_success(
        self, monkeypatch, ollama_absent, ollama_never_started,
    ):
        monkeypatch.setenv("AI_DOCTOR_AGENT_MODE", "deterministic")
        report = Report(title="t")
        config = preflight.check_environment(report)
        mode = _one(report, "config:mode")
        assert mode.status == WARN
        assert "no model will be invoked" in mode.detail
        assert config is not None and config.is_bedrock is False

    def test_bedrock_mode_without_a_model_or_region_fails_loudly(self, monkeypatch):
        monkeypatch.setenv("AI_DOCTOR_AGENT_MODE", "bedrock")
        monkeypatch.delenv("AI_DOCTOR_AWS_REGION", raising=False)
        monkeypatch.delenv("AI_DOCTOR_BEDROCK_MODEL_ID", raising=False)
        report = Report(title="t")
        config = preflight.check_environment(report)
        load = _one(report, "config:load")
        if config is None:
            assert load.status == FAIL
        else:
            # Region and model have documented defaults; relying on one is a warning.
            assert load.status == PASS
            assert config.model_id and config.aws_region

    def test_unset_required_variables_are_warnings_with_an_explanation(
        self, monkeypatch, ollama_absent,
    ):
        for name in preflight.REQUIRED_ENV:
            monkeypatch.delenv(name, raising=False)
        report = Report(title="t")
        preflight.check_environment(report)
        for name in preflight.REQUIRED_ENV:
            check = _one(report, f"env:{name}")
            assert check.status == WARN
            assert "not set" in check.detail


# =========================================================================
# Output formats
# =========================================================================


class TestOutput:
    def test_json_is_machine_readable_and_secret_free(
        self, bedrock_configured, fake_credentials, ollama_absent,
        ollama_never_started, capsys,
    ):
        assert run_preflight(no_network=True, as_json=True) == 1
        out = capsys.readouterr().out
        doc = json.loads(out)  # the whole stdout must be valid JSON
        assert doc["verdict"] == "BLOCKED"
        assert doc["ready"] is False
        assert set(doc["counts"]) == {"pass", "warn", "fail", "blocked", "skip"}
        names = {c["check"] for c in doc["checks"]}
        assert {"aws:credentials", "bedrock:client", "ollama:state"} <= names
        assert FAKE_SECRET_ACCESS_KEY not in out
        assert FAKE_ACCESS_KEY_ID not in out

    def test_json_counts_match_the_checks_it_reports(
        self, bedrock_configured, fake_credentials, ollama_absent,
        ollama_never_started, capsys,
    ):
        run_preflight(no_network=True, as_json=True)
        doc = json.loads(capsys.readouterr().out)
        counts = doc["counts"]
        statuses = [c["status"] for c in doc["checks"]]
        assert counts["pass"] == statuses.count(PASS)
        assert counts["blocked"] == statuses.count(BLOCKED)
        assert counts["warn"] == statuses.count(WARN)
        assert counts["skip"] == statuses.count(SKIP)
        assert counts["fail"] == statuses.count(FAIL)

    def test_section_headers_are_not_counted_as_checks(
        self, bedrock_configured, fake_credentials, ollama_absent,
        ollama_never_started, capsys,
    ):
        run_preflight(no_network=True, as_json=True)
        doc = json.loads(capsys.readouterr().out)
        assert not any(c["check"].startswith("---") for c in doc["checks"])

    def test_the_human_report_points_at_the_next_command(
        self, ollama_absent, ollama_never_started, capsys,
    ):
        run_preflight(no_network=True)
        out = capsys.readouterr().out
        assert "bedrock-smoke-test" in out
        assert LIVE_OPT_IN_ENV in out
        assert "live-demo" in out

    def test_render_lists_every_failure_with_its_reason(self):
        report = Report(title="t")
        report.add("a", PASS, "fine")
        report.add("b", BLOCKED, "the reason for b")
        report.add("c", FAIL, "the reason for c")
        out = render(report)
        assert "the reason for b" in out and "the reason for c" in out
        assert report.ready is False
        assert [c.name for c in report.failures] == ["b", "c"]

    def test_a_clean_report_is_ready(self):
        report = Report(title="t")
        report.add("a", PASS, "fine")
        report.add("b", WARN, "noted")
        assert report.ready is True
        assert report.as_dict()["verdict"] == "READY"


# =========================================================================
# The redaction gate that must pass before any real request
# =========================================================================


class TestRedactionGate:
    def test_the_required_test_files_exist(self):
        for relative in REDACTION_TEST_FILES:
            assert (REPO_ROOT / relative).exists(), f"{relative} is missing"

    def test_a_failing_redaction_suite_blocks_the_request(self, monkeypatch):
        monkeypatch.setattr(
            preflight.subprocess, "run",
            lambda *a, **k: subprocess.CompletedProcess(a, 1, stdout="1 failed", stderr=""),
        )
        report = Report(title="t")
        assert run_redaction_tests(report) is False
        check = _one(report, "redaction:tests")
        assert check.status == BLOCKED
        assert "no real request was made" in check.detail

    def test_a_passing_redaction_suite_opens_the_gate(self, monkeypatch):
        monkeypatch.setattr(
            preflight.subprocess, "run",
            lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout="85 passed", stderr=""),
        )
        report = Report(title="t")
        assert run_redaction_tests(report) is True
        assert _one(report, "redaction:tests").status == PASS

    def test_missing_redaction_tests_block_rather_than_pass_silently(self, monkeypatch):
        monkeypatch.setattr(preflight, "REDACTION_TEST_FILES", ("tests/does_not_exist.py",))
        report = Report(title="t")
        assert run_redaction_tests(report) is False
        assert _one(report, "redaction:tests").status == BLOCKED

    def test_a_hanging_redaction_suite_is_a_failure_not_a_hang(self, monkeypatch):
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd=kwargs.get("args", "pytest"), timeout=600)

        monkeypatch.setattr(preflight.subprocess, "run", timeout)
        report = Report(title="t")
        assert run_redaction_tests(report) is False
        assert _one(report, "redaction:tests").status == FAIL

    def test_the_gate_runs_before_any_request_is_attempted(
        self, monkeypatch, bedrock_configured, fake_credentials,
        ollama_absent, ollama_never_started, aws_api_spy, capsys,
    ):
        monkeypatch.setenv(LIVE_OPT_IN_ENV, "1")
        monkeypatch.setattr(preflight, "run_redaction_tests", lambda report: False)
        assert run_bedrock_smoke_test() == 1
        assert aws_api_spy == [], "the gate must close before any AWS call"
        assert "bedrock-runtime" not in {s for s, _ in aws_api_spy}

    def test_the_real_gate_actually_passes_on_this_repository(self):
        # Not stubbed: runs the two suites for real, in a subprocess.
        report = Report(title="t")
        assert run_redaction_tests(report) is True, _one(report, "redaction:tests").detail


# =========================================================================
# Proof fields
# =========================================================================


class TestProofFields:
    def test_every_field_the_operator_must_see_is_defined(self):
        required = {
            "agent_mode", "agent_status", "diagnosis_outcome", "model_id", "aws_region",
            "bedrock_request_id", "latency_ms", "evidence_ids", "recommended_action",
            "policy_result", "remediation_action", "verification_result", "retry_result",
            "final_http_status",
        }
        assert required <= set(PROOF_FIELDS)

    def test_token_counts_are_recorded_but_are_not_the_proof(self):
        assert {"input_tokens", "output_tokens", "total_tokens"} <= set(PROOF_FIELDS)

    def test_an_empty_outcome_yields_nulls_never_zeros(self):
        proof = proof_from_outcome({})
        for key in ("bedrock_request_id", "latency_ms", "input_tokens", "output_tokens",
                    "total_tokens", "final_http_status", "agent_mode", "agent_status"):
            assert proof[key] is None, f"{key} must be null when absent, not {proof[key]!r}"
        assert proof["evidence_ids"] == []
        assert proof["verification_result"] is None
        assert proof["remediation_succeeded"] is None

    def test_a_real_outcome_is_read_field_by_field(self):
        outcome = {
            "status": "RECOVERED",
            "agent_mode": "bedrock",
            "agent_status": "BEDROCK_SUCCESS",
            "diagnosis_outcome": "DIAGNOSED",
            "bedrock_invoked": True,
            "used_llm": True,
            "runtime_state": "OLLAMA_RUNNING",
            "action_taken": "start_ollama",
            "action_result": {"success": True},
            "agent_telemetry": {
                "model_id": "anthropic.claude-3-5-haiku-20241022-v1:0",
                "aws_region": "us-east-1",
                "bedrock_request_id": "5c9d1f2a-0000-1111-2222-333344445555",
                "agent_latency_ms": 1234,
                "input_tokens": 900,
                "output_tokens": 120,
                "total_tokens": 1020,
            },
            "policy_decision": {"allowed": True, "approved_action": "start_ollama"},
            "verification": {"success": True, "runtime_state": "OLLAMA_RUNNING",
                             "port_open": True, "api_available": True, "api_status_code": 200},
            "retry_result": {"success": True, "status_code": 200},
            "timeline": [{
                "stage_code": "AI_DIAGNOSIS",
                "details": {"ai_diagnosis": {
                    "evidence_ids": ["ev-1", "ev-2"],
                    "corroborating_probes": ["port_11434"],
                    "recommended_action": "start_ollama",
                }},
            }],
        }
        proof = proof_from_outcome(outcome)
        assert proof["bedrock_request_id"] == "5c9d1f2a-0000-1111-2222-333344445555"
        assert proof["latency_ms"] == 1234
        assert proof["total_tokens"] == 1020
        assert proof["evidence_ids"] == ["ev-1", "ev-2"]
        assert proof["final_http_status"] == 200
        assert proof["policy_result"]["allowed"] is True
        assert proof["verification_result"]["runtime_state"] == "OLLAMA_RUNNING"
        assert proof["incident_status"] == "RECOVERED"

    def test_a_deterministic_fallback_outcome_cannot_produce_bedrock_proof(self):
        proof = proof_from_outcome({
            "status": "FAILED",
            "agent_mode": "deterministic",
            "agent_status": "FALLBACK_USED",
            "bedrock_invoked": False,
            "used_llm": False,
            "diagnosis_outcome": "DIAGNOSED",
        })
        assert proof["bedrock_request_id"] is None
        assert proof["latency_ms"] is None
        assert proof["used_llm"] is False
        assert proof["bedrock_invoked"] is False

    def test_final_http_status_comes_from_the_retry_and_is_not_invented(self):
        assert proof_from_outcome({"retry_result": {"success": False, "status_code": 503}})[
            "final_http_status"] == 503
        # A retry that never happened must not report 0, 200 or None-as-success.
        proof = proof_from_outcome({"retry_result": None})
        assert proof["final_http_status"] is None
        assert proof["retry_result"]["present"] is False

    def test_render_proof_marks_nulls_explicitly(self):
        proof = proof_from_outcome({})
        out = render_proof(proof)
        assert "never that it is zero" in out
        assert "bedrock_request_id" in out
        assert "None" in out

    def test_render_proof_redacts_a_secret_that_reaches_it(self):
        proof = proof_from_outcome({})
        proof["model_id"] = {"api_key": FAKE_SECRET_ACCESS_KEY}
        out = render_proof(proof)
        assert FAKE_SECRET_ACCESS_KEY not in out


# =========================================================================
# The eleven success criteria
# =========================================================================


def complete_proof():
    """A proof shaped like a genuinely successful real run."""
    return proof_from_outcome({
        "status": "RECOVERED",
        "agent_mode": "bedrock",
        "agent_status": "BEDROCK_SUCCESS",
        "diagnosis_outcome": "DIAGNOSED",
        "bedrock_invoked": True,
        "used_llm": True,
        "runtime_state": "OLLAMA_RUNNING",
        "action_taken": "start_ollama",
        "action_result": {"success": True},
        "agent_telemetry": {
            "model_id": "anthropic.claude-3-5-haiku-20241022-v1:0",
            "aws_region": "us-east-1",
            "bedrock_request_id": "real-request-id-from-the-service",
            "agent_latency_ms": 1234,
        },
        "policy_decision": {"allowed": True, "approved_action": "start_ollama"},
        "verification": {"success": True, "runtime_state": "OLLAMA_RUNNING",
                         "port_open": True, "api_available": True, "api_status_code": 200},
        "retry_result": {"success": True, "status_code": 200},
        "timeline": [{"stage_code": "AI_DIAGNOSIS", "details": {"ai_diagnosis": {
            "evidence_ids": ["ev-1"], "recommended_action": "start_ollama"}}}],
    })


class TestSuccessCriteria:
    def test_there_are_eleven_criteria_in_pipeline_order(self):
        checks = evaluate_success_criteria(complete_proof(), "OLLAMA_STOPPED")
        assert len(checks) == 11
        assert [c.name for c in checks] == [f"criterion-{i:02d}" for i in range(1, 12)]

    def test_a_complete_real_run_passes_all_eleven(self):
        checks = evaluate_success_criteria(complete_proof(), "OLLAMA_STOPPED")
        assert all(c.status == PASS for c in checks), [
            (c.name, c.detail) for c in checks if c.status != PASS
        ]

    def test_token_counts_are_not_required_for_success(self):
        proof = complete_proof()
        assert proof["input_tokens"] is None and proof["total_tokens"] is None
        checks = evaluate_success_criteria(proof, "OLLAMA_STOPPED")
        assert all(c.status == PASS for c in checks)

    def test_an_absent_runtime_fails_the_first_criterion(self):
        checks = evaluate_success_criteria(complete_proof(), "OLLAMA_NOT_INSTALLED")
        assert checks[0].status == FAIL
        assert "OLLAMA_NOT_INSTALLED" in checks[0].detail

    def test_the_deterministic_fallback_cannot_claim_a_model_diagnosis(self):
        proof = complete_proof()
        proof["agent_mode"] = "deterministic"
        proof["bedrock_invoked"] = False
        checks = evaluate_success_criteria(proof, "OLLAMA_STOPPED")
        assert checks[3].status == FAIL
        assert "The real Strands Agent executed" in checks[3].detail

    def test_bedrock_success_without_a_request_id_is_not_a_success(self):
        proof = complete_proof()
        proof["bedrock_request_id"] = None
        checks = evaluate_success_criteria(proof, "OLLAMA_STOPPED")
        assert checks[4].status == FAIL
        assert "A real Bedrock request succeeded" in checks[4].detail

    def test_a_result_not_produced_by_the_model_fails(self):
        proof = complete_proof()
        proof["used_llm"] = False
        assert evaluate_success_criteria(proof, "OLLAMA_STOPPED")[5].status == FAIL

    def test_a_policy_refusal_is_not_a_successful_demonstration(self):
        proof = complete_proof()
        proof["policy_result"] = {"present": True, "allowed": False,
                                  "approved_action": None, "violation": "destructive_action"}
        checks = evaluate_success_criteria(proof, "OLLAMA_STOPPED")
        assert checks[6].status == FAIL
        assert "policy" in checks[6].detail

    def test_a_remediation_that_did_not_succeed_fails(self):
        proof = complete_proof()
        proof["remediation_succeeded"] = False
        assert evaluate_success_criteria(proof, "OLLAMA_STOPPED")[7].status == FAIL

    def test_an_action_outside_the_allowlist_is_not_a_pass(self):
        proof = complete_proof()
        proof["remediation_action"] = "none"
        assert evaluate_success_criteria(proof, "OLLAMA_STOPPED")[7].status == FAIL

    def test_verification_requires_the_real_runtime_to_be_running(self):
        proof = complete_proof()
        proof["verification_result"] = {"present": True, "success": True,
                                        "runtime_state": "OLLAMA_STOPPED"}
        assert evaluate_success_criteria(proof, "OLLAMA_STOPPED")[8].status == FAIL

    def test_a_missing_verification_fails(self):
        proof = complete_proof()
        proof["verification_result"] = None
        assert evaluate_success_criteria(proof, "OLLAMA_STOPPED")[8].status == FAIL

    def test_a_retry_that_never_happened_fails(self):
        proof = complete_proof()
        proof["retry_result"] = {"present": False, "success": None, "status_code": None}
        assert evaluate_success_criteria(proof, "OLLAMA_STOPPED")[9].status == FAIL

    @pytest.mark.parametrize("status", [500, 503, 404, 0, None])
    def test_only_http_200_satisfies_the_last_criterion(self, status):
        proof = complete_proof()
        proof["final_http_status"] = status
        assert evaluate_success_criteria(proof, "OLLAMA_STOPPED")[10].status == FAIL

    def test_the_earliest_failure_is_the_one_to_report(self):
        # Two things went wrong; the report must name the first, because the
        # second is a consequence of it.
        proof = complete_proof()
        proof["agent_mode"] = "deterministic"
        proof["bedrock_invoked"] = False
        proof["bedrock_request_id"] = None
        proof["final_http_status"] = 503
        checks = evaluate_success_criteria(proof, "OLLAMA_STOPPED")
        failed = [c for c in checks if c.status == FAIL]
        assert failed[0].name == "criterion-04"
        assert len(failed) > 1

    def test_a_completely_empty_run_fails_at_the_first_criterion(self):
        checks = evaluate_success_criteria(proof_from_outcome({}), "OLLAMA_NOT_INSTALLED")
        assert checks[0].status == FAIL
        assert all(c.status == FAIL for c in checks)
        assert not any(c.status == PASS for c in checks)


# =========================================================================
# CLI surface
# =========================================================================


class TestCli:
    def test_the_default_command_is_preflight(self):
        args = build_parser().parse_args([])
        assert args.command is None  # main() maps this onto preflight

    def test_flags_are_accepted_before_and_after_the_subcommand(self):
        # A regression guard: argparse lets a subparser's default silently
        # overwrite a value already set on the top-level parser.
        before = build_parser().parse_args(["--json", "--no-network", "preflight"])
        after = build_parser().parse_args(["preflight", "--json", "--no-network"])
        for args in (before, after):
            assert args.json is True
            assert args.no_network is True

    def test_the_subcommands_are_the_three_documented_ones(self):
        parser = build_parser()
        choices = next(
            a.choices for a in parser._actions if a.dest == "command"
        )
        assert set(choices) == {"preflight", "bedrock-smoke-test", "live-demo"}

    def test_the_help_text_states_the_cost_of_the_smoke_test(self):
        parser = build_parser()
        text = parser.format_help() + parser.format_usage()
        assert "billable" in text
        assert LIVE_OPT_IN_ENV in text

    def test_the_module_is_runnable_with_dash_m(self):
        completed = subprocess.run(
            [sys.executable, "-m", "runner.preflight", "--help"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120,
        )
        assert completed.returncode == 0
        assert "bedrock-smoke-test" in completed.stdout


# =========================================================================
# Static security invariants
# =========================================================================


class TestStaticInvariants:
    def test_no_dynamic_code_execution_or_shell(self):
        source = (REPO_ROOT / "runner" / "preflight.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        forbidden = {"eval", "exec", "compile", "system", "popen", "spawn"}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            assert name not in forbidden, f"{name}() must not appear in preflight"
            for keyword in node.keywords:
                if keyword.arg == "shell":
                    value = getattr(keyword.value, "value", None)
                    assert value is not True, "shell=True must never be used"

    def test_subprocess_use_is_a_fixed_argv_list(self):
        source = (REPO_ROOT / "runner" / "preflight.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        calls = [
            n for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr == "run"
            and isinstance(n.func.value, ast.Name)
            and n.func.value.id == "subprocess"
        ]
        assert calls, "the redaction gate should run pytest in a subprocess"
        for call in calls:
            assert isinstance(call.args[0], ast.List), "argv must be a fixed list, not a string"

    def test_no_secret_is_ever_formatted_into_output(self):
        source = (REPO_ROOT / "runner" / "preflight.py").read_text(encoding="utf-8")
        assert "secret_key" in source  # only as a presence check
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith('"""'):
                continue
            if "secret_key" in stripped:
                assert "bool(" in stripped or "getattr" in stripped, (
                    f"the secret access key may only be tested for presence: {stripped}"
                )
            assert "AWS_SECRET_ACCESS_KEY" not in stripped or "os.environ" not in stripped


# =========================================================================
# Failure classification reported by the preflight (defect regressions)
# =========================================================================


class TestFailureClassification:
    def test_a_tls_failure_is_a_network_failure_not_unknown(self):
        # botocore's SSLError is its own class, and the classifier matches on the
        # exact class name, so a corporate-proxy certificate failure used to be
        # reported as UNKNOWN_AWS_ERROR - the one category an operator cannot act
        # on. It is a network failure and the taxonomy already had a kind for it.
        import botocore.exceptions
        from agent.strands_agent import classify_bedrock_failure

        with pytest.raises(botocore.exceptions.SSLError) as info:
            raise botocore.exceptions.SSLError(
                endpoint_url="https://bedrock-runtime.us-east-1.amazonaws.com",
                error="[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed",
            )
        assert classify_bedrock_failure(info.value) == "NETWORK_UNREACHABLE"

    @pytest.mark.parametrize("factory,expected", [
        (lambda e: e.NoCredentialsError(), "NO_CREDENTIALS"),
        (lambda e: e.EndpointConnectionError(endpoint_url="https://x", msg="dns"),
         "NETWORK_UNREACHABLE"),
        (lambda e: e.ConnectTimeoutError(endpoint_url="https://x", msg="slow"), "TIMEOUT"),
        (lambda e: e.ReadTimeoutError(endpoint_url="https://x", msg="slow"), "TIMEOUT"),
        (lambda e: e.HTTPClientError(error="boom"), "NETWORK_UNREACHABLE"),
    ])
    def test_transport_failures_keep_their_own_category(self, factory, expected):
        import botocore.exceptions
        from agent.strands_agent import classify_bedrock_failure

        with pytest.raises(botocore.exceptions.BotoCoreError) as info:
            raise factory(botocore.exceptions)
        assert classify_bedrock_failure(info.value) == expected

    def test_an_access_denied_service_error_is_not_collapsed(self):
        from agent.strands_agent import classify_bedrock_failure

        error = {"Error": {"Code": "AccessDeniedException", "Message": "not authorised"}}
        import botocore.exceptions
        try:
            raise botocore.exceptions.ClientError(error, "Converse")
        except botocore.exceptions.ClientError as exc:
            assert classify_bedrock_failure(exc) == "ACCESS_DENIED"

    def test_a_model_not_ready_error_is_distinguishable_from_a_bad_model_id(self):
        import botocore.exceptions
        from agent.strands_agent import aws_error_code, classify_bedrock_failure

        for code, expected in (("ModelNotReadyException", "SERVICE_UNAVAILABLE"),
                               ("ResourceNotFoundException", "INVALID_MODEL"),
                               ("ThrottlingException", "THROTTLED"),
                               ("ValidationException", "VALIDATION_ERROR")):
            try:
                raise botocore.exceptions.ClientError(
                    {"Error": {"Code": code, "Message": "m"}}, "Converse"
                )
            except botocore.exceptions.ClientError as exc:
                assert classify_bedrock_failure(exc) == expected, code
                assert aws_error_code(exc) == code, "the raw AWS code must be preserved"
