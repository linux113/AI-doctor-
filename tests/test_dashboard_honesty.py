"""
Dashboard honesty tests (requirement 11).

The dashboard may never say a port was restored, a request was replayed or a
service recovered unless the backend proved it, and it may never imply a model
answered when the offline rule engine did.

There is no JavaScript test runner in this repository and adding one is not worth
the dependency, so the dashboard is audited at the source level instead: the
rendered JSX is parsed for claims that are not gated on a backend field. Comments
are stripped first, because this file's own history discusses the false claims a
previous version made, and documentation must not be able to trip (or hide) the
check.
"""

import re
from pathlib import Path

import pytest

FRONTEND = Path(__file__).resolve().parent.parent / "frontend" / "src" / "app" / "page.tsx"

# Claims that are only true when the backend verified them. Each must be absent
# as an unconditional string, and each must appear - if at all - gated on the
# field that proves it.
UNPROVEN_CLAIMS = (
    "Port 11434 restored",
    "port 11434 restored",
    "HTTP 200 replayed",
    "retried successfully",
    "Heal complete! Service verified on port 11434",
    "Service restored",
    "Recovery successful",
)

# Backend fields a claim must be gated on.
GATING_FIELDS = (
    'incident.status === "RESOLVED"',
    "incident.verification",
    "incident.verification.api_available",
    "incident.retry_result",
    "incident.retry_result.success",
    "incident.used_llm",
    "incident.requires_human",
    "incident.action_result?.success === false",
)


def strip_comments(source: str) -> str:
    """
    Removes block comments (including JSX `{/* ... */}`) and whole-line `//`
    comments.

    Only whole-line `//` comments are removed, so a URL inside a string literal
    such as "http://127.0.0.1:11434" survives and the audit still sees it.
    """
    without_blocks = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    lines = [line for line in without_blocks.split("\n") if not line.strip().startswith("//")]
    return "\n".join(lines)


@pytest.fixture(scope="module")
def dashboard() -> str:
    assert FRONTEND.exists(), f"the dashboard source is missing: {FRONTEND}"
    return strip_comments(FRONTEND.read_text())


def test_no_unconditional_success_claim_is_rendered(dashboard):
    """
    The specific sentences that used to be asserted regardless of outcome. None of
    them may appear in rendered code at all: the honest equivalents are built from
    what the backend reported.
    """
    for claim in UNPROVEN_CLAIMS:
        assert claim not in dashboard, (
            f"the dashboard renders {claim!r} - a claim the backend may not have earned"
        )


@pytest.mark.parametrize("gate", GATING_FIELDS)
def test_success_claims_are_gated_on_a_backend_field(dashboard, gate):
    """
    Each gate must be present in the source. If one disappears, the claim it
    guarded has either been deleted or - worse - made unconditional, and this test
    names the missing gate rather than silently passing.
    """
    assert gate in dashboard, f"the dashboard no longer gates on {gate!r}"


def test_recovery_claims_are_derived_from_the_selected_incident(dashboard):
    assert 'incident.status === "RESOLVED"' in dashboard
    assert "Already Resolved" in dashboard
    assert "Recovery Result" in dashboard
    assert "incident.action_result?.success" in dashboard
    assert "incident.verification" in dashboard


def test_retry_claim_reports_the_actual_replay_result(dashboard):
    assert "incident.retry_result" in dashboard
    assert "incident.retry_result.success" in dashboard
    assert "incident.retry_result.status_code" in dashboard
    assert "No captured request" in dashboard
    assert "FAILED" in dashboard


def test_verification_claim_reports_the_observed_runtime_state(dashboard):
    assert "incident.verification?.api_available" in dashboard
    assert "incident.verification?.api_status_code" in dashboard
    assert "incident.verification?.runtime_state" in dashboard
    assert "incident.evidence?.port_11434?.is_open" in dashboard
    assert "VERIFICATION PENDING" in dashboard


def test_an_ai_claim_is_gated_on_a_real_model_round_trip(dashboard):
    assert "incident.used_llm" in dashboard
    assert "AWS Strands + Amazon Bedrock" in dashboard
    assert "Deterministic rule engine" in dashboard
    assert "no model was invoked." in dashboard
    assert "Amazon Bedrock was requested but did not produce a validated model diagnosis." in dashboard


def test_the_readiness_state_reads_live_system_status(dashboard):
    assert "status?.agent?.llm_operational" in dashboard
    assert "agentReady" in dashboard
    assert "llm_operational" in dashboard


def test_the_dashboard_does_not_claim_unverified_cloud_deployment(dashboard):
    assert "Lambda" not in dashboard
    assert "API Gateway" not in dashboard
    assert "DynamoDB" not in dashboard


def test_the_failure_classification_is_available_to_the_operator(dashboard):
    assert "incident.bedrock_failure" in dashboard
    assert "incident.bedrock_failure.error_class" in dashboard
    assert "incident.bedrock_failure.error_detail" in dashboard
    assert "failure_kind" in dashboard
