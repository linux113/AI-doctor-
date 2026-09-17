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
    "latestIncident.status === 'RESOLVED'",
    "latestIncident.verification",
    "latestIncident.verification.api_available",
    "latestIncident.retry_result",
    "latestIncident.retry_result.success",
    "latestIncident.used_llm",
    "latestIncident.requires_human",
    "latestIncident.action_result.success === false",
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


def test_a_recovery_claim_is_only_rendered_from_the_verified_status(dashboard):
    """
    "Recovery:" is the one place the dashboard states an overall verdict. It must
    print the backend's status verbatim, and colour it by that same status - never
    a hardcoded word such as "Recovered".
    """
    block = dashboard[dashboard.index("Recovery:{' '}"):]
    block = block[: block.index("</div>")]
    assert "latestIncident.status === 'RESOLVED'" in block
    assert "{latestIncident.status}" in block
    assert "Recovered" not in block, "the verdict is hardcoded rather than read"


def test_a_retry_claim_reports_what_the_replay_actually_returned(dashboard):
    """
    RESOLVED means the service came back; it does NOT mean the replayed request
    succeeded. The retry line must branch on `retry_result.success` and print the
    real status code or error, and must say when nothing was captured to replay.
    """
    block = dashboard[dashboard.index("Retry:{' '}"):]
    block = block[: block.index("Recovery:{' '}") + 200]
    assert "latestIncident.retry_result.success" in block
    assert "NO REQUEST CAPTURED" in block
    assert "did NOT succeed" in block or "FAILED" in block
    assert "status_code" in block


def test_a_verification_claim_reports_the_real_runtime_state(dashboard):
    """The verification line must print the observed state, not an assumed one."""
    block = dashboard[dashboard.index("Verification:{' '}"):]
    block = block[: block.index("Retry:{' '}") + 100]
    assert "latestIncident.verification.api_available" in block
    assert "latestIncident.verification.runtime_state" in block
    assert "NOT RUN" in block, "a missing verification must be shown as not run"
    assert "port_open" in block


def test_an_ai_claim_is_gated_on_a_real_model_round_trip(dashboard):
    """
    Honesty rule: "Amazon Bedrock" may only be shown against an incident when a
    model really produced the diagnosis. `used_llm` is the field that says so, and
    the label must fall back to the offline engine or to an explicit statement that
    Bedrock produced nothing.
    """
    assert "latestIncident.used_llm" in dashboard
    assert "deterministic rule engine (no model invoked)" in dashboard
    assert "Amazon Bedrock was requested but produced no diagnosis" in dashboard
    assert "Amazon Bedrock answered but returned no usable diagnosis" in dashboard


def test_the_readiness_banner_reads_the_live_system_status(dashboard):
    """
    The footer banner used to say "AWS Strands & Bedrock Ready" unconditionally -
    a claim that is false on any machine without the SDK or credentials. It must
    now be derived from /api/system-status, which reports what was actually
    detected.
    """
    assert "AWS Strands & Bedrock Ready" not in dashboard
    assert "Clean contracts ready for Phase 2" not in dashboard
    assert "status?.agent?.llm_operational" in dashboard
    assert "AWS Strands + Bedrock Operational" in dashboard
    assert "AWS Strands + Bedrock Not Operational" in dashboard
    assert "AWS Strands + Bedrock Not Configured" in dashboard


def test_the_banner_states_that_nothing_is_deployed(dashboard):
    """
    Requirement 13: no cloud resource is deployed until the local Bedrock path is
    validated. The dashboard must not imply a DynamoDB table exists.
    """
    assert "nothing is deployed" in dashboard
    assert "no Lambda, API Gateway or DynamoDB table exists" in dashboard


def test_the_failure_classification_is_shown_to_the_operator(dashboard):
    """
    The machine-readable failure kind exists so an operator and a dashboard can
    both act on it. Showing only prose would waste it.
    """
    assert "latestIncident.bedrock_failure.failure_kind" in dashboard
    assert "latestIncident.bedrock_failure.error_class" in dashboard
