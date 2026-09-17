"""
OFFLINE DETERMINISTIC end-to-end tests - suite A of the three separated tests.

    A  tests/test_e2e_offline_deterministic.py  (THIS FILE) no AWS, no Ollama, CI
    B  tests/test_bedrock_contract.py           real Agent + real BedrockModel,
                                                only client.converse answered locally
    C  tests/test_bedrock_live.py               a real, billable AWS request

What suite A proves
-------------------
That the whole pipeline - detection, evidence collection, diagnosis, policy gate,
allowlist, remediation, verification, retry, timeline - runs to completion and
reports HONESTLY on a machine that has neither AWS credentials nor an Ollama
installation. This is the configuration CI runs in, and it is the configuration
most likely to be demoed by accident, so it is the one where a false claim would
be most damaging.

The invariants asserted here are the ones a reader relies on:

  * a deterministic run never produces a live marker (no request ID, no tokens,
    no model id) and never sets used_llm;
  * bedrock mode without credentials is labelled as what it became - the offline
    rule engine - and the incident names the AWS failure that caused it, so a
    silent substitution cannot be read as an AI diagnosis;
  * with fallback disabled, no action is taken at all rather than a rule-engine
    conclusion being dressed up as a recovery;
  * an absent Ollama runtime is reported as NOT_INSTALLED and is never converted
    into "Ollama is installed but not running";
  * RESOLVED is only ever reported when verification really observed a running
    service, and the timeline never claims a restored port or a replayed request
    that did not happen.

No test in this file contacts AWS, and none starts a service on a machine that
has one installed but stopped (see `full_loop` below).
"""

from typing import Any, Dict

import pytest

from runner.doctor_runner import DoctorRunner
from runner.timeline import (
    STAGE_AI_DIAGNOSIS,
    STAGE_CODES,
    STAGE_DETECTED,
    STAGE_EVIDENCE_COLLECTED,
    STAGE_FAILED,
    STAGE_POLICY_CHECK,
    STAGE_RECOVERED,
    STAGE_REMEDIATION_STARTED,
    STAGE_RETRY,
    STAGE_VERIFICATION,
    TIMELINE_STAGE_CODES,
)
from runner.ollama_runtime import OLLAMA_NOT_INSTALLED, OLLAMA_RUNNING, OLLAMA_STOPPED
from runner.redaction import sanitize_deep
from runner.remediation_registry import REMEDIATION_ALLOWLIST

INCIDENT: Dict[str, Any] = {
    "incident_id": "inc-offline-e2e",
    "detected_error": "HTTPConnectionPool(host='127.0.0.1', port=11434): connection refused",
    "failure_type": "service_down",
    "request_context": {"url": "http://127.0.0.1:11434/api/tags", "method": "GET"},
}

# Markers that may only ever be produced by a real Amazon Bedrock round trip.
LIVE_MARKERS = ("bedrock_request_id", "total_tokens", "input_tokens", "output_tokens")

# Claims the backend may only make when it actually verified them.
UNPROVEN_CLAIMS = (
    "Port 11434 restored",
    "port 11434 restored",
    "HTTP 200 replayed",
    "replayed successfully",
    "Recovered",
    "recovered successfully",
)


@pytest.fixture
def no_aws(monkeypatch):
    """
    Pins the credential chain empty, so no test here can reach AWS even if the
    developer's machine has credentials configured.

    `HOME` is redirected too: the credential hint also inspects `~/.aws`, and a
    test that only cleared environment variables would silently prove nothing on
    a machine that has a profile file.
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
    monkeypatch.delenv("AI_DOCTOR_RUN_LIVE_BEDROCK", raising=False)


@pytest.fixture
def full_loop(ollama_state):
    """
    Guards the tests that run the whole healing loop.

    `heal_incident` executes the allowlisted remediation for real. On a machine
    where Ollama is installed but stopped, that would start the developer's
    daemon as a side effect of running the test suite - so those tests skip there.
    With no Ollama at all (CI) the loop runs to its honest FAILED conclusion, and
    with a running daemon it exercises the genuinely-recovered path.
    """
    if ollama_state == OLLAMA_STOPPED:
        pytest.skip(
            "Ollama is installed but stopped on this machine; running the healing "
            "loop would start the developer's daemon as a side effect of the suite."
        )
    return ollama_state


def _timeline_text(result: Dict[str, Any]) -> str:
    """Every stage description in the timeline, as one searchable string."""
    return "\n".join(str(entry.get("description") or "") for entry in result["timeline"])


# =========================================================================
# The offline run itself
# =========================================================================


def test_the_pipeline_completes_offline_with_no_aws_and_no_ollama(no_aws, full_loop, monkeypatch):
    """
    The whole loop, on a machine with no credentials and no runtime, must finish
    and return a coherent record rather than raising or hanging.
    """
    monkeypatch.setenv("AI_DOCTOR_AGENT_MODE", "deterministic")
    result = DoctorRunner().heal_incident(dict(INCIDENT))

    assert result["incident_id"] == INCIDENT["incident_id"]
    assert result["status"] in ("RESOLVED", "FAILED")
    assert result["root_cause"], "an offline run must still produce a root cause"
    assert 0.0 <= float(result["confidence"]) <= 1.0
    assert result["agent_mode"] == "deterministic"
    assert result["agent_status"] == "DETERMINISTIC"
    assert result["action_taken"] in (set(REMEDIATION_ALLOWLIST) | {"none"})
    assert [entry["stage"] for entry in result["timeline"]][:3] == [
        "DETECTED", "INVESTIGATING", "ROOT CAUSE FOUND"]


def test_an_offline_run_produces_no_live_marker(no_aws, full_loop, monkeypatch):
    """
    Nothing that only a real AWS round trip can produce may appear. If any of
    these ever becomes non-null offline, service metadata is being fabricated.
    """
    monkeypatch.setenv("AI_DOCTOR_AGENT_MODE", "deterministic")
    result = DoctorRunner().heal_incident(dict(INCIDENT))
    telemetry = result["agent_telemetry"]

    for marker in LIVE_MARKERS:
        assert telemetry[marker] is None, f"{marker} appeared without a real Bedrock call"
    assert telemetry["model_id"] is None
    assert telemetry["aws_region"] is None
    assert telemetry["agent_mode"] == "deterministic"
    assert telemetry["failure_kind"] is None, "nothing failed; no failure kind applies"
    assert result["model_id"] is None
    assert result["aws_region"] is None
    assert result["used_llm"] is False
    assert result["bedrock_invoked"] is False
    assert result["bedrock_failure"] is None


def test_an_offline_run_never_claims_ai_reasoning(no_aws, full_loop, monkeypatch):
    """
    Honesty rule: "AI diagnosis" is only true when a model answered. The timeline
    must name the offline rule engine, and nothing may imply otherwise.
    """
    monkeypatch.setenv("AI_DOCTOR_AGENT_MODE", "deterministic")
    result = DoctorRunner().heal_incident(dict(INCIDENT))
    text = _timeline_text(result) + "\n" + str(result["agent_note"])

    assert "deterministic offline rule engine" in text
    assert "Amazon Bedrock" not in text, "an offline run must not name Bedrock"
    for claim in ("AI diagnosis", "AI reasoning", "Bedrock powered", "Autonomous"):
        assert claim.lower() not in text.lower(), f"offline run claimed {claim!r}"


# =========================================================================
# Bedrock mode on a machine that cannot reach Bedrock
# =========================================================================


def test_bedrock_mode_without_credentials_is_labelled_as_the_substitution_it_became(
    no_aws, full_loop, monkeypatch
):
    """
    The most dangerous silent failure in this project: bedrock mode requested, no
    credentials, fallback allowed. The loop still produces a useful answer - but
    it must say plainly that the answer came from the rule engine, and record the
    AWS failure that caused it.
    """
    monkeypatch.setenv("AI_DOCTOR_AGENT_MODE", "bedrock")
    result = DoctorRunner().heal_incident(dict(INCIDENT))

    assert result["agent_mode"] == "deterministic", "the substitution must be labelled"
    assert result["agent_status"] == "FALLBACK_DETERMINISTIC"
    assert result["used_llm"] is False
    assert result["bedrock_invoked"] is False
    assert result["diagnosis_outcome"] == "DIAGNOSED"

    failure = result["bedrock_failure"]
    assert failure is not None, "the AWS failure that caused the fallback must be recorded"
    assert failure["failure_kind"] == "NO_CREDENTIALS"
    assert failure["error_class"] == "NoCredentialsError"

    note = result["agent_note"]
    assert "Bedrock" in note and "could not be used" in note
    assert "NO_CREDENTIALS" in note
    assert "not from a model" in note
    # And the machine-readable classification is present in the incident record.
    assert result["agent_telemetry"]["failure_kind"] == "NO_CREDENTIALS"
    for marker in LIVE_MARKERS:
        assert result["agent_telemetry"][marker] is None


def test_bedrock_mode_with_fallback_disabled_takes_no_action_at_all(
    no_aws, full_loop, monkeypatch
):
    """
    With `AI_DOCTOR_AGENT_FALLBACK=fail`, a machine that cannot reach Bedrock must
    end the incident unresolved with NO remediation attempted - not a rule-engine
    conclusion presented as a recovery.
    """
    monkeypatch.setenv("AI_DOCTOR_AGENT_MODE", "bedrock")
    monkeypatch.setenv("AI_DOCTOR_AGENT_FALLBACK", "fail")
    result = DoctorRunner().heal_incident(dict(INCIDENT))

    assert result["agent_mode"] == "bedrock", "the incident records what was asked for"
    assert result["agent_status"] == "BEDROCK_UNAVAILABLE"
    assert result["diagnosis_outcome"] == "FAILED"
    assert result["used_llm"] is False
    assert result["bedrock_invoked"] is False
    assert result["action_taken"] == "none", "no action may be taken on a failed diagnosis"
    assert result["requires_human"] is True
    assert result["status"] == "FAILED"
    assert result["resolved_at"] is None
    # Nothing was executed, so nothing may appear in the audit trail as executed.
    executed = [entry for entry in result["audit_log"] if entry.get("executed")]
    assert executed == [], f"an action was executed despite no diagnosis: {executed}"


# =========================================================================
# Absence is absence
# =========================================================================


def test_an_absent_ollama_is_reported_as_not_installed_never_as_not_running(
    no_aws, full_loop, monkeypatch, ollama_state
):
    """
    Prohibition: if Ollama is unavailable because it is not on this machine, say
    NOT_INSTALLED. Converting absence into "installed but stopped" would imply an
    allowlisted action could fix it, and none can - installing software is not
    remediation.
    """
    if ollama_state != OLLAMA_NOT_INSTALLED:
        pytest.skip(f"Ollama is present on this machine (state: {ollama_state}).")

    monkeypatch.setenv("AI_DOCTOR_AGENT_MODE", "deterministic")
    result = DoctorRunner().heal_incident(dict(INCIDENT))

    assert result["runtime_state"] == OLLAMA_NOT_INSTALLED
    assert "OLLAMA_NOT_INSTALLED" in result["root_cause"]
    assert "no ollama executable was found" in result["root_cause"]
    assert result["requires_human"] is True
    # The absence must not be reported as an outage of an installed service.
    blob = str(result["root_cause"]) + " " + _timeline_text(result)
    assert "OLLAMA_NOT_RUNNING" not in blob
    assert "ollama_not_running" not in blob
    assert "OLLAMA_STOPPED" not in blob
    # And the loop must not claim it recovered something that is not installed.
    assert result["status"] == "FAILED"


def test_not_installed_is_never_reported_as_a_successful_recovery(no_aws, full_loop, monkeypatch,
                                                                 ollama_state):
    """The dashboard-facing half of the same rule."""
    if ollama_state != OLLAMA_NOT_INSTALLED:
        pytest.skip(f"Ollama is present on this machine (state: {ollama_state}).")

    monkeypatch.setenv("AI_DOCTOR_AGENT_MODE", "deterministic")
    result = DoctorRunner().heal_incident(dict(INCIDENT))

    assert result["status"] != "RESOLVED"
    assert result["resolved_at"] is None
    stages = [entry["stage"] for entry in result["timeline"]]
    assert "RESOLVED" not in stages
    assert "FAILED" in stages
    text = _timeline_text(result)
    for claim in UNPROVEN_CLAIMS:
        assert claim not in text, f"the timeline claimed {claim!r} without verifying it"


# =========================================================================
# Recovery claims must be earned
# =========================================================================


def test_resolved_is_only_reported_when_verification_really_observed_a_running_service(
    no_aws, full_loop, monkeypatch
):
    """
    Machine-independent consistency rule. Whatever this machine's state, RESOLVED
    may only appear together with a verification that observed OLLAMA_RUNNING -
    and a replayed request may only be claimed if one was actually replayed.
    """
    monkeypatch.setenv("AI_DOCTOR_AGENT_MODE", "deterministic")
    result = DoctorRunner().heal_incident(dict(INCIDENT))

    if result["status"] != "RESOLVED":
        assert result["resolved_at"] is None
        return

    verification = result["verification"] or {}
    assert verification.get("runtime_state") == OLLAMA_RUNNING, (
        f"RESOLVED was reported but verification saw {verification.get('runtime_state')!r}"
    )
    assert verification.get("success") is True
    if result["retry_result"] is None:
        assert "replayed" not in _timeline_text(result).lower() or "No captured request" in _timeline_text(result)


def test_only_allowlisted_actions_are_ever_taken(no_aws, full_loop, monkeypatch):
    """No remediation outside the allowlist may appear in the record."""
    monkeypatch.setenv("AI_DOCTOR_AGENT_MODE", "deterministic")
    result = DoctorRunner().heal_incident(dict(INCIDENT))

    assert result["action_taken"] in (set(REMEDIATION_ALLOWLIST) | {"none"})
    for entry in result["audit_log"]:
        assert entry.get("action") in set(REMEDIATION_ALLOWLIST), entry
    for stage in result["timeline"]:
        action = (stage.get("details") or {}).get("action")
        if action:
            assert action in (set(REMEDIATION_ALLOWLIST) | {"none"}), stage


# =========================================================================
# Nothing secret leaves the machine
# =========================================================================


def test_no_secret_appears_anywhere_in_the_offline_record(no_aws, full_loop, monkeypatch):
    """
    The record is persisted and rendered. Even with the credential chain pinned
    empty, the serialised result must carry no credential-shaped material and no
    credential variable names, and sanitisation must be idempotent on it.
    """
    monkeypatch.setenv("AI_DOCTOR_AGENT_MODE", "deterministic")
    monkeypatch.setenv("API_KEY", "SECRET")
    result = DoctorRunner().heal_incident(dict(INCIDENT))

    serialised = str(sanitize_deep(result))
    for marker in ("AKIA", "aws_secret_access_key", "AWS_SECRET_ACCESS_KEY",
                   "session_token", "Authorization: Bearer", "api_key=SECRET",
                   "password=SECRET", "token=SECRET"):
        assert marker not in serialised, f"{marker!r} leaked into the offline record"
    # Sanitising an already-sanitised record must not change it.
    assert str(sanitize_deep(result)) == serialised


def test_the_offline_record_serialises_for_the_api(no_aws, full_loop, monkeypatch):
    """The backend returns this dict as JSON; it must be plain JSON-safe data."""
    import json

    monkeypatch.setenv("AI_DOCTOR_AGENT_MODE", "deterministic")
    result = DoctorRunner().heal_incident(dict(INCIDENT))
    encoded = json.dumps(result, default=str)
    assert encoded
    assert json.loads(encoded)["status"] == result["status"]


# =========================================================================
# The timeline: required vocabulary, in order, with nothing invented
# =========================================================================


@pytest.fixture
def offline_result(no_aws, full_loop, monkeypatch):
    """One real offline run, shared by the timeline assertions."""
    monkeypatch.setenv("AI_DOCTOR_AGENT_MODE", "deterministic")
    return DoctorRunner().heal_incident(dict(INCIDENT))


def test_every_timeline_entry_carries_a_stage_code_from_the_required_vocabulary(offline_result):
    """
    A consumer must be able to branch on a stable identifier rather than parse a
    display string, so every entry carries both - and the two cannot drift,
    because one helper emits them together.
    """
    timeline = offline_result["timeline"]
    assert timeline, "the loop produced no timeline at all"
    for entry in timeline:
        assert entry.get("stage_code") in TIMELINE_STAGE_CODES, entry
        assert entry.get("stage"), entry
        assert STAGE_CODES[entry["stage"]] == entry["stage_code"], (
            f"the display string and the code disagree: {entry['stage']!r} vs {entry['stage_code']!r}"
        )


def test_the_stages_appear_in_the_pipeline_order(offline_result):
    """
    DETECTED -> EVIDENCE_COLLECTED -> AI_DIAGNOSIS -> POLICY_CHECK ->
    REMEDIATION_STARTED -> VERIFICATION -> (RETRY) -> RECOVERED or FAILED.

    RETRY is optional: it appears only when a captured request was really
    replayed. Everything else is mandatory, and the order is what makes the
    timeline readable as a causal sequence.
    """
    codes = [entry["stage_code"] for entry in offline_result["timeline"]]
    required = [
        STAGE_DETECTED,
        STAGE_EVIDENCE_COLLECTED,
        STAGE_AI_DIAGNOSIS,
        STAGE_POLICY_CHECK,
        STAGE_REMEDIATION_STARTED,
        STAGE_VERIFICATION,
    ]
    positions = []
    for code in required:
        assert code in codes, f"{code} is missing from {codes}"
        positions.append(codes.index(code))
    assert positions == sorted(positions), f"stages are out of order: {codes}"
    assert codes[0] == STAGE_DETECTED
    assert codes[-1] in (STAGE_RECOVERED, STAGE_FAILED)
    # A terminal stage appears exactly once, at the end.
    assert codes.count(STAGE_RECOVERED) + codes.count(STAGE_FAILED) == 1


def test_the_retry_stage_appears_only_when_a_request_was_really_replayed(offline_result):
    """
    A stage that did not happen must not appear. Here the remediation itself
    failed, so nothing was replayed - and the timeline must not imply otherwise.
    """
    codes = [entry["stage_code"] for entry in offline_result["timeline"]]
    replayed = isinstance(offline_result.get("retry_result"), dict)
    assert (STAGE_RETRY in codes) == replayed, (
        f"RETRY present={STAGE_RETRY in codes} but retry_result present={replayed}"
    )


def test_the_ai_diagnosis_stage_states_which_engine_answered(offline_result):
    """
    Requirement: AI_DIAGNOSIS shows the agent mode, the model, the confidence, the
    evidence it relied on and the recommended action - so a reader can tell a
    model diagnosis from a rule-engine one without opening any other field.
    """
    entry = next(e for e in offline_result["timeline"] if e["stage_code"] == STAGE_AI_DIAGNOSIS)
    summary = entry["details"]["ai_diagnosis"]

    for key in ("agent_mode", "agent_status", "diagnosis_outcome", "used_llm",
                "bedrock_invoked", "model_id", "aws_region", "confidence",
                "evidence_ids", "recommended_action", "requires_human"):
        assert key in summary, f"AI_DIAGNOSIS is missing {key}"

    assert summary["agent_mode"] == "deterministic"
    assert summary["used_llm"] is False
    assert summary["bedrock_invoked"] is False
    assert summary["model_id"] is None, "an offline run must not name a model"
    assert summary["recommended_action"] in (set(REMEDIATION_ALLOWLIST) | {"none"})
    # The offline engine has no evidence catalogue, so its probe names are the
    # linkage - and the entry must carry one or the other, never neither.
    assert summary["evidence_ids"] or summary["corroborating_probes"]
    # The description names the engine too, since that is what a reader sees first.
    assert "deterministic offline rule engine" in entry["description"]
    assert "Amazon Bedrock model" not in entry["description"]


def test_the_policy_check_is_its_own_visible_stage(offline_result):
    """
    The gate between a recommendation and an execution is the boundary a security
    reviewer needs to see, so it is a stage rather than a detail buried inside
    another one.
    """
    entry = next(e for e in offline_result["timeline"] if e["stage_code"] == STAGE_POLICY_CHECK)
    assert entry["details"], "the policy stage records nothing"
    # Deterministic mode produces no model recommendation to gate; the entry says
    # so and points at the layer that does enforce the allowlist.
    assert entry["details"]["layer"] == "remediation_allowlist"
    assert entry["details"]["requested_action"] == offline_result["action_taken"]
    assert entry["details"]["allowlisted"] is (
        offline_result["action_taken"] in REMEDIATION_ALLOWLIST
    )


def test_no_timeline_entry_contains_a_secret_or_a_raw_prompt(offline_result):
    """
    The timeline is persisted and rendered. It must carry conclusions, never the
    prompt that produced them and never credential material.
    """
    blob = str(offline_result["timeline"])
    for forbidden in (
        "You are the diagnosis agent for AI Doctor",   # the system prompt
        "===END-OF-UNTRUSTED-EVIDENCE===",             # the evidence fence
        "AKIA",
        "AWS_SECRET_ACCESS_KEY=",
        "Authorization: Bearer",
        "password=",
        "api_key=",
    ):
        assert forbidden not in blob, f"the timeline contains {forbidden!r}"


def test_nothing_in_this_file_imports_the_fake_bedrock_transport():
    """
    Suite A must not be able to borrow suite B's fake. Parsed from the AST so the
    docstring above - which names the fake files - cannot trip the check.
    """
    import ast
    import inspect
    import sys

    tree = ast.parse(inspect.getsource(sys.modules[__name__]))
    modules = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            modules.append(node.module or "")
    assert not [m for m in modules if "_fake_bedrock" in m], modules
    assert "json" in modules and "pytest" in modules, modules
