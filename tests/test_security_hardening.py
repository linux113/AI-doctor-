"""
Security hardening and lifecycle-correctness regression tests.

Every test here pins a specific defect that was found and fixed during the
technical audit of the request lifecycle, the deterministic root-cause logic
and the security boundary. They are written to fail loudly if a guardrail is
later relaxed.
"""

import importlib
import os

import psutil
import pytest

from runner.diagnostics import redact_sensitive_data
from runner.diagnosis import diagnose
from runner.doctor_runner import doctor_runner
from runner.pidfile import is_trusted_ollama_pid, read_trusted_pid
from runner.remediation import retry_request, start_ollama, stop_ollama
from runner.remediation_registry import remediation_registry
from runner.security import validate_retry_url


# =========================================================================
# 1. SSRF: structural URL validation replaces the bypassable prefix check
# =========================================================================

BYPASS_ATTEMPTS = [
    "http://127.0.0.1.evil.com/steal",       # suffix of an allowed host
    "http://localhost.evil.com/steal",
    "http://localhost@evil.com/steal",       # userinfo trick
    "http://127.0.0.1@evil.com/steal",
    "http://evil.com/?next=http://127.0.0.1",
    "http://evil.com/#http://127.0.0.1",
    "http://EVIL.COM",
    "file:///etc/passwd",                    # non-HTTP scheme
    "gopher://127.0.0.1:25/_MAIL",
    "ftp://127.0.0.1/x",
    "http:///no-host",
    "",
    "not a url",
]


@pytest.mark.parametrize("url", BYPASS_ATTEMPTS)
def test_ssrf_bypass_attempts_are_rejected(url):
    allowed, reason = validate_retry_url(url)
    assert allowed is False, f"expected {url!r} to be rejected"
    assert reason


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:11434/api/tags",
        "http://127.0.0.1:8000/api/demo/query",
        "http://localhost:8000/api/incidents",
        "https://127.0.0.1:8443/secure",
        "http://[::1]:8000/api/system-status",
    ],
)
def test_legitimate_loopback_destinations_are_allowed(url):
    allowed, _ = validate_retry_url(url)
    assert allowed is True


def test_retry_request_enforces_the_guard_end_to_end():
    """The guard must be reachable through the remediation itself, not just the helper."""
    res = retry_request("http://127.0.0.1.evil.com/steal", timeout=1.0)
    assert res["success"] is False
    assert "Security validation failed" in res["error"]


def test_retry_request_does_not_leak_the_hostile_url():
    """A rejected destination is attacker-controlled content; it must not be echoed."""
    hostile = "http://localhost@evil.com/exfil?d=secret"
    res = retry_request(hostile, timeout=1.0)
    assert "evil.com" not in res["error"]


# =========================================================================
# 2. Remediation registry must not mask an action's own failure
# =========================================================================


def test_registry_propagates_inner_failure():
    """
    A callable that returns {"success": False} without raising used to be
    reported as a SUCCESS, which made the runner blame the VERIFY stage for a
    broken FIX.
    """
    original = remediation_registry._actions["retry_request"]["fn"]
    remediation_registry._actions["retry_request"]["fn"] = lambda **kw: {
        "action": "retry_request",
        "success": False,
        "error": "simulated inner failure",
    }
    try:
        out = remediation_registry.execute("retry_request", url="http://127.0.0.1:8000/x")
        assert out["success"] is False
        assert out["error"] == "simulated inner failure"
        assert out["result"]["success"] is False
    finally:
        remediation_registry._actions["retry_request"]["fn"] = original


def test_registry_records_failed_status_in_audit_log():
    original = remediation_registry._actions["retry_request"]["fn"]
    remediation_registry._actions["retry_request"]["fn"] = lambda **kw: {
        "action": "retry_request",
        "success": False,
        "error": "audit me",
    }
    try:
        remediation_registry.execute("retry_request", url="http://127.0.0.1:8000/x")
        entry = remediation_registry.get_audit_log(limit=1)[-1]
        assert entry["status"] == "FAILED"
        assert entry["error"] == "audit me"
        assert entry["allowed"] is True
    finally:
        remediation_registry._actions["retry_request"]["fn"] = original


def test_registry_treats_actions_without_success_key_as_successful():
    """
    An action that returns cleanly without a "success" key is a success.

    The callable is replaced rather than the real `stop_ollama` being invoked, so
    this asserts the registry's verdict logic without touching any process and
    without depending on a real Ollama installation.
    """
    original = remediation_registry._actions["stop_ollama"]["fn"]
    remediation_registry._actions["stop_ollama"]["fn"] = lambda: {
        "action": "stop_ollama",
        "terminated_pids": [],
    }
    try:
        out = remediation_registry.execute("stop_ollama")
        assert out["success"] is True
        assert out["result"]["action"] == "stop_ollama"
    finally:
        remediation_registry._actions["stop_ollama"]["fn"] = original


def test_fix_failure_is_attributed_to_the_fix_stage():
    original = remediation_registry._actions["start_ollama"]["fn"]
    remediation_registry._actions["start_ollama"]["fn"] = lambda: {
        "action": "start_ollama",
        "success": False,
        "error": "Timeout waiting for Ollama to bind to port 11434.",
    }
    try:
        out = doctor_runner.run_remediation_and_verify("start_ollama")
        assert out["success"] is False
        assert out["stage"] == "FIX", "a failed action must not be reported as a VERIFY failure"
        assert "bind to port 11434" in out["error"]
    finally:
        remediation_registry._actions["start_ollama"]["fn"] = original
        start_ollama()


def test_timeline_separates_fix_failure_from_verification():
    stop_ollama()
    original = remediation_registry._actions["start_ollama"]["fn"]
    remediation_registry._actions["start_ollama"]["fn"] = lambda: {
        "action": "start_ollama",
        "success": False,
        "error": "daemon crashed on boot",
    }
    try:
        out = doctor_runner.heal_incident({"incident_id": "inc-fixfail", "error": "boom"})
        stages = {t["stage"]: t for t in out["timeline"]}

        assert out["status"] == "FAILED"
        assert out["failed_stage"] == "FIX"
        assert stages["REMEDIATION"]["details"]["fix_succeeded"] is False
        assert "failed" in stages["REMEDIATION"]["description"]
        # Verification never ran, and the timeline must say so rather than
        # implying the service was checked and found down.
        assert "Skipped" in stages["VERIFYING"]["description"]
        assert stages["VERIFYING"]["verified"] is False
        assert "FIX" in stages["FAILED"]["description"]
    finally:
        remediation_registry._actions["start_ollama"]["fn"] = original
        start_ollama()


# =========================================================================
# 3. retry_request remediation must receive the captured request context
# =========================================================================


def test_retry_remediation_passes_the_captured_url_to_the_action(local_http_server):
    """
    When the diagnosis is retry_request, the runner used to invoke the action
    with no arguments. `url` is required, so it raised TypeError and every
    "infrastructure looks healthy" incident failed at the FIX stage.

    The captured request is replayed against a generic local listener: the defect
    is about argument passing, which has no Ollama dependency. The full
    RESOLVED-path version of this test is in tests/test_ollama_integration.py.
    """
    _host, _port, url = local_http_server
    calls = []
    original = remediation_registry._actions["retry_request"]["fn"]

    def spy(**kwargs):
        calls.append(kwargs)
        return original(**kwargs)

    remediation_registry._actions["retry_request"]["fn"] = spy
    try:
        out = doctor_runner.run_remediation_and_verify(
            "retry_request",
            failed_request_context={"url": url, "method": "GET"},
            incident_id="inc-retry-args",
        )
        assert len(calls) == 1, f"expected exactly one replay, got {calls}"
        assert calls[0]["url"] == url
        assert calls[0]["method"] == "GET"
        # A TypeError from a missing `url` would surface as a FIX-stage failure.
        assert out.get("stage") != "FIX", out.get("error")
    finally:
        remediation_registry._actions["retry_request"]["fn"] = original


def test_retry_remediation_does_not_replay_twice(local_http_server):
    """
    The remediation IS the replay; the separate RETRY step must not re-issue it.

    A double replay of a non-idempotent POST is a real fault, so the call count
    is asserted rather than the recovery outcome.
    """
    _host, _port, url = local_http_server
    calls = []
    original = remediation_registry._actions["retry_request"]["fn"]

    def spy(**kwargs):
        calls.append(kwargs.get("url"))
        return original(**kwargs)

    remediation_registry._actions["retry_request"]["fn"] = spy
    try:
        doctor_runner.run_remediation_and_verify(
            "retry_request",
            failed_request_context={"url": url, "method": "POST", "payload": {"prompt": "x"}},
            incident_id="inc-once",
        )
        assert len(calls) == 1, f"expected exactly one replay, got {calls}"
    finally:
        remediation_registry._actions["retry_request"]["fn"] = original


def test_retry_remediation_without_context_fails_cleanly():
    """
    retry_request with no captured request must fail at the FIX stage with a
    clear reason, instead of raising TypeError inside the action.

    Called directly so the assertion does not depend on which hypothesis the
    evidence happens to select on this machine.
    """
    out = doctor_runner.run_remediation_and_verify(
        "retry_request", failed_request_context=None, incident_id="inc-nocontext"
    )
    assert out["success"] is False
    assert out["stage"] == "FIX"
    assert out["action"] == "retry_request"
    assert "no request context" in out["error"]


def test_heal_incident_without_context_routes_through_the_allowlist(ollama_state):
    """
    heal_incident must still produce a complete, honest timeline when there is no
    request context to replay - whatever the runtime state on this machine.
    """
    from runner.ollama_runtime import OLLAMA_NOT_INSTALLED

    out = doctor_runner.heal_incident({"incident_id": "inc-nocontext2", "error": "boom"})
    assert out["incident_id"] == "inc-nocontext2"
    stages = [t["stage"] for t in out["timeline"]]
    assert stages[0] == "DETECTED"
    assert "ROOT CAUSE FOUND" in stages
    assert stages[-1] in ("RESOLVED", "FAILED")
    if ollama_state == OLLAMA_NOT_INSTALLED:
        # No allowlisted action can install a runtime, so this must not resolve.
        assert out["status"] == "FAILED"
        assert out["runtime_state"] == OLLAMA_NOT_INSTALLED
        assert out["requires_human"] is True
    assert out["audit_log"], "every remediation attempt must leave an audit trail"
    assert all(e["incident_id"] == "inc-nocontext2" for e in out["audit_log"])


def test_heal_incident_returns_the_incident_id():
    """heal_incident used to read incident_data["id"]; the field is "incident_id"."""
    start_ollama()
    out = doctor_runner.heal_incident({
        "incident_id": "inc-idcheck",
        "error": "boom",
        "request_context": {"url": "http://127.0.0.1:11434/api/tags", "method": "GET"},
    })
    assert out["incident_id"] == "inc-idcheck"


def test_heal_incident_surfaces_the_detected_error():
    """
    The Incident model field is `detected_error`. heal_incident read `error`,
    so every DETECTED timeline entry on the live path said "Unknown error" and
    the actual failure message was discarded.
    """
    start_ollama()
    out = doctor_runner.heal_incident({
        "incident_id": "inc-errormsg",
        "detected_error": "ConnectionRefusedError: Failed to connect to Ollama on port 11434",
        "request_context": {"url": "http://127.0.0.1:11434/api/tags", "method": "GET"},
    })
    detected = next(t for t in out["timeline"] if t["stage"] == "DETECTED")
    assert "ConnectionRefusedError" in detected["description"]
    assert "Unknown error" not in detected["description"]


# =========================================================================
# 4. Confidence must be evidence-derived, not a constant
# =========================================================================

DOWN = {
    "port_11434": {"is_open": False},
    "process_ollama": {"is_running": False},
    "ollama_api": {"is_available": False},
}
HEALTHY = {
    "port_11434": {"is_open": True},
    "process_ollama": {"is_running": True},
    "ollama_api": {"is_available": True},
}
PROC_UP_PORT_DOWN = {
    "port_11434": {"is_open": False},
    "process_ollama": {"is_running": True},
    "ollama_api": {"is_available": False},
}
PORT_OPEN_API_DOWN = {
    "port_11434": {"is_open": True},
    "process_ollama": {"is_running": True},
    "ollama_api": {"is_available": False},
}
INCONSISTENT = {
    "port_11434": {"is_open": False},
    "process_ollama": {"is_running": True},
    "ollama_api": {"is_available": True},
}


def test_confidence_is_not_a_constant():
    scores = {
        diagnose(ev, "boom").confidence
        for ev in (DOWN, HEALTHY, PROC_UP_PORT_DOWN, PORT_OPEN_API_DOWN, INCONSISTENT)
    }
    assert len(scores) > 1, "confidence must vary with the evidence"


def test_unexplained_failure_gets_low_confidence():
    """This branch used to claim 0.98 - near certainty about an unknown cause."""
    d = diagnose(HEALTHY, "weird application error")
    assert d.recommended_remediation == "retry_request"
    assert d.confidence <= 0.40
    assert d.hypothesis == "unexplained_application_error"
    assert d.notes  # must explain why confidence is low


def test_fully_corroborated_outage_gets_high_confidence():
    d = diagnose(DOWN, "ConnectionRefusedError")
    assert d.recommended_remediation == "start_ollama"
    assert d.confidence >= 0.85
    assert len(d.corroborating_probes) == 3
    assert d.contradicting_probes == []
    # Wording relied on by tests/test_api_endpoints.py
    assert "Ollama daemon process is terminated" in d.root_cause


def test_contradictory_probes_lower_confidence_and_flag_inconsistency():
    d = diagnose(INCONSISTENT, "boom")
    assert d.evidence_consistent is False
    assert d.contradicting_probes
    assert d.confidence < diagnose(DOWN, "boom").confidence


def test_confidence_is_monotonic_in_corroboration():
    assert diagnose(DOWN, "e").confidence > diagnose(PORT_OPEN_API_DOWN, "e").confidence
    assert diagnose(PORT_OPEN_API_DOWN, "e").confidence > diagnose(HEALTHY, "e").confidence


def test_impossible_probe_combination_is_caught_before_any_hypothesis():
    """
    A closed socket and a successful HTTP response through that same socket
    cannot both be true. This must not be absorbed by the "process alive but
    unbound" branch and reported at high confidence.
    """
    d = diagnose(INCONSISTENT, "boom")
    assert d.hypothesis == "contradictory_probes"
    assert d.evidence_consistent is False
    assert d.confidence <= 0.40


def test_healthy_api_with_blind_process_probe_is_flagged():
    """
    The HTTP API answering proves the service runs, so a missing PID means the
    process probe is blind - not that the service is down.
    """
    d = diagnose(
        {
            "port_11434": {"is_open": True},
            "process_ollama": {"is_running": False},
            "ollama_api": {"is_available": True},
        },
        "boom",
    )
    assert d.hypothesis == "unexplained_application_error"
    assert d.evidence_consistent is False
    assert "blind" in (d.notes or "")
    assert d.confidence <= 0.40


def test_root_cause_decision_table_has_exactly_one_implementation():
    """
    The decision table used to exist twice - once in runner/doctor_runner.py and
    once in agent/strands_agent.py - and the copies had drifted. The agent-layer
    placeholder that held the second copy is gone: agent/ now contains a real
    Bedrock agent and no rule engine of its own.

    These assertions pin that. If a private duplicate ever reappears, or if the
    runner stops delegating to runner.diagnosis, this fails.
    """
    from pathlib import Path

    import runner.diagnosis as diagnosis_module

    # 1. The runner delegates to the shared engine instead of carrying a copy.
    for ev in (DOWN, HEALTHY, PROC_UP_PORT_DOWN, PORT_OPEN_API_DOWN, INCONSISTENT):
        runner_result = doctor_runner.diagnose_root_cause(ev, "boom")
        assert runner_result == diagnose(ev, "boom").as_dict()

    # 2. No agent module re-implements the table or fakes an AWS client.
    agent_dir = Path(diagnosis_module.__file__).resolve().parent.parent / "agent"
    forbidden_definitions = (
        "def evaluate_root_cause",
        "def diagnose_root_cause",
        "class StrandsAgentPlaceholder",
        "class BedrockClientPlaceholder",
        "class BedrockClientInterface",
        "class StrandsAgentInterface",
    )
    for path in sorted(agent_dir.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        for marker in forbidden_definitions:
            assert marker not in source, f"{path.name} re-implements the agent seam: {marker}"

    # 3. The fake AWS client module no longer exists at all.
    assert not (agent_dir / "bedrock_client.py").exists(), (
        "agent/bedrock_client.py was a placeholder that stood in for Amazon "
        "Bedrock; the real integration lives in agent/strands_agent.py"
    )


def test_both_diagnosis_producers_return_the_same_report_contract():
    """
    The deterministic engine and the Bedrock agent are two producers of one
    report shape. If they disagree, the runner, the API and the dashboard would
    each need a branch - which is exactly how the original drift happened.
    """
    from agent.diagnosis_agent import REPORT_CONTRACT_KEYS

    engine_keys = set(diagnose(DOWN, "boom").as_dict())
    assert set(REPORT_CONTRACT_KEYS) == engine_keys

    outcome = doctor_runner.diagnose_incident(
        {"incident_id": "inc-contract", "detected_error": "boom"}, DOWN, "boom"
    )
    # Every contract key is present, whichever engine answered.
    assert engine_keys <= set(outcome)
    # And the mode is always stated explicitly.
    assert outcome["agent_mode"] in ("bedrock", "deterministic", "openrouter")
    assert outcome["agent_status"]
    assert outcome["agent_note"]
    assert outcome["agent_telemetry"]["agent_mode"] == outcome["agent_mode"]
    # In this environment no model can run, so nothing may claim it did.
    assert outcome["used_llm"] is False or outcome["agent_mode"] == "openrouter"
    assert outcome["agent_telemetry"]["model_id"] is None or outcome["agent_mode"] == "openrouter"


def test_diagnosis_serialisation_keeps_the_legacy_contract():
    d = diagnose(DOWN, "boom").as_dict()
    assert {"root_cause", "recommended_remediation", "confidence"} <= set(d)


# =========================================================================
# 5. PID file must be treated as a hint, never as authority
# =========================================================================


def test_refuses_to_signal_the_ai_doctor_process_itself():
    trusted, reason = is_trusted_ollama_pid(os.getpid())
    assert trusted is False
    assert "itself" in reason


def test_refuses_a_stale_or_foreign_pid(tmp_path):
    """
    stop_ollama used to SIGTERM whatever integer sat in a world-writable
    /tmp file, letting any local user aim the remediation at another process.
    """
    victim = os.getppid()
    pid_file = tmp_path / "ollama.pid"
    pid_file.write_text(str(victim))
    os.chmod(pid_file, 0o666)

    pid, reason = read_trusted_pid(str(pid_file))
    assert pid is None
    assert reason is not None
    assert psutil.pid_exists(victim), "the unverified process must not have been touched"


def test_refuses_a_malformed_pid_file(tmp_path):
    pid_file = tmp_path / "ollama.pid"
    pid_file.write_text("not-an-integer")
    pid, reason = read_trusted_pid(str(pid_file))
    assert pid is None
    assert reason is not None


def test_stop_ollama_refuses_a_tampered_pid_file(tmp_path):
    """
    The PID file lives in world-writable /tmp, so its contents are untrusted.

    A PID whose live process is not the Ollama runtime must be refused and
    reported, never signalled. The runtime's process discovery and port probe are
    stubbed out so this unit test cannot signal a real daemon that happens to be
    running on the developer's machine.
    """
    from runner.ollama_runtime import OllamaRuntime

    victim = os.getppid()
    pid_file = tmp_path / "ollama.pid"
    pid_file.write_text(str(victim))
    os.chmod(pid_file, 0o666)

    runtime = OllamaRuntime(pid_file=str(pid_file))
    runtime._resolution_attempted = True
    runtime._resolved_executable = None  # deterministic "not installed"
    runtime.find_ollama_processes = lambda: []
    runtime.port_is_open = lambda timeout=1.0: False

    out = runtime.stop().as_dict()

    assert victim not in out["terminated_pids"]
    assert out["refused_pids"], "a tampered PID must be reported as refused"
    assert str(victim) in out["refused_pids"][0]["reason"]
    assert psutil.pid_exists(victim), "the tampered PID target was signalled"


def test_stop_ollama_refuses_a_malformed_pid_file(tmp_path):
    from runner.ollama_runtime import OllamaRuntime

    pid_file = tmp_path / "ollama.pid"
    pid_file.write_text("not-an-integer")

    runtime = OllamaRuntime(pid_file=str(pid_file))
    runtime._resolution_attempted = True
    runtime._resolved_executable = None
    runtime.find_ollama_processes = lambda: []
    runtime.port_is_open = lambda timeout=1.0: False

    out = runtime.stop().as_dict()
    assert out["terminated_pids"] == []
    assert out["refused_pids"]
    assert "does not contain an integer" in out["refused_pids"][0]["reason"]


def test_stop_ollama_refuses_to_signal_the_ai_doctor_process(tmp_path):
    """Even a PID file naming our own process must not cause self-termination."""
    from runner.ollama_runtime import OllamaRuntime

    pid_file = tmp_path / "ollama.pid"
    pid_file.write_text(str(os.getpid()))

    runtime = OllamaRuntime(pid_file=str(pid_file))
    runtime._resolution_attempted = True
    runtime._resolved_executable = None
    runtime.find_ollama_processes = lambda: []
    runtime.port_is_open = lambda timeout=1.0: False

    out = runtime.stop().as_dict()
    assert os.getpid() not in out["terminated_pids"]
    assert any("AI Doctor process itself" in r["reason"] for r in out["refused_pids"])


def test_accepts_the_real_service_pid_file(requires_real_ollama):
    """
    INTEGRATION - a PID file written by a verified start of the real daemon must
    be accepted. Skips when Ollama is absent; never satisfied by a stand-in.
    """
    runtime = requires_real_ollama
    assert runtime.start().success, "could not start the real daemon"

    pid, reason = read_trusted_pid(runtime.pid_file)
    assert reason is None
    assert pid is not None
    trusted, _ = is_trusted_ollama_pid(pid)
    assert trusted is True


# =========================================================================
# 6. Credential redaction coverage
# =========================================================================

# Provider-shaped fixtures are assembled at runtime rather than written as
# literal strings. Every value below is structurally valid for the redaction
# regex under test, but committing credential-shaped literals trips GitHub
# secret-scanning push protection - and shipping a fake "AKIA..." key inside a
# security-hardening commit is exactly the habit that causes real leaks.
_FILLER_UPPER = "A1B2C3D4E5F6G7H8I9J0KLMNOPQRSTUVWX"
_FILLER_LOWER = _FILLER_UPPER.lower()

# Assembled so no single credential-shaped token appears in the source text.
_JWT = ".".join([
    "eyJhbGciOiJIUzI1NiJ9",
    "eyJzdWIiOiIxMjM0NTY3ODkwIn9",
    "dBjftJeZ4CVPmB92K27uhbUJU1p1r",
])
_PEM = "\n".join([
    "-----BEGIN RSA PRIVATE KEY-----",
    "MIIEowIBAAKCAQEA",
    "-----END RSA PRIVATE KEY-----",
])

SECRET_SAMPLES = [
    ("AKIA" + _FILLER_UPPER[:16], "AWS access key ID"),
    ("ASIA" + _FILLER_UPPER[:16], "AWS temporary key ID"),
    ("sk-ant-api03-" + _FILLER_LOWER[:24], "Anthropic key"),
    ("sk-proj-" + _FILLER_LOWER[:24], "OpenAI project key"),
    ("ghp_" + "0123456789" + _FILLER_LOWER[:26], "GitHub classic PAT"),
    ("github_pat_" + _FILLER_LOWER[:24], "GitHub fine-grained PAT"),
    ("xoxb-" + "012345678901-0123456789012-" + _FILLER_LOWER[:26], "Slack token"),
    ("AIza" + "Sy" + _FILLER_UPPER[:33], "Google API key"),
    ("sk_live_" + _FILLER_LOWER[:20], "Stripe secret key"),
    ("sk-" + _FILLER_LOWER[:28], "generic sk- prefixed key"),
    (_JWT, "JWT"),
    (_PEM, "PEM private key"),
    ("postgres://admin:" + "sup3rs3cret" + "@db.internal:5432/app", "connection-string password"),
    ("x-api-key: " + _FILLER_LOWER[:18], "x-api-key header"),
    ('password = "' + _FILLER_LOWER[:13] + '"', "password assignment"),
    ("aws_secret_access_key=" + _FILLER_LOWER[:30], "AWS secret access key assignment"),
    ("token: " + _FILLER_LOWER[:20], "token assignment"),
]


@pytest.mark.parametrize("secret,label", SECRET_SAMPLES)
def test_secret_is_redacted(secret, label):
    out = redact_sensitive_data(f"context before {secret} context after")
    assert secret not in out, f"{label} was not redacted"
    assert "REDACTED" in out


BENIGN_SAMPLES = [
    "Ollama daemon successfully started with PID 4242.",
    "ConnectionRefusedError: Failed to connect to Ollama service at http://127.0.0.1:11434/api/generate",
    "Port 11434 closed: True",
    "HTTP GET http://127.0.0.1:11434/api/tags returned 200 in 12ms",
    "Models available: 1",
    "The password rotation policy is documented in the runbook.",
]


@pytest.mark.parametrize("line", BENIGN_SAMPLES)
def test_operational_log_lines_are_not_over_redacted(line):
    assert redact_sensitive_data(line) == line


# =========================================================================
# 7. Backend security posture: CORS and the optional token gate
# =========================================================================


def test_cors_never_combines_wildcard_origin_with_credentials():
    import backend.main as bm

    if "*" in bm.CORS_ORIGINS:
        assert bm.CORS_ALLOW_CREDENTIALS is False


def test_token_gate_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("AIDOCTOR_API_TOKEN", raising=False)
    import backend.main as bm

    importlib.reload(bm)
    try:
        assert bm.TOKEN_GATE_ENABLED is False
        # Read-only endpoints stay open, preserving local development.
        from fastapi.testclient import TestClient

        assert TestClient(bm.app).get("/health").status_code == 200
    finally:
        importlib.reload(bm)


def test_token_gate_enforces_on_process_controlling_endpoints(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("AIDOCTOR_API_TOKEN", "s3cret-gate-token")
    import backend.main as bm

    importlib.reload(bm)
    try:
        assert bm.TOKEN_GATE_ENABLED is True
        client = TestClient(bm.app)

        # No credentials -> 401 on every process-controlling route.
        for path in ("/api/demo/stop-ollama", "/api/demo/start-ollama", "/api/demo/simulate-incident"):
            assert client.post(path).status_code == 401, path
        assert client.post("/api/heal", json={"incident_id": "x"}).status_code == 401

        # Wrong credentials -> 403.
        bad = {"Authorization": "Bearer not-the-token"}
        assert client.post("/api/demo/stop-ollama", headers=bad).status_code == 403

        # Correct credentials -> past the gate. A 404 here proves the
        # dependency passed without mutating any process state.
        good = {"Authorization": "Bearer s3cret-gate-token"}
        assert client.post("/api/heal", json={"incident_id": "does-not-exist"}, headers=good).status_code == 404

        # Read-only endpoints remain open even with the gate on.
        assert client.get("/api/system-status").status_code == 200
    finally:
        monkeypatch.delenv("AIDOCTOR_API_TOKEN", raising=False)
        importlib.reload(bm)


def test_system_status_reports_security_posture_without_leaking_secrets(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("AIDOCTOR_API_TOKEN", "super-secret-value")
    import backend.main as bm

    importlib.reload(bm)
    try:
        body = TestClient(bm.app).get("/api/system-status").json()
        sec = body["security"]
        assert sec["token_gate_enabled"] is True
        assert sorted(sec["remediation_allowlist"]) == ["retry_request", "start_ollama", "stop_ollama"]
        assert "super-secret-value" not in str(body)
    finally:
        monkeypatch.delenv("AIDOCTOR_API_TOKEN", raising=False)
        importlib.reload(bm)


def test_explicit_cors_origins_enable_credentials(monkeypatch):
    monkeypatch.setenv("AIDOCTOR_CORS_ORIGINS", "https://dashboard.example.com")
    import backend.main as bm

    importlib.reload(bm)
    try:
        assert bm.CORS_ORIGINS == ["https://dashboard.example.com"]
        assert bm.CORS_ALLOW_CREDENTIALS is True
    finally:
        monkeypatch.delenv("AIDOCTOR_CORS_ORIGINS", raising=False)
        importlib.reload(bm)


# =========================================================================
# 8. Timestamps are timezone-aware and format-stable
# =========================================================================


def test_timestamps_are_fixed_width_utc_with_z_suffix():
    """created_at doubles as a DynamoDB RANGE key sorted lexicographically."""
    import re

    from runner.timeutil import now_iso

    ts = now_iso()
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", ts), ts

    from backend.models import Incident

    inc = Incident(detected_error="boom")
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", inc.created_at)



