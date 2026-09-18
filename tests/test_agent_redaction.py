"""
Redaction-boundary tests for the Bedrock path (requirement 8).

`runner/redaction.sanitize_deep` is the authoritative redactor. These tests prove
it is applied *before* anything reaches the model, by running the real agent
stack against a fake HTTP transport (tests/_fake_bedrock.py) and inspecting the
exact request payload that would have been sent to Amazon Bedrock.

No model call happens here. Nothing here is a live-AWS test - that is
tests/test_bedrock_live.py, which skips without credentials.
"""

import pytest

from agent.evidence import build_evidence_catalog, build_incident_summary
from agent.prompts import build_user_prompt
from agent.tools import ToolBudget, build_diagnostic_tools
from runner.diagnostics import get_recent_logs, record_log
from runner.redaction import sanitize_deep

from _fake_bedrock import (
    BASELINE,
    INCIDENT,
    WELL_FORMED_REPLY,
    FakeBedrockTransport,
    bedrock_config,
    make_transport_agent,
)

# The four secrets named in the requirement, embedded in nested evidence exactly
# as they would arrive from a captured request, a log line or a process
# environment. Values are distinctive so a substring search is unambiguous.
BEARER_HEADER = "Authorization: Bearer TokValue-9f3c-DoNotLeak"
API_KEY_PAIR = "api_key=ApiKeyValue-77ab-DoNotLeak"
PASSWORD_PAIR = "password=PassValue-5c1d-DoNotLeak"
AWS_SECRET_PAIR = "AWS_SECRET_ACCESS_KEY=AwsSecretValue-31ef-DoNotLeak"
PEM_BLOCK = (
    "-----BEGIN PRIVATE KEY-----\nMIIEvKeyMaterialDoNotLeak1234567890\n"
    "-----END PRIVATE KEY-----"
)
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJsZWFrIn0.SigDoNotLeakValue99"
AWS_KEY_ID = "AKIA" + "IOSFODNN7DONOTLK"   # AKIA + exactly 16 characters

SECRET_VALUES = [
    "TokValue-9f3c-DoNotLeak",
    "ApiKeyValue-77ab-DoNotLeak",
    "PassValue-5c1d-DoNotLeak",
    "AwsSecretValue-31ef-DoNotLeak",
    "MIIEvKeyMaterialDoNotLeak1234567890",
    "SigDoNotLeakValue99",
    # Concatenated so the source text never holds a complete 20-character AWS
    # access key ID; the *value* the test searches for is still the full string.
    "AKIA" + "IOSFODNN7DONOTLK",
]


def poisoned_evidence():
    """
    Real evidence shape from `DoctorRunner.collect_evidence()`, with secrets
    nested several levels down in every field the agent is allowed to see.
    """
    return {
        "collected_at": "2026-09-17T10:00:00Z",
        "runtime": {
            "installed": True,
            "state": "OLLAMA_STOPPED",
            "binary_path": "/usr/local/bin/ollama",
            # A captured environment dump from the failed service.
            "environment": {"AWS_SECRET_ACCESS_KEY": "AwsSecretValue-31ef-DoNotLeak"},
        },
        "port_11434": {"is_open": False, "status": "closed"},
        "process_ollama": {
            "is_running": False,
            "pids": [],
            # A command line that happens to carry a credential.
            "cmdline": f"/usr/local/bin/ollama serve --auth {BEARER_HEADER}",
        },
        "ollama_api": {"is_available": False, "last_error": API_KEY_PAIR},
        "recent_logs": [
            {"level": "ERROR", "message": "upstream connect failed", "service": "demo"},
            {"level": "ERROR", "message": f"request failed with {BEARER_HEADER}", "service": "demo"},
            {"level": "WARN", "message": f"config {API_KEY_PAIR} {PASSWORD_PAIR}", "service": "demo"},
            {"level": "WARN", "message": AWS_SECRET_PAIR, "service": "demo"},
            {"level": "ERROR", "message": f"key material: {PEM_BLOCK}", "service": "demo"},
            {"level": "ERROR", "message": f"token {JWT} rejected", "service": "demo"},
            {"level": "ERROR", "message": f"access key {AWS_KEY_ID} invalid", "service": "demo"},
        ],
    }


def poisoned_incident():
    """Incident metadata and request context, also carrying secrets."""
    return {
        "incident_id": "inc-redaction",
        "detected_error": f"HTTP 500: upstream rejected {BEARER_HEADER}",
        "error_class": "UpstreamError",
        "error_detail": f"{API_KEY_PAIR}; {AWS_SECRET_PAIR}",
        "http_status": 500,
        "service": "demo-inference-service",
        "runtime_state": "OLLAMA_STOPPED",
        "request_context": {
            "url": "http://127.0.0.1:11434/api/generate",
            "method": "POST",
            "headers": {
                "Authorization": BEARER_HEADER,
                "x-api-key": "ApiKeyValue-77ab-DoNotLeak",
                "cookie": "session_id=PassValue-5c1d-DoNotLeak",
            },
            "payload": {"prompt": "summarise", "password": "PassValue-5c1d-DoNotLeak"},
        },
    }


def assert_no_secret(blob: str, where: str) -> None:
    leaked = [s for s in SECRET_VALUES if s in blob]
    assert not leaked, f"{where} leaked secret value(s): {leaked}"


# =========================================================================
# The requirement: nothing reaches the Bedrock client
# =========================================================================


def test_no_secret_reaches_the_bedrock_request_payload():
    """
    The end-to-end assertion. Runs the REAL agent stack - real
    `strands.Agent`, real `BedrockModel`, real request construction - with only
    `client.converse` answered locally, then searches everything that would have
    been transmitted.
    """
    transport = FakeBedrockTransport(fields=dict(WELL_FORMED_REPLY))
    agent = make_transport_agent(bedrock_config(), transport)

    outcome = agent.diagnose(poisoned_incident(), poisoned_evidence(), BASELINE, "inc-redaction")

    assert outcome.status == "DIAGNOSED"
    assert transport.calls, "the model was never called, so nothing was proven"

    payload = transport.payload_json()
    assert_no_secret(payload, "Bedrock request payload")

    # Every part of the request, checked individually so a failure names the leak.
    assert_no_secret(transport.system_prompt(), "system prompt")
    assert_no_secret(transport.user_prompt(), "user prompt")
    assert_no_secret(str(transport.last_request["messages"]), "message history")
    assert_no_secret(str(transport.last_request.get("toolConfig")), "tool config")

    # And the report/telemetry that get persisted must not carry them either.
    assert_no_secret(str(outcome.report), "diagnosis report")
    assert_no_secret(str(outcome.telemetry.as_dict()), "agent telemetry")


# The six literal strings named in the redaction requirement, verbatim. Each must
# be impossible to send to Bedrock, and each must leave a marker behind so an
# operator can still see that something was removed.
REQUIREMENT_STRINGS = (
    "Authorization: Bearer SECRET",
    "api_key=SECRET",
    "password=SECRET",
    "AWS_ACCESS_KEY_ID=SECRET",
    "AWS_SECRET_ACCESS_KEY=SECRET",
    "token=SECRET",
)


def test_all_six_requirement_strings_cannot_reach_the_bedrock_request():
    """
    The requirement's end state, asserted at the wire.

    All six named literals are embedded in every shape real evidence takes -
    nested dicts, lists, an exception object, HTTP headers, log lines and the
    environment dump - and the REAL agent stack is run (real `strands.Agent`,
    real `BedrockModel`, real request construction; only `client.converse` is
    answered locally). What is then searched is the exact payload that would have
    been transmitted to Amazon Bedrock.

    This is the test that matters: a redactor that works on a string in isolation
    proves nothing about what the model actually receives.
    """
    evidence = poisoned_evidence()
    incident = poisoned_incident()

    # Every one of the six, in the containers evidence really arrives in.
    evidence["runtime"]["environment"].update({
        "captured_body": '{"AWS_ACCESS_KEY_ID": "SECRET", "token": "SECRET"}',
        "startup_error": RuntimeError(
            "ollama exited: Authorization: Bearer SECRET rejected, api_key=SECRET"
        ),
        "env_dump": [
            "AWS_ACCESS_KEY_ID=SECRET",
            "AWS_SECRET_ACCESS_KEY=SECRET",
            "token=SECRET",
        ],
    })
    evidence["recent_logs"].extend([
        {"level": "ERROR", "message": "header was Authorization: Bearer SECRET", "service": "demo"},
        {"level": "ERROR", "message": "config api_key=SECRET password=SECRET", "service": "demo"},
        {"level": "WARN", "message": '{"token": "SECRET"}', "service": "demo"},
    ])
    incident["request_context"]["headers"]["x-captured"] = "AWS_ACCESS_KEY_ID=SECRET"
    incident["request_context"]["payload"]["nested"] = {"deep": [{"token": "SECRET"}]}
    incident["error_detail"] += "; token=SECRET; AWS_ACCESS_KEY_ID=SECRET"

    transport = FakeBedrockTransport(fields=dict(WELL_FORMED_REPLY))
    agent = make_transport_agent(bedrock_config(), transport)
    outcome = agent.diagnose(incident, evidence, BASELINE, "inc-six-strings")

    assert transport.calls, "the model was never called, so nothing was proven"
    payload = transport.payload_json()
    assert payload, "no request payload was recorded"

    for literal in REQUIREMENT_STRINGS:
        assert literal not in payload, (
            f"{literal!r} reached the Bedrock request payload:\n{payload[:1200]}"
        )
        # Checked in each part of the request too, so a failure names the leak.
        assert literal not in transport.system_prompt(), f"{literal!r} in the system prompt"
        assert literal not in transport.user_prompt(), f"{literal!r} in the user prompt"
        assert literal not in str(transport.last_request["messages"]), (
            f"{literal!r} in the message history"
        )
        assert literal not in str(transport.last_request.get("toolConfig")), (
            f"{literal!r} in the tool config"
        )

    # The distinctive values from the nested fixtures must be gone as well.
    assert_no_secret(payload, "Bedrock request payload")
    assert_no_secret(str(outcome.report), "diagnosis report")
    assert_no_secret(str(outcome.telemetry.as_dict()), "telemetry")
    # And redaction demonstrably happened, rather than the evidence being dropped.
    assert "[REDACTED" in payload, "no redaction marker in the payload - was it applied at all?"


def test_the_exact_requirement_strings_are_redacted():
    """
    The requirement names six literal strings. Each is asserted individually,
    including that the surrounding key name survives (an operator still needs to
    know *which* credential was removed) while the value does not.
    """
    for raw, marker in (
        (BEARER_HEADER, "[REDACTED_HEADER]"),
        (API_KEY_PAIR, "[REDACTED_KEY]"),
        (PASSWORD_PAIR, "[REDACTED_PASSWORD]"),
        (AWS_SECRET_PAIR, "[REDACTED_KEY]"),
    ):
        cleaned = sanitize_deep(raw)
        assert marker in cleaned, f"{raw!r} -> {cleaned!r}"
        assert_no_secret(cleaned, f"redacted form of {raw!r}")

    # The literal shapes from the requirement text, using "SECRET" as the value.
    assert sanitize_deep("Authorization: Bearer SECRET") == "Authorization: [REDACTED_HEADER]"
    assert sanitize_deep("api_key=SECRET") == "api_key=[REDACTED_KEY]"
    assert sanitize_deep("password=SECRET") == "password=[REDACTED_PASSWORD]"
    assert sanitize_deep("AWS_ACCESS_KEY_ID=SECRET") == "AWS_ACCESS_KEY_ID=[REDACTED_KEY]"
    assert sanitize_deep("AWS_SECRET_ACCESS_KEY=SECRET") == "AWS_SECRET_ACCESS_KEY=[REDACTED_KEY]"
    assert sanitize_deep("token=SECRET") == "token=[REDACTED_TOKEN]"


@pytest.mark.parametrize("literal", REQUIREMENT_STRINGS)
def test_every_requirement_string_is_redacted_in_every_container(literal):
    """
    The same literal, placed in each container shape evidence actually arrives in:
    a bare string, a nested dict, a list, a dict used as a KEY, an exception
    message, an HTTP header value and a log line.

    Redaction that only works at the top level is redaction that fails in
    production, because evidence is always nested.
    """
    value = literal.split()[-1] if " " in literal else literal
    containers = {
        "bare string": literal,
        "nested dict": {"runtime": {"environment": {"dump": literal}}},
        "list": [{"level": "ERROR", "message": literal}],
        "dict key": {literal: "some value"},
        "exception message": RuntimeError(literal),
        "exception in a dict": {"last_error": ValueError(f"call failed: {literal}")},
        "header value": {"headers": {"x-captured": literal}},
        "deep nesting": {"a": {"b": [{"c": {"d": [literal]}}]}},
    }
    for where, container in containers.items():
        cleaned = sanitize_deep(container)
        blob = str(cleaned)
        assert literal not in blob, f"{where}: {literal!r} survived -> {blob!r}"
        assert "[REDACTED" in blob, f"{where}: nothing was redacted -> {blob!r}"
        # The credential VALUE itself must be gone, not merely the key.
        if value and value != literal:
            assert value not in blob, f"{where}: value {value!r} survived -> {blob!r}"


def test_serialised_json_credentials_are_redacted_not_just_key_value_pairs():
    """
    Regression. Every key/value rule required the key name to be followed
    directly by ":" or "=", so a credential inside a SERIALIZED JSON document -
    a captured request body, an environment dump, an exception payload, a log
    line - survived untouched and would have been sent to the model. The quoted
    key form ("password": "hunter2") is the shape real evidence actually has.
    """
    documents = [
        '{"AWS_ACCESS_KEY_ID": "SECRET"}',
        '{"aws_secret_access_key": "wJalrXUtnFEMI-DoNotLeak"}',
        '{"password": "hunter2-DoNotLeak"}',
        '{"api_key": "sk-DoNotLeak"}',
        '{"token": "tok-DoNotLeak"}',
        '{"session_id": "SessValue-DoNotLeak"}',
        '{"authorization": "AuthValue-DoNotLeak"}',
        '{"headers": {"x-api-key": "ApiKeyValue-DoNotLeak"}}',
        'captured body: {"prompt":"hi","password":"PassValue-DoNotLeak"}',
    ]
    for document in documents:
        cleaned = str(sanitize_deep(document))
        assert "DoNotLeak" not in cleaned, f"{document!r} -> {cleaned!r}"
        assert "[REDACTED" in cleaned, f"{document!r} -> {cleaned!r}"
        # Idempotent: re-sanitising a marker must not double-redact.
        assert sanitize_deep(cleaned) == cleaned


def test_an_exception_object_nested_in_evidence_cannot_leak():
    """
    Regression. `sanitize_deep` used to return any non-primitive untouched on the
    assumption that the only such values were ints and None. An exception raised
    by a failed HTTP call embeds the credentials it was given, so an exception
    sitting inside the evidence bundle reached the model verbatim once the bundle
    was serialised. Scalars must keep their type; everything else becomes
    redacted text.
    """
    exc = RuntimeError("connection refused with password=SECRET and token=SECRET")
    cleaned = sanitize_deep({"ollama_api": {"last_error": exc}})
    blob = str(cleaned)
    assert "password=SECRET" not in blob and "token=SECRET" not in blob
    assert "[REDACTED_PASSWORD]" in blob and "[REDACTED_TOKEN]" in blob

    # Scalars are preserved, so counters and JSON shapes do not change type.
    for value in (None, True, False, 0, 42, 3.5):
        out = sanitize_deep({"k": value})["k"]
        assert out is value or out == value, value
        assert type(out) is type(value), f"{value!r} became {type(out).__name__}"

    # A hostile __str__ must not crash redaction, and must not pass through.
    class Unrenderable:
        def __str__(self):
            raise ValueError("no")

        def __repr__(self):
            raise ValueError("no")

    assert sanitize_deep(Unrenderable()) == "[REDACTED_UNRENDERABLE_OBJECT]"


def test_short_bearer_credentials_are_redacted_not_just_long_ones():
    """
    Regression: the long-form bearer rule required 20+ characters, so an 18
    character token survived and reached the prompt. Both the Authorization
    header form and the bare scheme form are covered now.
    """
    for raw in (
        "Authorization: Bearer SECRET-TOKEN-VALUE",
        "Authorization: Bearer abc123",
        "authorization=bearer shorttok",
        "Bearer tok-9f3c",
        "curl -H 'Authorization: Bearer abc123-def456' https://internal",
    ):
        cleaned = sanitize_deep(raw)
        assert "[REDACTED" in cleaned, f"{raw!r} -> {cleaned!r}"
        for fragment in ("SECRET-TOKEN-VALUE", "abc123", "shorttok", "tok-9f3c", "def456"):
            assert fragment not in cleaned, f"{fragment!r} survived in {cleaned!r}"


def test_prose_is_not_mangled_by_the_bearer_rule():
    """
    Redaction must not destroy diagnostic meaning. "Bearer authentication
    failed" is a sentence, not a credential, and an operator needs to read it.
    """
    prose = "Bearer authentication failed for the service account"
    assert sanitize_deep(prose) == prose


# =========================================================================
# Redaction happens BEFORE cataloguing and BEFORE prompting
# =========================================================================


def test_evidence_catalog_is_built_from_redacted_input():
    """The catalog is what becomes the prompt, so it must already be clean."""
    catalog = build_evidence_catalog(poisoned_evidence(), max_evidence_bytes=16000, max_log_lines=25)
    assert catalog.items, "catalog was empty"
    assert_no_secret(str(catalog.as_list()), "evidence catalog")
    assert "[REDACTED" in str(catalog.as_list()), "no redaction marker found - was it applied at all?"


def test_incident_summary_is_redacted():
    summary = build_incident_summary(poisoned_incident())
    assert_no_secret(str(summary), "incident summary")
    # The request_context blob is deliberately excluded from the summary; its
    # contents reach the model only as catalogued, redacted evidence.
    assert "request_context" not in summary


def test_prompt_is_redacted_even_if_a_caller_skips_the_catalog():
    """
    `build_user_prompt` is a second line of defence: it sanitises what it is
    given, so a future caller that forgets to pre-redact still cannot leak.
    """
    prompt = build_user_prompt(
        incident_summary={"detected_error": BEARER_HEADER},
        evidence_catalog=[{"id": "E1", "source": "logs", "value": AWS_SECRET_PAIR}],
        deterministic_baseline={"root_cause": API_KEY_PAIR},
        max_prompt_chars=24000,
    )
    assert_no_secret(prompt, "user prompt built from unredacted input")


def test_builders_do_not_mutate_the_caller_evidence():
    """
    The runner keeps the evidence bundle for the incident record. Redaction must
    produce a new structure, never rewrite the caller's dict in place.
    """
    evidence = poisoned_evidence()
    before = repr(evidence)
    build_evidence_catalog(evidence, max_evidence_bytes=16000, max_log_lines=25)
    build_incident_summary(poisoned_incident())
    assert repr(evidence) == before, "the caller's evidence was mutated"
    assert SECRET_VALUES[0] in repr(evidence), "input should still hold the original value"


# =========================================================================
# Tool results are redacted on the way back to the model
# =========================================================================


def test_tool_output_returned_to_the_model_is_redacted():
    """
    The agent can call `get_recent_logs` mid-conversation. Whatever the log
    buffer holds, the string handed back to the model must already be clean.
    """
    record_log("ERROR", f"leaked {BEARER_HEADER} and {AWS_SECRET_PAIR}", service="redaction-test")

    budget = ToolBudget(4)
    tools = build_diagnostic_tools(budget)
    registered = [getattr(t, "tool_name", None) for t in tools]
    get_logs = next((t for t in tools if getattr(t, "tool_name", None) == "get_recent_logs"), None)
    assert get_logs is not None, f"get_recent_logs was not registered (tools: {registered})"

    # What the model would receive back from the tool call. The tool exposes
    # `limit` only - deliberately no `service` filter and no path argument.
    raw = get_logs(limit=50)
    assert_no_secret(str(raw), "get_recent_logs tool output returned to the model")
    # The poisoned line is present, but redacted - proving the tool really did
    # read it rather than the assertion passing because the line was absent.
    assert "[REDACTED_HEADER]" in str(raw), "the leaked line was not redacted in tool output"
    # The tool call consumed budget, as it must.
    assert budget.total >= 1


def test_application_log_reader_redacts_the_leaked_line():
    """Independent check on the same buffer, through the production reader."""
    record_log("ERROR", f"leaked {BEARER_HEADER}", service="redaction-test-2")
    payload = get_recent_logs(limit=500, service="redaction-test-2")
    assert_no_secret(str(payload), "get_recent_logs() production reader")
