"""
A fake Bedrock TRANSPORT - and nothing else.

Why this file exists
--------------------
Requirement: "Do not make the test suite green by mocking the entire Bedrock
implementation." These helpers therefore replace exactly one object: the
`converse` method of the real boto3 bedrock-runtime client. Everything above it
is the genuine article -

    strands.Agent                  real
    strands.models.BedrockModel    real
    request construction           real (modelId, system, toolConfig, messages)
    structured-output tool         real (the SDK generates it from the Pydantic model)
    response parsing + metrics     real
    our evidence/redaction/policy  real

Only the HTTP call to `bedrock-runtime.<region>.amazonaws.com` is answered
locally, from a canned response in the shape Bedrock actually returns. That is
what makes it possible to assert *what would have been sent to the model* - the
redaction and prompt-injection requirements - without an AWS account, and to
exercise the real parsing path against a malformed or adversarial reply.

It is not a green light for the live integration. `tests/test_bedrock_live.py`
covers that and SKIPS unless real credentials and model access exist.
"""

import json
from typing import Any, Dict, List, Optional

from agent.config import AgentConfig
from agent.schemas import DiagnosisResult
from agent.strands_agent import BedrockDiagnosisAgent

DEFAULT_USAGE = {"inputTokens": 1234, "outputTokens": 210, "totalTokens": 1444}

# A well-formed reply, used when a test cares about the plumbing rather than the
# model's answer.
WELL_FORMED_REPLY = {
    "hypothesis": "Ollama runtime is installed but not listening",
    "confidence": 0.82,
    "evidence_ids": ["E1", "E2"],
    "contradictory_evidence_ids": [],
    "recommended_action": "start_ollama",
    "investigation_needed": [],
    "explanation": "The process probe found no listener while the binary is present.",
    "requires_human": False,
}


class _FakeHttpResponse:
    """
    The minimum botocore's own handlers need from an HTTP response.

    `release_retry_quota` listens on the same event and reads `status_code` and
    `context`, so a stub without them raises inside botocore rather than in the
    code under test.
    """

    def __init__(self, request_id: str, status_code: int = 200):
        self.status_code = status_code
        self.headers = {"x-amzn-RequestId": request_id}


class FakeBedrockTransport:
    """
    Answers `client.converse(**request)` locally and records every request.

    Parameters
    ----------
    fields:
        Field dict the model "returns" as a DiagnosisResult tool call. Pass
        `None` to make the model reply with free-form text instead, which is how
        the schema-rejection path is exercised.
    text:
        Free-form text reply (used when `fields` is None).
    stop_reason:
        Bedrock stopReason. Set to "tool_use" by default; "end_turn" produces a
        reply with no structured output.
    error:
        An exception instance to raise from `converse`, for failure-path tests.
    """

    def __init__(
        self,
        fields: Optional[Dict[str, Any]] = None,
        text: Optional[str] = None,
        stop_reason: Optional[str] = None,
        usage: Optional[Dict[str, Any]] = None,
        error: Optional[BaseException] = None,
        request_id: str = "REQ-fake-0001",
        emit_request_id_event: bool = True,
    ):
        if fields is None and text is None and error is None:
            fields = dict(WELL_FORMED_REPLY)
        self.fields = fields
        self.text = text
        self.stop_reason = stop_reason or ("tool_use" if fields is not None else "end_turn")
        self.usage = usage if usage is not None else dict(DEFAULT_USAGE)
        self.error = error
        self.request_id = request_id
        self.emit_request_id_event = emit_request_id_event
        self.calls: List[Dict[str, Any]] = []

    # -- the canned Bedrock response ------------------------------------
    def response(self) -> Dict[str, Any]:
        if self.fields is not None:
            content: List[Dict[str, Any]] = [
                {
                    "toolUse": {
                        "toolUseId": "tu-fake-1",
                        "name": DiagnosisResult.__name__,
                        "input": dict(self.fields),
                    }
                }
            ]
        else:
            content = [{"text": self.text or "no structured answer"}]
        return {
            "output": {"message": {"role": "assistant", "content": content}},
            "stopReason": self.stop_reason,
            "usage": dict(self.usage),
            "ResponseMetadata": {
                "RequestId": self.request_id,
                "HTTPStatusCode": 200,
                "HTTPHeaders": {"x-amzn-requestid": self.request_id},
            },
        }

    # -- what the tests assert on ---------------------------------------
    @property
    def last_request(self) -> Dict[str, Any]:
        assert self.calls, "the model was never called"
        return self.calls[-1]

    def payload_json(self) -> str:
        """Everything that would have gone over the wire, as one searchable string."""
        return json.dumps(self.calls, default=str)

    def user_prompt(self) -> str:
        """The user turn text the SDK built from our prompt."""
        parts: List[str] = []
        for message in self.last_request.get("messages", []):
            for block in message.get("content", []):
                if isinstance(block, dict) and "text" in block:
                    parts.append(block["text"])
        return "\n".join(parts)

    def system_prompt(self) -> str:
        return "".join(b.get("text", "") for b in self.last_request.get("system", []))

    def tool_names(self) -> List[str]:
        return [t["toolSpec"]["name"] for t in self.last_request["toolConfig"]["tools"]]


def make_transport_agent(
    config: AgentConfig, transport: FakeBedrockTransport
) -> BedrockDiagnosisAgent:
    """
    A real `BedrockDiagnosisAgent` whose model talks to `transport`.

    `build_model()` calls the real implementation first, so the real
    `BedrockModel` and the real boto3 client are constructed exactly as in
    production; only the client's `converse` method is swapped.
    """

    class _TransportAgent(BedrockDiagnosisAgent):
        def build_model(self):
            model = super().build_model()
            real_client = model.client

            class _StubClient:
                # The real client's meta is kept so region/service lookups and
                # the event hook registration behave exactly as in production.
                meta = real_client.meta
                exceptions = real_client.exceptions

                def converse(self, **request: Dict[str, Any]) -> Dict[str, Any]:
                    transport.calls.append(request)
                    if transport.error is not None:
                        raise transport.error
                    response = transport.response()
                    # Emulate the post-call event botocore fires in production, so
                    # the bedrock_request_id capture hook is exercised on the same
                    # code path rather than left untested until a live call.
                    if transport.emit_request_id_event:
                        try:
                            real_client.meta.events.emit(
                                "after-call.bedrock-runtime",
                                http_response=_FakeHttpResponse(transport.request_id),
                                parsed=response,
                                model=None,
                                context={},
                            )
                        except Exception:
                            pass
                    return response

            model.client = _StubClient()
            return model

    return _TransportAgent(config)


def bedrock_config(**overrides: Any) -> AgentConfig:
    """A bedrock-mode AgentConfig with test defaults."""
    values: Dict[str, Any] = {
        "mode": "bedrock",
        "aws_region": "us-east-1",
        "model_id": "anthropic.claude-3-5-haiku-20241022-v1:0",
        "temperature": 0.0,
        "max_tool_calls": 5,
        "max_turns": 4,
    }
    values.update(overrides)
    return AgentConfig(**values)


DOWN_EVIDENCE: Dict[str, Any] = {
    "runtime": {"installed": True, "state": "OLLAMA_STOPPED", "binary_path": "/usr/local/bin/ollama"},
    "port_11434": {"is_open": False, "status": "closed"},
    "process_ollama": {"is_running": False, "pids": []},
    "ollama_api": {"is_available": False},
    "recent_logs": [{"level": "ERROR", "message": "connect refused", "service": "demo"}],
}

INCIDENT: Dict[str, Any] = {
    "incident_id": "inc-fake-transport",
    "detected_error": "HTTP 500 from demo-inference-service",
    "error_class": "UpstreamError",
    "http_status": 500,
    "service": "demo-inference-service",
    "runtime_state": "OLLAMA_STOPPED",
}

BASELINE: Dict[str, Any] = {
    "root_cause": "Ollama daemon is not running",
    "recommended_remediation": "start_ollama",
    "confidence": 0.9,
    "runtime_state": "OLLAMA_STOPPED",
}
