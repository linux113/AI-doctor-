"""
Real AWS Strands Agent backed by Amazon Bedrock.

This replaces `StrandsAgentPlaceholder`, which was a rule-based local engine
wearing an agent-shaped coat. What is here now makes a genuine model invocation:

    BedrockModel(region_name=..., model_id=..., temperature=...)   # real boto3 client
        -> Agent(model=..., tools=<five read-only tools>, system_prompt=...)
        -> agent(prompt, structured_output_model=DiagnosisResult, limits=...)
        -> AgentResult.structured_output

There is no mock, no canned response and no hidden deterministic path in this
module. If Bedrock cannot be reached - no credentials, no network, model not
enabled, SDK missing - `diagnose()` raises `BedrockUnavailableError` naming the
real cause. It does **not** quietly fall back to the rule engine, because an
incident that says "Bedrock diagnosed this" when a Python if-statement did is
worse than an incident that says diagnosis failed.

The deterministic engine still exists, in `runner/diagnosis.py`, and is selected
only by explicit configuration (`AI_DOCTOR_AGENT_MODE=deterministic`) or as a
declared, separately-labelled fallback decided by the caller.
"""

import time
from typing import Any, Dict, List, Optional

from pydantic import ValidationError

from runner.diagnostics import record_log
from runner.redaction import sanitize_deep

from strands.models.openai import OpenAIModel

from .config import (
    MODE_BEDROCK,
    MODE_OPENROUTER,
    AgentConfig,
    AgentConfigurationError,
    strands_sdk_version,
)
from .evidence import EvidenceCatalog, build_evidence_catalog, build_incident_summary
from .policy import validate_diagnosis
from .prompts import SYSTEM_PROMPT, build_user_prompt
from .schemas import AgentTelemetry, DiagnosisResult, PolicyDecision
from .tools import ALLOWED_TOOL_NAMES, ToolBudget, build_diagnostic_tools, summarise_tool_use

# ---------------------------------------------------------------------------
# Two different questions, kept in two different fields
# ---------------------------------------------------------------------------
# Conflating them is how a system ends up claiming an AI diagnosis that never
# happened. `bedrock_status` answers "did a real model round trip succeed?";
# `diagnosis_outcome` answers "what should happen next?".

# How far down an exception chain `aws_error_code` will look for the AWS code.
# Real chains are one or two links deep; the bound exists so a cycle cannot hang us.
_MAX_CAUSE_DEPTH = 8

# Round-trip status - what Amazon Bedrock did.
STATUS_BEDROCK_SUCCESS = "BEDROCK_SUCCESS"
STATUS_BEDROCK_SCHEMA_REFUSED = "BEDROCK_SCHEMA_REFUSED"
STATUS_BEDROCK_UNAVAILABLE = "BEDROCK_UNAVAILABLE"
STATUS_OPENROUTER_SUCCESS = "OPENROUTER_SUCCESS"
STATUS_OPENROUTER_SCHEMA_REFUSED = "OPENROUTER_SCHEMA_REFUSED"
STATUS_OPENROUTER_UNAVAILABLE = "OPENROUTER_UNAVAILABLE"

# Diagnosis outcome - what the pipeline decided.
STATUS_DIAGNOSED = "DIAGNOSED"
STATUS_REQUIRES_HUMAN = "REQUIRES_HUMAN"
STATUS_FAILED = "FAILED"

# A real request reached Bedrock and a response came back in both of these cases.
BEDROCK_WAS_INVOKED = frozenset({STATUS_BEDROCK_SUCCESS, STATUS_BEDROCK_SCHEMA_REFUSED})


# ---------------------------------------------------------------------------
# Machine-readable failure classification
# ---------------------------------------------------------------------------
# A human-readable message tells an operator what to do; a stable identifier lets
# a dashboard, an alarm or a Lambda branch on the cause without parsing prose.
# These values are part of the incident record, so they are fixed strings and
# must not be reworded casually.

FAILURE_NO_CREDENTIALS = "NO_CREDENTIALS"
FAILURE_PARTIAL_CREDENTIALS = "PARTIAL_CREDENTIALS"
FAILURE_ACCESS_DENIED = "ACCESS_DENIED"
FAILURE_INVALID_MODEL = "INVALID_MODEL"
FAILURE_VALIDATION_ERROR = "VALIDATION_ERROR"
FAILURE_THROTTLED = "THROTTLED"
FAILURE_TIMEOUT = "TIMEOUT"
FAILURE_NETWORK = "NETWORK_UNREACHABLE"
FAILURE_SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
FAILURE_CONTEXT_OVERFLOW = "CONTEXT_OVERFLOW"
FAILURE_SCHEMA_REFUSED = "SCHEMA_REFUSED"
FAILURE_SDK_MISSING = "SDK_MISSING"
FAILURE_UNKNOWN = "UNKNOWN_AWS_ERROR"

FAILURE_KINDS = frozenset({
    FAILURE_NO_CREDENTIALS,
    FAILURE_PARTIAL_CREDENTIALS,
    FAILURE_ACCESS_DENIED,
    FAILURE_INVALID_MODEL,
    FAILURE_VALIDATION_ERROR,
    FAILURE_THROTTLED,
    FAILURE_TIMEOUT,
    FAILURE_NETWORK,
    FAILURE_SERVICE_UNAVAILABLE,
    FAILURE_CONTEXT_OVERFLOW,
    FAILURE_SCHEMA_REFUSED,
    FAILURE_SDK_MISSING,
    FAILURE_UNKNOWN,
})

# botocore exception class name -> kind.
_BOTOCORE_KINDS = {
    "NoCredentialsError": FAILURE_NO_CREDENTIALS,
    "PartialCredentialsError": FAILURE_PARTIAL_CREDENTIALS,
    "EndpointConnectionError": FAILURE_NETWORK,
    "NewConnectionError": FAILURE_NETWORK,
    "ConnectTimeoutError": FAILURE_TIMEOUT,
    "ReadTimeoutError": FAILURE_TIMEOUT,
    "ConnectionClosedError": FAILURE_NETWORK,
    "HTTPClientError": FAILURE_NETWORK,
    # botocore.exceptions.SSLError is its own class (MRO: SSLError ->
    # ConnectionError -> BotoCoreError), and the lookup above matches on the exact
    # class name, so without this entry a TLS/proxy-certificate failure - one of
    # the most common ways a real Bedrock call fails behind a corporate proxy -
    # was reported as UNKNOWN_AWS_ERROR. It is a network failure, and the frozen
    # taxonomy already has a kind for that.
    "SSLError": FAILURE_NETWORK,
    "UnknownServiceError": FAILURE_NETWORK,
}

# Bedrock service error code -> kind. These arrive inside a botocore ClientError,
# whose Python class name is always "ClientError" and therefore carries no
# information at all.
_SERVICE_CODE_KINDS = {
    # -- Documented errors of BedrockRuntime.Converse, verified against the
    # -- service model shipped with the installed botocore. Every one of the nine
    # -- is mapped, so no real Converse failure can fall through to UNKNOWN.
    "AccessDeniedException": FAILURE_ACCESS_DENIED,          # 403
    "InternalServerException": FAILURE_SERVICE_UNAVAILABLE,  # 500
    "ModelErrorException": FAILURE_SERVICE_UNAVAILABLE,      # 424
    "ModelNotReadyException": FAILURE_SERVICE_UNAVAILABLE,   # 429, model not serving yet
    "ModelTimeoutException": FAILURE_TIMEOUT,                # 408
    "ResourceNotFoundException": FAILURE_INVALID_MODEL,      # 404, no such model here
    "ServiceUnavailableException": FAILURE_SERVICE_UNAVAILABLE,  # 503
    "ThrottlingException": FAILURE_THROTTLED,                # 429
    "ValidationException": FAILURE_VALIDATION_ERROR,         # 400
    # Other bedrock-runtime shapes (streaming and quota paths).
    "ModelStreamErrorException": FAILURE_SERVICE_UNAVAILABLE,
    "ServiceQuotaExceededException": FAILURE_THROTTLED,
    "ConflictException": FAILURE_VALIDATION_ERROR,
    # -- AWS-wide codes from the SigV4/STS layer, which can reject the call before
    # -- Bedrock itself ever sees it.
    "UnrecognizedClientException": FAILURE_ACCESS_DENIED,
    "InvalidSignatureException": FAILURE_ACCESS_DENIED,
    "SignatureDoesNotMatch": FAILURE_ACCESS_DENIED,
    "NotAcceptPolicyException": FAILURE_ACCESS_DENIED,
    "ExpiredToken": FAILURE_ACCESS_DENIED,
    "ExpiredTokenException": FAILURE_ACCESS_DENIED,
    "InvalidClientTokenId": FAILURE_ACCESS_DENIED,
    "AccessDenied": FAILURE_ACCESS_DENIED,
    "MissingAuthenticationToken": FAILURE_ACCESS_DENIED,
    "TooManyRequestsException": FAILURE_THROTTLED,
    "RequestLimitExceeded": FAILURE_THROTTLED,
    "SlowDown": FAILURE_THROTTLED,
    "InternalFailure": FAILURE_SERVICE_UNAVAILABLE,
    "ServiceUnavailable": FAILURE_SERVICE_UNAVAILABLE,
}

# Strands re-raises some Bedrock conditions as its own exception types.
_STRANDS_KINDS = {
    "ModelThrottledException": FAILURE_THROTTLED,
    "ContextWindowOverflowException": FAILURE_CONTEXT_OVERFLOW,
    "StructuredOutputException": FAILURE_SCHEMA_REFUSED,
}


def _code_on(exc: BaseException) -> Optional[str]:
    """The AWS service code carried directly by this exception, if any."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict):
            code = error.get("Code")
            if isinstance(code, str) and code:
                return code
    return None


def aws_error_code(exc: BaseException) -> Optional[str]:
    """
    The AWS service error code behind this failure, or None.

    The exception chain is walked, because Strands re-raises some Bedrock errors as
    its own types - a botocore `ThrottlingException` surfaces as
    `strands.exceptions.ModelThrottledException`. Reading only the outermost
    exception would throw away the AWS code, and an incident record that says
    "throttled" without saying which code AWS returned is a record an operator
    cannot cross-reference against CloudTrail.
    """
    seen = set()
    current: Optional[BaseException] = exc
    for _ in range(_MAX_CAUSE_DEPTH):
        if current is None or id(current) in seen:
            return None
        seen.add(id(current))
        code = _code_on(current)
        if code:
            return code
        current = current.__cause__ or current.__context__
    return None


def classify_bedrock_failure(exc: BaseException) -> str:
    """
    Maps any exception raised on the Bedrock path onto a stable failure kind.

    Order matters, and it is deliberate:

    1. Configuration errors - we never called AWS at all, so no AWS code applies.
    2. Strands wrapper types - these are authoritative about the round trip. A
       `StructuredOutputException` means the model DID answer and we could not
       validate the shape; that must not be re-labelled as an AWS validation
       error just because something in the chain looks like one.
    3. The AWS service code, read through the exception chain.
    4. The botocore exception class.

    Nothing collapses to UNKNOWN unless it genuinely is unrecognised - and even
    then the original code is preserved separately so the information is not lost.
    """
    from agent.config import AgentConfigurationError

    name = type(exc).__name__

    if isinstance(exc, AgentConfigurationError):
        # SDK missing, or bedrock mode configured without a region/model.
        return FAILURE_SDK_MISSING if "not installed" in str(exc) else FAILURE_VALIDATION_ERROR

    if name in _STRANDS_KINDS:
        return _STRANDS_KINDS[name]

    code = aws_error_code(exc)
    if code and code in _SERVICE_CODE_KINDS:
        kind = _SERVICE_CODE_KINDS[code]
        # "The provided model identifier is invalid" is an operator-fixable
        # configuration problem, not a generic validation failure.
        if kind == FAILURE_VALIDATION_ERROR and "model identifier" in str(exc).lower():
            return FAILURE_INVALID_MODEL
        return kind

    if name in _BOTOCORE_KINDS:
        return _BOTOCORE_KINDS[name]
    if isinstance(exc, ValidationError):
        return FAILURE_SCHEMA_REFUSED
    return FAILURE_UNKNOWN


class BedrockUnavailableError(RuntimeError):
    """
    Amazon Bedrock could not perform the diagnosis.

    Carries a machine-readable `failure_kind`, the underlying AWS/Python error
    identity, and a redacted message, so the incident records the true cause
    instead of a generic failure.
    """

    def __init__(
        self,
        message: str,
        error_class: Optional[str] = None,
        failure_kind: str = FAILURE_UNKNOWN,
        aws_error_code: Optional[str] = None,
    ):
        super().__init__(message)
        self.error_class = error_class or "BedrockUnavailableError"
        self.failure_kind = failure_kind if failure_kind in FAILURE_KINDS else FAILURE_UNKNOWN
        self.aws_error_code = aws_error_code

    def as_record(self) -> Dict[str, Any]:
        """The safe, persistable part of this failure. Contains no credentials."""
        return {
            "failure_kind": self.failure_kind,
            "error_class": self.error_class,
            "aws_error_code": self.aws_error_code,
            "error_detail": str(self)[:900],
        }


class AgentDiagnosis:
    """
    Everything one agent invocation produced, kept separate from what it decided.

    Two statuses, because they answer different questions:
      `bedrock_status`     did a real model round trip succeed?
      `status`             what should happen next (DIAGNOSED / REQUIRES_HUMAN)?
    """

    def __init__(
        self,
        status: str,
        report: Dict[str, Any],
        telemetry: AgentTelemetry,
        policy: Optional[PolicyDecision] = None,
        structured: Optional[DiagnosisResult] = None,
        incident_id: Optional[str] = None,
        bedrock_status: str = STATUS_BEDROCK_SUCCESS,
    ):
        self.status = status
        self.report = report
        self.telemetry = telemetry
        self.policy = policy
        self.structured = structured
        self.incident_id = incident_id
        self.bedrock_status = bedrock_status

    @property
    def bedrock_invoked(self) -> bool:
        """True only when a real request reached Bedrock and a response returned."""
        return self.bedrock_status in BEDROCK_WAS_INVOKED

    @property
    def used_llm(self) -> bool:
        """
        True only when a model produced the validated diagnosis.

        A schema refusal does not count: Bedrock answered, but nothing usable came
        back, so there is no model diagnosis to claim.
        """
        return self.bedrock_status in (STATUS_BEDROCK_SUCCESS, STATUS_OPENROUTER_SUCCESS) and self.structured is not None

    def as_dict(self) -> Dict[str, Any]:
        out = dict(self.report)
        out["agent_status"] = self.bedrock_status
        out["diagnosis_outcome"] = self.status
        out["bedrock_invoked"] = self.bedrock_invoked
        out["used_llm"] = self.used_llm
        out["agent_mode"] = self.telemetry.agent_mode
        out["telemetry"] = self.telemetry.as_dict()
        out["policy"] = self.policy.audit_event(self.incident_id) if self.policy else None
        return out


def _schema_refusal_errors() -> tuple:
    """
    Exception types that mean "the model answered, but not in the required shape".

    Strands raises `StructuredOutputException` when the model never invokes the
    structured-output tool even after being forced to; a pydantic
    `ValidationError` surfaces when the tool input does not satisfy
    `DiagnosisResult`. Both are refusals of a malformed reply - NOT evidence that
    Bedrock was unreachable - so they must not be reported as an AWS outage, and
    must not trigger the deterministic fallback: a model that cannot follow the
    schema is a reason to escalate to a human, not a reason to quietly run the
    rule engine instead.
    """
    types: List[type] = []
    try:
        from strands.types.exceptions import StructuredOutputException

        types.append(StructuredOutputException)
    except Exception:
        pass
    try:
        from pydantic import ValidationError

        types.append(ValidationError)
    except Exception:
        pass
    return tuple(types)


class BedrockDiagnosisAgent:
    """
    Wraps a real Strands Agent over a real Bedrock model.

    Constructed per configuration; the model and agent are built per invocation so
    tool budgets and message history cannot leak between incidents.
    """

    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or AgentConfig(mode=MODE_BEDROCK)
        if not self.config.is_bedrock:
            raise AgentConfigurationError(
                "BedrockDiagnosisAgent requires AI_DOCTOR_AGENT_MODE=bedrock; "
                f"got mode={self.config.mode!r}. The deterministic engine lives in "
                "runner/diagnosis.py and is selected by that mode instead."
            )
        if not self.config.aws_region or not self.config.model_id:
            raise AgentConfigurationError(
                "Bedrock mode requires AI_DOCTOR_AWS_REGION and AI_DOCTOR_BEDROCK_MODEL_ID."
            )
        self._last_request_id: Optional[str] = None

    # ------------------------------------------------------------------
    # Real client construction
    # ------------------------------------------------------------------
    def build_model(self) -> Any:
        """
        Constructs the real `strands.models.BedrockModel`.

        Credentials come from boto3's standard chain (environment, shared config,
        IAM role, IMDS). None are read, stored, logged or hardcoded here.
        """
        try:
            from botocore.config import Config as BotoConfig
            from strands.models import BedrockModel
        except ImportError as exc:
            raise AgentConfigurationError(
                f"The AWS Strands Agents SDK is not installed ({exc}). "
                "Install with: pip install -r requirements-aws.txt"
            ) from exc

        # Bound the call: a hung model must not hang incident handling, and
        # retries are capped (2 retries = 3 total attempts) so a failing region
        # cannot multiply cost or hammer a throttled endpoint.
        boto_config = BotoConfig(
            region_name=self.config.aws_region,
            connect_timeout=min(10.0, self.config.request_timeout_seconds),
            read_timeout=self.config.request_timeout_seconds,
            retries={"max_attempts": 2, "mode": "standard"},
        )

        model = BedrockModel(
            region_name=self.config.aws_region,
            model_id=self.config.model_id,
            temperature=self.config.temperature,
            max_tokens=self.config.max_output_tokens,
            # Non-streaming: the agent returns one structured object, so partial
            # text has no use here and `converse` gives cleaner telemetry.
            streaming=False,
            boto_client_config=boto_config,
        )
        self._register_request_id_capture(model)
        return model

    def _register_request_id_capture(self, model: Any) -> None:
        """
        Best-effort capture of the Bedrock request ID for support tracing.

        Strands does not surface `ResponseMetadata.RequestId`, so a botocore
        response hook records it. Purely observational: if registration fails the
        diagnosis proceeds with `bedrock_request_id=None`.
        """

        def _capture(**kwargs: Any) -> None:
            try:
                parsed = kwargs.get("parsed")
                if isinstance(parsed, dict):
                    rid = (parsed.get("ResponseMetadata") or {}).get("RequestId")
                    if rid:
                        self._last_request_id = str(rid)
                        return
                http_response = kwargs.get("http_response")
                headers = getattr(http_response, "headers", None)
                if headers is not None:
                    rid = headers.get("x-amzn-RequestId") or headers.get("X-Amzn-Requestid")
                    if rid:
                        self._last_request_id = str(rid)
            except Exception:
                # Telemetry must never break a diagnosis.
                pass

        try:
            model.client.meta.events.register("after-call.bedrock-runtime", _capture)
        except Exception:
            pass

    def build_agent(self, budget: ToolBudget) -> Any:
        """Constructs the real Strands `Agent` with only the read-only tools."""
        from strands import Agent
        from strands.event_loop._retry import ModelRetryStrategy

        return Agent(
            model=self.build_model(),
            tools=build_diagnostic_tools(budget),
            system_prompt=SYSTEM_PROMPT,
            # Quiet by design: the default handler prints every tool call and the
            # model's message to stdout, which would put evidence text into
            # service logs. The evidence is already redacted, but the incident
            # record is the place for it, not the process log.
            callback_handler=None,
            # Bound the throttle backoff. Strands' default (6 attempts, 4s..240s)
            # would hold an incident for ~124 seconds before failing; this is a
            # request path, so one short retry is the most that is justified.
            retry_strategy=ModelRetryStrategy(
                max_attempts=max(1, self.config.max_model_attempts),
                initial_delay=1,
                max_delay=5,
            ),
        )

    # ------------------------------------------------------------------
    # Invocation
    # ------------------------------------------------------------------
    def diagnose(
        self,
        incident_data: Dict[str, Any],
        evidence: Dict[str, Any],
        deterministic_baseline: Optional[Dict[str, Any]] = None,
        incident_id: Optional[str] = None,
    ) -> AgentDiagnosis:
        """
        Runs one real Bedrock agent invocation and returns a validated diagnosis.

        Raises `BedrockUnavailableError` if the model could not be used. Never
        returns a deterministic result labelled as a Bedrock one.
        """
        incident_id = incident_id or (incident_data or {}).get("incident_id")
        started = time.monotonic()
        self._last_request_id = None

        # Redaction + cataloguing happen before the prompt is built, so nothing
        # unredacted can reach the model.
        catalog = build_evidence_catalog(
            evidence or {},
            max_evidence_bytes=self.config.max_evidence_bytes,
            max_log_lines=self.config.max_log_lines,
        )
        summary = build_incident_summary(incident_data or {})
        prompt = build_user_prompt(
            incident_summary=summary,
            evidence_catalog=catalog.as_list(),
            deterministic_baseline=deterministic_baseline or {},
            max_prompt_chars=self.config.max_prompt_chars,
        )

        budget = ToolBudget(self.config.max_tool_calls)

        try:
            agent = self.build_agent(budget)
        except AgentConfigurationError:
            raise
        except Exception as exc:
            raise self._unavailable(exc, "agent construction failed") from exc

        record_log(
            "INFO",
            f"Invoking Amazon Bedrock ({self.config.model_id} in {self.config.aws_region}) "
            f"for incident {incident_id}; prompt={len(prompt)} chars, evidence={len(catalog.items)} items.",
            service="agent",
        )

        try:
            result = agent(
                prompt,
                structured_output_model=DiagnosisResult,
                limits={
                    "turns": self.config.max_turns,
                    "total_tokens": self.config.max_total_tokens,
                },
            )
        except AgentConfigurationError:
            raise
        except _schema_refusal_errors() as exc:
            # The model was reached and answered, but not in the required shape.
            latency = int((time.monotonic() - started) * 1000)
            reason = (
                "The model did not return a schema-valid DiagnosisResult "
                f"({type(exc).__name__}). Refusing to act on unstructured output."
            )
            telemetry = self._telemetry(
                latency_ms=latency,
                budget=budget,
                metrics=None,
                stop_reason="structured_output_failed",
                error_class=type(exc).__name__,
                error_detail=self._describe(exc),
                confidence=None,
                failure_kind=FAILURE_SCHEMA_REFUSED,
                aws_error_code=None,
            )
            record_log("WARN", f"{reason} Incident {incident_id}.", service="agent")
            policy = validate_diagnosis(
                None,
                evidence_ids=catalog.ids,
                incident_id=incident_id,
                budget_exhausted=budget.exhausted,
                iteration_limit_hit=True,
            )
            return AgentDiagnosis(
                status=STATUS_REQUIRES_HUMAN,
                report=self._report_from_policy(policy, catalog, deterministic_baseline, reason),
                telemetry=telemetry,
                policy=policy,
                structured=None,
                incident_id=incident_id,
                bedrock_status=STATUS_BEDROCK_SCHEMA_REFUSED,
            )
        except Exception as exc:
            latency = int((time.monotonic() - started) * 1000)
            telemetry = self._telemetry(
                latency_ms=latency,
                budget=budget,
                metrics=None,
                stop_reason=None,
                error_class=aws_error_code(exc) or type(exc).__name__,
                error_detail=self._describe(exc),
                confidence=None,
                failure_kind=classify_bedrock_failure(exc),
                aws_error_code=aws_error_code(exc),
            )
            record_log(
                "ERROR",
                f"Bedrock diagnosis failed for incident {incident_id}: "
                f"{telemetry.error_class}: {telemetry.error_detail}",
                service="agent",
            )
            raise self._unavailable(exc) from exc

        latency = int((time.monotonic() - started) * 1000)
        stop_reason = getattr(result, "stop_reason", None)
        metrics = getattr(result, "metrics", None)
        structured: Optional[DiagnosisResult] = getattr(result, "structured_output", None)
        iteration_limit_hit = stop_reason in ("limit_turns", "limit_total_tokens", "limit_output_tokens")

        confidence = float(structured.confidence) if structured is not None else None
        telemetry = self._telemetry(
            latency_ms=latency,
            budget=budget,
            metrics=metrics,
            stop_reason=stop_reason,
            error_class=None,
            error_detail=None,
            confidence=confidence,
        )

        record_log(
            "INFO",
            f"Bedrock returned for incident {incident_id} in {latency}ms "
            f"(stop_reason={stop_reason}, turns={telemetry.turns}, tools={telemetry.tool_call_count}, "
            f"tokens={telemetry.total_tokens}).",
            service="agent",
        )

        # --- Schema validation -------------------------------------------
        if structured is None:
            reason = (
                "Bedrock returned no schema-valid DiagnosisResult "
                f"(stop_reason={stop_reason}). Refusing to act on unstructured model text."
            )
            record_log("WARN", reason, service="agent")
            policy = validate_diagnosis(
                None,
                evidence_ids=catalog.ids,
                incident_id=incident_id,
                budget_exhausted=budget.exhausted,
                iteration_limit_hit=iteration_limit_hit,
            )
            return AgentDiagnosis(
                status=STATUS_REQUIRES_HUMAN,
                report=self._report_from_policy(policy, catalog, deterministic_baseline, reason),
                telemetry=telemetry,
                policy=policy,
                structured=None,
                incident_id=incident_id,
                bedrock_status=STATUS_BEDROCK_SCHEMA_REFUSED,
            )

        # --- Policy validation -------------------------------------------
        policy = validate_diagnosis(
            structured,
            evidence_ids=catalog.ids,
            incident_id=incident_id,
            budget_exhausted=budget.exhausted,
            iteration_limit_hit=iteration_limit_hit,
        )

        status = STATUS_DIAGNOSED if policy.allowed else STATUS_REQUIRES_HUMAN
        if policy.requires_human and policy.violation is None:
            status = STATUS_REQUIRES_HUMAN

        report = self._report_from_structured(structured, policy, catalog, deterministic_baseline)
        return AgentDiagnosis(
            status=status,
            report=report,
            telemetry=telemetry,
            policy=policy,
            structured=structured,
            incident_id=incident_id,
        )

    # ------------------------------------------------------------------
    # Mapping and telemetry
    # ------------------------------------------------------------------
    def _telemetry(
        self,
        latency_ms: int,
        budget: ToolBudget,
        metrics: Any,
        stop_reason: Optional[str],
        error_class: Optional[str],
        error_detail: Optional[str],
        confidence: Optional[float],
        failure_kind: Optional[str] = None,
        aws_error_code: Optional[str] = None,
    ) -> AgentTelemetry:
        usage_summary = summarise_tool_use(metrics, budget) if metrics is not None else {
            "tool_calls": dict(budget.counts),
            "tool_call_count": budget.total,
        }

        usage: Dict[str, Any] = {}
        turns = 0
        try:
            usage = dict(getattr(metrics, "accumulated_usage", {}) or {})
            turns = int(getattr(metrics, "cycle_count", 0) or 0)
        except Exception:
            usage = {}

        return AgentTelemetry(
            agent_mode=MODE_BEDROCK,
            model_id=self.config.model_id,
            aws_region=self.config.aws_region,
            agent_latency_ms=latency_ms,
            diagnosis_confidence=confidence,
            tool_calls=usage_summary.get("tool_calls") or {},
            tool_call_count=int(usage_summary.get("tool_call_count") or 0),
            turns=turns,
            input_tokens=_token_count_or_none(usage.get("inputTokens")),
            output_tokens=_token_count_or_none(usage.get("outputTokens")),
            total_tokens=_token_count_or_none(usage.get("totalTokens")),
            bedrock_request_id=self._last_request_id,
            stop_reason=str(stop_reason) if stop_reason else None,
            strands_sdk_version=strands_sdk_version(),
            error_class=error_class,
            error_detail=error_detail,
            failure_kind=failure_kind,
            aws_error_code=aws_error_code,
        )

    def _report_from_structured(
        self,
        structured: DiagnosisResult,
        policy: PolicyDecision,
        catalog: EvidenceCatalog,
        baseline: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Maps a validated model reply onto the report shape the runner consumes.

        `recommended_remediation` comes from the POLICY decision, never from the
        model's string, so nothing the model wrote is forwarded to an executor.
        """
        sources = {item["id"]: item["source"] for item in catalog.items}
        corroborating = [sources.get(eid, eid) for eid in structured.evidence_ids]
        contradicting = [sources.get(eid, eid) for eid in structured.contradictory_evidence_ids]

        action = policy.approved_action or "none"
        root_cause = f"{structured.hypothesis}: {structured.explanation}"

        return {
            "root_cause": sanitize_deep(root_cause)[:1500],
            "recommended_remediation": action,
            "confidence": round(float(structured.confidence), 2),
            "hypothesis": sanitize_deep(structured.hypothesis)[:200],
            "corroborating_probes": corroborating,
            "contradicting_probes": contradicting,
            "evidence_consistent": not contradicting,
            "evidence_ids": list(structured.evidence_ids),
            "contradictory_evidence_ids": list(structured.contradictory_evidence_ids),
            "investigation_needed": [sanitize_deep(x)[:200] for x in structured.investigation_needed],
            "explanation": sanitize_deep(structured.explanation)[:2000],
            "requires_human": bool(policy.requires_human),
            "notes": policy.reason,
            "runtime_state": (baseline or {}).get("runtime_state"),
            "agent_mode": MODE_BEDROCK,
            "policy_allowed": policy.allowed,
            "policy_violation": policy.violation,
        }

    def _report_from_policy(
        self,
        policy: PolicyDecision,
        catalog: EvidenceCatalog,
        baseline: Optional[Dict[str, Any]],
        reason: str,
    ) -> Dict[str, Any]:
        """Report used when the model produced nothing usable."""
        base = baseline or {}
        return {
            "root_cause": sanitize_deep(
                f"Agent diagnosis unavailable: {reason}"
            )[:1500],
            "recommended_remediation": "none",
            "confidence": 0.0,
            "hypothesis": "agent_diagnosis_unavailable",
            "corroborating_probes": [],
            "contradicting_probes": [],
            "evidence_consistent": False,
            "evidence_ids": [],
            "contradictory_evidence_ids": [],
            "investigation_needed": [],
            "explanation": sanitize_deep(reason)[:2000],
            "requires_human": True,
            "notes": policy.reason,
            "runtime_state": base.get("runtime_state"),
            "agent_mode": MODE_BEDROCK,
            "policy_allowed": False,
            "policy_violation": policy.violation,
        }

    # A schema refusal escalates to a human; it never silently substitutes the
    # deterministic engine, so `recommended_remediation` stays "none" above.


    def _describe(self, exc: BaseException) -> str:
        """A redacted, bounded description of an AWS/model failure."""
        text = sanitize_deep(f"{type(exc).__name__}: {exc}")
        return str(text)[:600]

    def _unavailable(self, exc: BaseException, prefix: str = "Bedrock invocation failed") -> BedrockUnavailableError:
        """
        Translates a real AWS/SDK failure into an honest, actionable error.

        Classification happens first (`classify_bedrock_failure`) and the message
        is then built from the resulting kind, so the machine-readable field and
        the human-readable text can never disagree. The underlying identity is
        preserved (redacted) because "the model failed" is not something an
        operator can act on.
        """
        kind = classify_bedrock_failure(exc)
        code = aws_error_code(exc)
        name = type(exc).__name__
        detail = self._describe(exc)
        region = self.config.aws_region
        model = self.config.model_id

        if kind == FAILURE_NO_CREDENTIALS:
            message = (
                "No AWS credentials were found in the default credential chain "
                "(environment, shared config, IAM role, IMDS). Configure credentials for a "
                "role with bedrock:InvokeModelWithResponseStream, or run with "
                f"AI_DOCTOR_AGENT_MODE=deterministic for offline operation. Underlying error: {detail}"
            )
        elif kind == FAILURE_PARTIAL_CREDENTIALS:
            message = (
                "The AWS credential chain returned an incomplete credential set (for example "
                "an access key ID without a secret access key, or a temporary credential "
                f"missing its session token). Underlying error: {detail}"
            )
        elif kind == FAILURE_ACCESS_DENIED:
            message = (
                f"AWS rejected this Bedrock call{f' ({code})' if code else ''}. The principal needs "
                f"bedrock:InvokeModelWithResponseStream on model {model!r} in {region!r}, and the "
                f"model must be enabled for that account. Underlying error: {detail}"
            )
        elif kind == FAILURE_INVALID_MODEL:
            message = (
                f"Bedrock model {model!r} is not valid or not enabled in {region!r}. Set "
                f"AI_DOCTOR_BEDROCK_MODEL_ID to a model your account can invoke in that region. "
                f"Underlying error: {detail}"
            )
        elif kind == FAILURE_THROTTLED:
            message = (
                f"Bedrock throttled the request to model {model!r} in {region!r} and the bounded "
                f"retry budget ({self.config.max_model_attempts} attempt(s)) was exhausted. Raise "
                f"AI_DOCTOR_AGENT_MAX_MODEL_ATTEMPTS only if you accept the added latency. "
                f"Underlying error: {detail}"
            )
        elif kind == FAILURE_TIMEOUT:
            message = (
                f"Bedrock did not respond within {self.config.request_timeout_seconds}s "
                f"(AI_DOCTOR_AGENT_TIMEOUT_SECONDS). Underlying error: {detail}"
            )
        elif kind == FAILURE_NETWORK:
            message = (
                f"Amazon Bedrock in region {region!r} could not be reached from this network. "
                f"Check egress to bedrock-runtime.{region}.amazonaws.com. Underlying error: {detail}"
            )
        elif kind == FAILURE_SERVICE_UNAVAILABLE:
            message = (
                f"Amazon Bedrock could not serve model {model!r} in {region!r} just now "
                f"{f'({code})' if code else ''}. This is a service-side or not-yet-ready "
                f"condition: retry after a short backoff, and confirm in the Bedrock console "
                f"that the model is available in that region. Underlying error: {detail}"
            )
        elif kind == FAILURE_CONTEXT_OVERFLOW:
            message = (
                "The prompt exceeded the model's context window. Lower AI_DOCTOR_MAX_EVIDENCE_BYTES, "
                f"AI_DOCTOR_MAX_LOG_LINES or AI_DOCTOR_MAX_PROMPT_CHARS. Underlying error: {detail}"
            )
        elif kind == FAILURE_SDK_MISSING:
            message = (
                "AI_DOCTOR_AGENT_MODE=bedrock was requested but the AWS Strands Agents SDK is not "
                f"installed. Install with: pip install -r requirements-aws.txt. Underlying error: {detail}"
            )
        elif kind == FAILURE_VALIDATION_ERROR:
            message = (
                f"Bedrock rejected the request{f' ({code})' if code else ''}. Underlying error: {detail}"
            )
        else:
            # UNKNOWN_AWS_ERROR. The service code is named explicitly rather than
            # collapsed into a generic message, so an unrecognised failure is
            # still searchable in CloudTrail.
            identity = code or name
            message = (
                f"{prefix}: unrecognised AWS/Bedrock failure ({identity}). "
                f"Model {model!r}, region {region!r}. Underlying error: {detail}"
            )

        # error_class keeps the AWS service code where there is one, otherwise the
        # Python class: both are what an operator would search CloudTrail for.
        return BedrockUnavailableError(
            message, error_class=code or name, failure_kind=kind, aws_error_code=code
        )

    def describe(self) -> Dict[str, Any]:
        """Non-secret description of this agent, for telemetry and the dashboard."""
        return {
            "agent_mode": MODE_BEDROCK,
            "provider": "Amazon Bedrock via AWS Strands Agents SDK",
            "model_id": self.config.model_id,
            "aws_region": self.config.aws_region,
            "strands_sdk_version": strands_sdk_version(),
            "temperature": self.config.temperature,
            "tools_exposed": list(ALLOWED_TOOL_NAMES),
            "uses_llm": True,
        }



class OpenRouterDiagnosisAgent:
    """
    Strands diagnosis agent using an OpenAI-compatible OpenRouter endpoint.

    The diagnostic evidence, tools, structured output and policy gate are the
    same as the Bedrock path. Only the model provider changes.
    """

    def __init__(self, config: AgentConfig):
        if not config.is_openrouter:
            raise AgentConfigurationError(
                "OpenRouterDiagnosisAgent requires AI_DOCTOR_AGENT_MODE=openrouter"
            )

        if not config.openrouter_api_key:
            raise AgentConfigurationError(
                "OPENROUTER_API_KEY is required when AI_DOCTOR_AGENT_MODE=openrouter"
            )

        self.config = config
        self._last_request_id = None

    def build_model(self) -> OpenAIModel:
        return OpenAIModel(
            client_args={
                "api_key": self.config.openrouter_api_key,
                "base_url": self.config.openrouter_base_url,
                "timeout": self.config.request_timeout_seconds,
            },
            model_id=self.config.model_id,
            params={
                "temperature": self.config.temperature,
                "max_tokens": self.config.max_output_tokens,
            },
        )

    def build_agent(self, budget: ToolBudget):
        from strands import Agent
        return Agent(
            model=self.build_model(),
            tools=build_diagnostic_tools(budget),
            system_prompt=SYSTEM_PROMPT,
        )

    def diagnose(
        self,
        incident_data: Dict[str, Any],
        evidence: Dict[str, Any],
        deterministic_baseline: Optional[Dict[str, Any]] = None,
        incident_id: Optional[str] = None,
    ) -> AgentDiagnosis:
        incident_id = incident_id or (incident_data or {}).get("incident_id")
        started = time.monotonic()

        catalog = build_evidence_catalog(
            evidence or {},
            max_evidence_bytes=self.config.max_evidence_bytes,
            max_log_lines=self.config.max_log_lines,
        )
        summary = build_incident_summary(incident_data or {})
        prompt = build_user_prompt(
            incident_summary=summary,
            evidence_catalog=catalog.as_list(),
            deterministic_baseline=deterministic_baseline or {},
            max_prompt_chars=self.config.max_prompt_chars,
        )

        budget = ToolBudget(self.config.max_tool_calls)

        try:
            agent = self.build_agent(budget)
            record_log(
                "INFO",
                f"Invoking OpenRouter ({self.config.model_id}); "
                f"incident {incident_id}; prompt={len(prompt)} chars, "
                f"evidence={len(catalog.items)} items.",
                service="agent",
            )
            result = agent(
                prompt,
                structured_output_model=DiagnosisResult,
                limits={
                    "turns": self.config.max_turns,
                    "total_tokens": self.config.max_total_tokens,
                },
            )
        except AgentConfigurationError:
            raise
        except _schema_refusal_errors() as exc:
            latency = int((time.monotonic() - started) * 1000)
            reason = (
                "OpenRouter did not return a schema-valid DiagnosisResult "
                f"({type(exc).__name__}). Refusing to act on unstructured output."
            )
            telemetry = self._telemetry(
                latency, budget, None, "structured_output_failed",
                type(exc).__name__, self._describe(exc), None,
            )
            policy = validate_diagnosis(
                None,
                evidence_ids=catalog.ids,
                incident_id=incident_id,
                budget_exhausted=budget.exhausted,
                iteration_limit_hit=True,
            )
            return AgentDiagnosis(
                status=STATUS_REQUIRES_HUMAN,
                report=self._report_from_policy(
                    policy, catalog, deterministic_baseline, reason
                ),
                telemetry=telemetry,
                policy=policy,
                structured=None,
                incident_id=incident_id,
                bedrock_status=STATUS_OPENROUTER_SCHEMA_REFUSED,
            )
        except Exception as exc:
            detail = self._describe(exc)
            record_log(
                "ERROR",
                f"OpenRouter diagnosis failed for incident {incident_id}: "
                f"{type(exc).__name__}: {detail}",
                service="agent",
            )
            raise RuntimeError(
                f"OpenRouter diagnosis failed: {detail}"
            ) from exc

        latency = int((time.monotonic() - started) * 1000)
        stop_reason = getattr(result, "stop_reason", None)
        metrics = getattr(result, "metrics", None)
        structured = getattr(result, "structured_output", None)
        iteration_limit_hit = stop_reason in (
            "limit_turns",
            "limit_total_tokens",
            "limit_output_tokens",
        )

        confidence = (
            float(structured.confidence)
            if structured is not None
            else None
        )

        telemetry = self._telemetry(
            latency, budget, metrics, stop_reason,
            None, None, confidence,
        )

        if structured is None:
            reason = (
                "OpenRouter returned no schema-valid DiagnosisResult "
                f"(stop_reason={stop_reason}). Refusing to act on unstructured output."
            )
            policy = validate_diagnosis(
                None,
                evidence_ids=catalog.ids,
                incident_id=incident_id,
                budget_exhausted=budget.exhausted,
                iteration_limit_hit=iteration_limit_hit,
            )
            return AgentDiagnosis(
                status=STATUS_REQUIRES_HUMAN,
                report=self._report_from_policy(
                    policy, catalog, deterministic_baseline, reason
                ),
                telemetry=telemetry,
                policy=policy,
                structured=None,
                incident_id=incident_id,
                bedrock_status=STATUS_OPENROUTER_SCHEMA_REFUSED,
            )

        policy = validate_diagnosis(
            structured,
            evidence_ids=catalog.ids,
            incident_id=incident_id,
            budget_exhausted=budget.exhausted,
            iteration_limit_hit=iteration_limit_hit,
        )

        status = STATUS_DIAGNOSED if policy.allowed else STATUS_REQUIRES_HUMAN

        report = self._report_from_structured(
            structured, policy, catalog, deterministic_baseline
        )

        return AgentDiagnosis(
            status=status,
            report=report,
            telemetry=telemetry,
            policy=policy,
            structured=structured,
            incident_id=incident_id,
            bedrock_status=STATUS_OPENROUTER_SUCCESS,
        )

    def _telemetry(
        self,
        latency_ms: int,
        budget: ToolBudget,
        metrics: Any,
        stop_reason: Optional[str],
        error_class: Optional[str],
        error_detail: Optional[str],
        confidence: Optional[float],
    ) -> AgentTelemetry:
        usage_summary = (
            summarise_tool_use(metrics, budget)
            if metrics is not None
            else {
                "tool_calls": dict(budget.counts),
                "tool_call_count": budget.total,
            }
        )

        usage: Dict[str, Any] = {}
        turns = 0
        try:
            usage = dict(getattr(metrics, "accumulated_usage", {}) or {})
            turns = int(getattr(metrics, "cycle_count", 0) or 0)
        except Exception:
            usage = {}

        return AgentTelemetry(
            agent_mode=MODE_OPENROUTER,
            model_id=self.config.model_id,
            aws_region=None,
            agent_latency_ms=latency_ms,
            diagnosis_confidence=confidence,
            tool_calls=usage_summary.get("tool_calls") or {},
            tool_call_count=int(usage_summary.get("tool_call_count") or 0),
            turns=turns,
            input_tokens=_token_count_or_none(usage.get("inputTokens")),
            output_tokens=_token_count_or_none(usage.get("outputTokens")),
            total_tokens=_token_count_or_none(usage.get("totalTokens")),
            bedrock_request_id=None,
            stop_reason=str(stop_reason) if stop_reason else None,
            strands_sdk_version=strands_sdk_version(),
            error_class=error_class,
            error_detail=error_detail,
        )

    def _report_from_structured(
        self,
        structured: DiagnosisResult,
        policy: PolicyDecision,
        catalog: EvidenceCatalog,
        baseline: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        sources = {item["id"]: item["source"] for item in catalog.items}
        corroborating = [
            sources.get(eid, eid) for eid in structured.evidence_ids
        ]
        contradicting = [
            sources.get(eid, eid)
            for eid in structured.contradictory_evidence_ids
        ]

        return {
            "root_cause": sanitize_deep(
                f"{structured.hypothesis}: {structured.explanation}"
            )[:1500],
            "recommended_remediation": policy.approved_action or "none",
            "confidence": round(float(structured.confidence), 2),
            "hypothesis": sanitize_deep(structured.hypothesis)[:200],
            "corroborating_probes": corroborating,
            "contradicting_probes": contradicting,
            "evidence_consistent": not contradicting,
            "evidence_ids": list(structured.evidence_ids),
            "contradictory_evidence_ids": list(
                structured.contradictory_evidence_ids
            ),
            "investigation_needed": [
                sanitize_deep(x)[:200]
                for x in structured.investigation_needed
            ],
            "explanation": sanitize_deep(structured.explanation)[:2000],
            "requires_human": bool(policy.requires_human),
            "notes": policy.reason,
            "runtime_state": (baseline or {}).get("runtime_state"),
            "agent_mode": MODE_OPENROUTER,
            "policy_allowed": policy.allowed,
            "policy_violation": policy.violation,
        }

    def _report_from_policy(
        self,
        policy: PolicyDecision,
        catalog: EvidenceCatalog,
        baseline: Optional[Dict[str, Any]],
        reason: str,
    ) -> Dict[str, Any]:
        base = baseline or {}
        return {
            "root_cause": sanitize_deep(
                f"Agent diagnosis unavailable: {reason}"
            )[:1500],
            "recommended_remediation": "none",
            "confidence": 0.0,
            "hypothesis": "agent_diagnosis_unavailable",
            "corroborating_probes": [],
            "contradicting_probes": [],
            "evidence_consistent": False,
            "evidence_ids": [],
            "contradictory_evidence_ids": [],
            "investigation_needed": [],
            "explanation": sanitize_deep(reason)[:2000],
            "requires_human": True,
            "notes": policy.reason,
            "runtime_state": base.get("runtime_state"),
            "agent_mode": MODE_OPENROUTER,
            "policy_allowed": False,
            "policy_violation": policy.violation,
        }

    def _describe(self, exc: BaseException) -> str:
        return sanitize_deep(
            f"{type(exc).__name__}: {exc}"
        )[:600]

    def describe(self) -> Dict[str, Any]:
        return {
            "agent_mode": MODE_OPENROUTER,
            "provider": "OpenRouter via OpenAI-compatible Strands Agents SDK",
            "model_id": self.config.model_id,
            "aws_region": None,
            "strands_sdk_version": strands_sdk_version(),
            "temperature": self.config.temperature,
            "tools_exposed": list(ALLOWED_TOOL_NAMES),
            "uses_llm": True,
        }

def _int_or_none(value: Any) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _token_count_or_none(value: Any) -> Optional[int]:
    """
    A token count, or None when there is nothing to substantiate one.

    Zero is treated as absent on purpose. Strands accumulates usage onto a
    zero-initialised counter, so a response with no `usage` block and a response
    reporting zero tokens are indistinguishable by the time we read them - and a
    real Bedrock call that returned a structured diagnosis has necessarily billed
    something. Recording 0 would therefore assert a measurement that was never
    made. Requirement: record the count if the service provided one, otherwise
    record null rather than fabricate a number.
    """
    count = _int_or_none(value)
    return count if count is not None and count > 0 else None
