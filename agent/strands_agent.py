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

from runner.diagnostics import record_log
from runner.redaction import sanitize_deep

from .config import (
    MODE_BEDROCK,
    AgentConfig,
    AgentConfigurationError,
    strands_sdk_version,
)
from .evidence import EvidenceCatalog, build_evidence_catalog, build_incident_summary
from .policy import validate_diagnosis
from .prompts import SYSTEM_PROMPT, build_user_prompt
from .schemas import AgentTelemetry, DiagnosisResult, PolicyDecision
from .tools import ALLOWED_TOOL_NAMES, ToolBudget, build_diagnostic_tools, summarise_tool_use

# Outcome states for an agent-assisted diagnosis.
STATUS_DIAGNOSED = "DIAGNOSED"
STATUS_REQUIRES_HUMAN = "REQUIRES_HUMAN"
STATUS_FAILED = "FAILED"


class BedrockUnavailableError(RuntimeError):
    """
    Amazon Bedrock could not perform the diagnosis.

    Always carries the underlying error class and a redacted message so the
    incident records the true cause instead of a generic failure.
    """

    def __init__(self, message: str, error_class: Optional[str] = None):
        super().__init__(message)
        self.error_class = error_class or "BedrockUnavailableError"


class AgentDiagnosis:
    """Everything one agent invocation produced, kept separate from what it decided."""

    def __init__(
        self,
        status: str,
        report: Dict[str, Any],
        telemetry: AgentTelemetry,
        policy: Optional[PolicyDecision] = None,
        structured: Optional[DiagnosisResult] = None,
        incident_id: Optional[str] = None,
    ):
        self.status = status
        self.incident_id = incident_id
        self.report = report
        self.telemetry = telemetry
        self.policy = policy
        self.structured = structured

    def as_dict(self) -> Dict[str, Any]:
        out = dict(self.report)
        out["agent_status"] = self.status
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
            )
        except Exception as exc:
            latency = int((time.monotonic() - started) * 1000)
            telemetry = self._telemetry(
                latency_ms=latency,
                budget=budget,
                metrics=None,
                stop_reason=None,
                error_class=type(exc).__name__,
                error_detail=self._describe(exc),
                confidence=None,
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
            input_tokens=_int_or_none(usage.get("inputTokens")),
            output_tokens=_int_or_none(usage.get("outputTokens")),
            total_tokens=_int_or_none(usage.get("totalTokens")),
            bedrock_request_id=self._last_request_id,
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

        The underlying class and message are preserved (redacted) because "the
        model failed" is not a diagnosis anyone can act on.
        """
        # botocore reports every Bedrock service error as a ClientError whose
        # real identity is in response["Error"]["Code"]; Strands additionally
        # re-raises throttling as ModelThrottledException and context overflow as
        # ContextWindowOverflowException. Matching only on the Python class name
        # would turn all of those into "something failed".
        name = type(exc).__name__
        code = _aws_error_code(exc)
        effective = code or name
        detail = self._describe(exc)

        if name in ("NoCredentialsError", "PartialCredentialsError"):
            message = (
                "No AWS credentials were found in the default credential chain "
                "(environment, shared config, IAM role, IMDS). Configure credentials for a "
                "role with bedrock:InvokeModelWithResponseStream, or run with "
                "AI_DOCTOR_AGENT_MODE=deterministic for offline operation. "
                f"Underlying error: {detail}"
            )
        elif effective in ("EndpointConnectionError", "ConnectTimeoutError", "ReadTimeoutError",
                           "NewConnectionError", "ConnectTimeoutError"):
            message = (
                f"Amazon Bedrock in region {self.config.aws_region!r} could not be reached "
                f"from this network. Underlying error: {detail}"
            )
        elif effective in ("AccessDeniedException", "UnrecognizedClientException",
                           "InvalidSignatureException", "NotAcceptPolicyException"):
            message = (
                "AWS rejected the credentials for this Bedrock call. The principal needs "
                f"bedrock:InvokeModelWithResponseStream on model {self.config.model_id!r} in "
                f"{self.config.aws_region!r}. Underlying error: {detail}"
            )
        elif effective == "ValidationException" and "model identifier" in detail.lower():
            message = (
                f"Bedrock model {self.config.model_id!r} is not valid or not enabled in "
                f"{self.config.aws_region!r}. Set AI_DOCTOR_BEDROCK_MODEL_ID to an enabled "
                f"model. Underlying error: {detail}"
            )
        elif effective in ("ModelTimeoutException", "ModelNotReadyException", "ServiceUnavailableException"):
            message = f"Bedrock model did not respond in time. Underlying error: {detail}"
        elif effective in ("ThrottlingException", "throttlingException") or name == "ModelThrottledException":
            message = (
                f"Bedrock throttled the request to model {self.config.model_id!r} in "
                f"{self.config.aws_region!r} and the bounded retry budget "
                f"({self.config.max_model_attempts} attempt(s)) was exhausted. "
                f"Underlying error: {detail}"
            )
        elif name == "ContextWindowOverflowException":
            message = (
                "The prompt exceeded the model's context window. Lower AI_DOCTOR_MAX_EVIDENCE_BYTES, "
                f"AI_DOCTOR_MAX_LOG_LINES or AI_DOCTOR_MAX_PROMPT_CHARS. Underlying error: {detail}"
            )
        else:
            message = f"{prefix}: {detail}"

        # The AWS service code where there is one, otherwise the Python class:
        # both are what an operator would search for in CloudTrail.
        return BedrockUnavailableError(message, error_class=effective)

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


def _aws_error_code(exc: BaseException) -> Optional[str]:
    """The AWS service error code inside a botocore ClientError, if there is one."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict):
            code = error.get("Code")
            if isinstance(code, str) and code:
                return code
    return None


def _int_or_none(value: Any) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
