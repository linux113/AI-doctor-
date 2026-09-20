"""
The one place that decides which diagnosis engine runs.

Two modes, chosen by `AI_DOCTOR_AGENT_MODE`, and the choice is always recorded on
the incident so a reader can never mistake one for the other:

    deterministic  the offline rule engine in `runner/diagnosis.py`. No model,
                   no network, no AWS. Reproducible; used by the test suite.
    bedrock        a real Amazon Bedrock invocation through the AWS Strands
                   Agents SDK (`agent/strands_agent.py`), schema-validated and
                   policy-gated before anything is executed.

Both producers return the same report contract - the keys of
`runner.diagnosis.Diagnosis.as_dict()` - so the runner, the API and the frontend
need only one code path. The extra `agent_mode` / `agent_status` fields are what
keep that shared shape honest.

The fallback rule
-----------------
If bedrock mode is requested and Bedrock cannot be used (no credentials, no
route to the endpoint, model not enabled, SDK missing), the deterministic engine
may run *only* if `AI_DOCTOR_AGENT_FALLBACK` permits it, and the result is then
labelled `agent_mode="deterministic"` with `agent_status="FALLBACK_DETERMINISTIC"`
plus the real AWS error class and message. A rule-based conclusion is never
reported as a Bedrock diagnosis, and the telemetry deliberately carries no
`model_id` in that case: no model was invoked, so naming one would imply
otherwise. With `AI_DOCTOR_AGENT_FALLBACK=fail` the incident records the failure
and no remediation is attempted at all.
"""

import time
from typing import Any, Dict, List, Optional

from runner.diagnosis import diagnose
from runner.diagnostics import record_log
from runner.redaction import sanitize_deep

from .config import (
    MODE_BEDROCK,
    MODE_DETERMINISTIC,
    MODE_OPENROUTER,
    AgentConfig,
    AgentConfigurationError,
    credential_source_hint,
    load_agent_config,
    strands_sdk_available,
    strands_sdk_version,
)
from .schemas import AgentTelemetry
from .strands_agent import (
    FAILURE_SDK_MISSING,
    STATUS_BEDROCK_SCHEMA_REFUSED,
    STATUS_BEDROCK_SUCCESS,
    STATUS_BEDROCK_UNAVAILABLE,
    STATUS_OPENROUTER_SUCCESS,
    STATUS_OPENROUTER_SCHEMA_REFUSED,
    STATUS_OPENROUTER_UNAVAILABLE,
    STATUS_DIAGNOSED,
    STATUS_FAILED,
    STATUS_REQUIRES_HUMAN,
    BedrockDiagnosisAgent,
    OpenRouterDiagnosisAgent,
    BedrockUnavailableError,
    classify_bedrock_failure,
)

# Round-trip statuses for the paths that never reach Bedrock. The Bedrock ones
# (BEDROCK_SUCCESS / BEDROCK_SCHEMA_REFUSED / BEDROCK_UNAVAILABLE) live in
# agent.strands_agent next to the code that produces them.
STATUS_DETERMINISTIC = "DETERMINISTIC"
STATUS_FALLBACK_DETERMINISTIC = "FALLBACK_DETERMINISTIC"

# The shared DIAGNOSIS contract - exactly the keys of
# `runner.diagnosis.Diagnosis.as_dict()`. Both producers must emit these, so the
# runner, the API and the dashboard need only one code path. Asserted against the
# engine in the tests, so adding a field to one producer without the other fails
# loudly.
REPORT_CONTRACT_KEYS: tuple = (
    "root_cause",
    "recommended_remediation",
    "confidence",
    "hypothesis",
    "corroborating_probes",
    "contradicting_probes",
    "evidence_consistent",
    "notes",
    "requires_human",
    "runtime_state",
)

# The PROVENANCE contract - which engine answered, and whether a real model round
# trip happened. Present on every outcome regardless of mode, because a report
# that omits them is a report a reader can misattribute.
AGENT_RECORD_KEYS: tuple = (
    "agent_mode",
    "agent_status",
    "diagnosis_outcome",
    "bedrock_invoked",
    "used_llm",
)


class AgentOutcome:
    """A diagnosis plus an unambiguous statement of how it was produced."""

    def __init__(
        self,
        report: Dict[str, Any],
        telemetry: AgentTelemetry,
        status: str,
        policy_event: Optional[Dict[str, Any]] = None,
        bedrock_failure: Optional[Dict[str, Any]] = None,
        diagnosis_outcome: str = STATUS_FAILED,
        bedrock_invoked: bool = False,
    ):
        self.report = report
        self.telemetry = telemetry
        # `status` is the ROUND TRIP: what Bedrock (or the offline engine) did.
        self.status = status
        self.policy_event = policy_event
        self.bedrock_failure = bedrock_failure
        # `diagnosis_outcome` is the DECISION: DIAGNOSED or REQUIRES_HUMAN.
        self.diagnosis_outcome = diagnosis_outcome
        self.bedrock_invoked = bedrock_invoked

    @property
    def agent_mode(self) -> str:
        return self.telemetry.agent_mode

    @property
    def used_llm(self) -> bool:
        """
        True only when a real model round trip produced this diagnosis.

        A schema refusal does not count: Bedrock answered, but nothing usable
        came back, so no model diagnosis exists to claim.
        """
        return (
            self.telemetry.agent_mode in (MODE_BEDROCK, MODE_OPENROUTER)
            and self.status in (STATUS_BEDROCK_SUCCESS, STATUS_OPENROUTER_SUCCESS)
            and self.diagnosis_outcome in (STATUS_DIAGNOSED, STATUS_REQUIRES_HUMAN)
        )

    def as_dict(self) -> Dict[str, Any]:
        out = dict(self.report)
        out["agent_status"] = self.status
        out["diagnosis_outcome"] = self.diagnosis_outcome
        out["bedrock_invoked"] = self.bedrock_invoked
        out["agent_telemetry"] = self.telemetry.as_dict()
        out["policy_event"] = self.policy_event
        out["bedrock_failure"] = self.bedrock_failure
        out["used_llm"] = self.used_llm
        return out


def run_diagnosis(
    incident_data: Dict[str, Any],
    evidence: Dict[str, Any],
    incident_id: Optional[str] = None,
    config: Optional[AgentConfig] = None,
) -> AgentOutcome:
    """
    Produces a diagnosis report for one incident.

    Never raises for a Bedrock outage unless the operator has configured
    `AI_DOCTOR_AGENT_FALLBACK=fail`; a configuration the operator spelled wrong
    always raises, because guessing there would hide the mistake.
    """
    started = time.monotonic()
    incident_id = incident_id or (incident_data or {}).get("incident_id")

    config = config or load_agent_config()

    # The deterministic reading of the same evidence is computed in both modes.
    # In bedrock mode it is handed to the model as a labelled *prior* so the
    # model can corroborate or contradict it; it is never presented as the
    # answer, and it is discarded if the model produces a validated diagnosis.
    initial_error = str(
        (incident_data or {}).get("detected_error")
        or (incident_data or {}).get("error_message")
        or ""
    )
    baseline = diagnose(evidence or {}, initial_error).as_dict()

    if not config.is_bedrock and not config.is_openrouter:
        return _deterministic_outcome(baseline, config, started, STATUS_DETERMINISTIC)

    if config.is_openrouter:
        if not config.openrouter_api_key:
            failure = {
                "failure_kind": "OPENROUTER_API_KEY_MISSING",
                "error_class": "AgentConfigurationError",
                "aws_error_code": None,
                "error_detail": (
                    "OPENROUTER_API_KEY is required when "
                    "AI_DOCTOR_AGENT_MODE=openrouter."
                ),
                "attempted_model_id": config.model_id,
                "attempted_region": None,
            }
            record_log("ERROR", failure["error_detail"], service="agent")
            return _handle_openrouter_failure(
                baseline, config, started, failure, incident_id
            )

        try:
            agent = OpenRouterDiagnosisAgent(config)
            result = agent.diagnose(
                incident_data, evidence, baseline, incident_id
            )
        except AgentConfigurationError as exc:
            failure = {
                "failure_kind": "OPENROUTER_CONFIGURATION_ERROR",
                "error_class": type(exc).__name__,
                "aws_error_code": None,
                "error_detail": sanitize_deep(str(exc))[:900],
                "attempted_model_id": config.model_id,
                "attempted_region": None,
            }
            record_log(
                "ERROR",
                f"OpenRouter diagnosis unavailable for incident {incident_id}: "
                f"{failure['error_detail']}",
                service="agent",
            )
            return _handle_openrouter_failure(
                baseline, config, started, failure, incident_id
            )
        except Exception as exc:
            failure = {
                "failure_kind": "OPENROUTER_UNAVAILABLE",
                "error_class": type(exc).__name__,
                "aws_error_code": None,
                "error_detail": sanitize_deep(str(exc))[:900],
                "attempted_model_id": config.model_id,
                "attempted_region": None,
            }
            record_log(
                "ERROR",
                f"OpenRouter diagnosis unavailable for incident {incident_id}: "
                f"{failure['error_detail']}",
                service="agent",
            )
            return _handle_openrouter_failure(
                baseline, config, started, failure, incident_id
            )

        report = dict(result.report)
        report["agent_mode"] = MODE_OPENROUTER
        report["agent_status"] = result.bedrock_status
        report["diagnosis_outcome"] = result.status
        report["bedrock_invoked"] = False
        report["used_llm"] = result.used_llm

        if result.bedrock_status == STATUS_OPENROUTER_SUCCESS:
            report["agent_note"] = (
                f"Diagnosis produced by OpenRouter model {config.model_id} "
                f"through the OpenAI-compatible Strands Agents SDK "
                f"({result.telemetry.turns} turn(s), "
                f"{result.telemetry.tool_call_count} tool call(s))."
            )
        else:
            report["agent_note"] = (
                f"OpenRouter model {config.model_id} was reached but did not "
                "return a schema-valid DiagnosisResult. No model diagnosis "
                "is claimed and no action was approved."
            )

        return AgentOutcome(
            report=_with_contract(report),
            telemetry=result.telemetry,
            status=result.bedrock_status,
            diagnosis_outcome=result.status,
            bedrock_invoked=False,
            policy_event=(
                result.policy.audit_event(incident_id)
                if result.policy
                else None
            ),
        )

    if not strands_sdk_available():
        failure = {
            "failure_kind": FAILURE_SDK_MISSING,
            "error_class": "AgentConfigurationError",
            "aws_error_code": None,
            "error_detail": (
                "AI_DOCTOR_AGENT_MODE=bedrock was requested but the AWS Strands Agents SDK "
                "is not installed. Install with: pip install -r requirements-aws.txt"
            ),
            "attempted_model_id": config.model_id,
            "attempted_region": config.aws_region,
        }
        record_log("ERROR", failure["error_detail"], service="agent")
        return _handle_bedrock_failure(
            baseline, config, started, failure, incident_id
        )

    try:
        agent = BedrockDiagnosisAgent(config)
        result = agent.diagnose(incident_data, evidence, baseline, incident_id)
    except (BedrockUnavailableError, AgentConfigurationError) as exc:
        kind = getattr(exc, "failure_kind", None) or classify_bedrock_failure(exc)
        failure = {
            "failure_kind": kind,
            "error_class": getattr(exc, "error_class", type(exc).__name__),
            "aws_error_code": getattr(exc, "aws_error_code", None),
            "error_detail": sanitize_deep(str(exc))[:900],
            "attempted_model_id": config.model_id,
            "attempted_region": config.aws_region,
        }
        record_log(
            "ERROR",
            f"Bedrock diagnosis unavailable for incident {incident_id} "
            f"[{failure['failure_kind']}]: {failure['error_class']}: "
            f"{failure['error_detail']}",
            service="agent",
        )
        return _handle_bedrock_failure(
            baseline, config, started, failure, incident_id
        )

    # A real model round trip. agent_mode is bedrock because Bedrock answered;
    # agent_status records the round trip, diagnosis_outcome records the decision.
    report = dict(result.report)
    report["agent_mode"] = MODE_BEDROCK
    report["agent_status"] = result.bedrock_status
    report["diagnosis_outcome"] = result.status
    report["bedrock_invoked"] = result.bedrock_invoked
    report["used_llm"] = result.used_llm
    if result.bedrock_status == STATUS_BEDROCK_SUCCESS:
        report["agent_note"] = (
            f"Diagnosis produced by Amazon Bedrock model {config.model_id} in "
            f"{config.aws_region} through the AWS Strands Agents SDK "
            f"({result.telemetry.turns} turn(s), {result.telemetry.tool_call_count} tool call(s), "
            f"request {result.telemetry.bedrock_request_id or 'id unavailable'})."
        )
    else:
        report["agent_note"] = (
            f"Amazon Bedrock model {config.model_id} in {config.aws_region} was reached but "
            "did not return a schema-valid DiagnosisResult. No model diagnosis is claimed and "
            "no action was approved."
        )
    return AgentOutcome(
        report=_with_contract(report),
        telemetry=result.telemetry,
        status=result.bedrock_status,
        diagnosis_outcome=result.status,
        bedrock_invoked=result.bedrock_invoked,
        policy_event=result.policy.audit_event(incident_id) if result.policy else None,
    )


# ----------------------------------------------------------------------
# Outcome builders
# ----------------------------------------------------------------------

def _handle_openrouter_failure(
    baseline: Dict[str, Any],
    config: AgentConfig,
    started: float,
    failure: Dict[str, Any],
    incident_id: Optional[str],
) -> AgentOutcome:
    """
    OpenRouter could not be used. Either fail the incident or run the offline
    deterministic engine with the substitution stated plainly on the record.
    """
    if not config.allow_fallback:
        telemetry = _deterministic_telemetry(
            config, started, baseline, error=failure, mode=MODE_OPENROUTER
        )
        report = dict(baseline)
        report.update(
            {
                "root_cause": f"Agent diagnosis failed: {failure['error_class']}",
                "recommended_remediation": "none",
                "confidence": 0.0,
                "requires_human": True,
                "agent_mode": MODE_OPENROUTER,
                "agent_status": STATUS_OPENROUTER_UNAVAILABLE,
                "diagnosis_outcome": STATUS_FAILED,
                "bedrock_invoked": False,
                "used_llm": False,
                "notes": None,
                "agent_note": (
                    f"OpenRouter could not perform the diagnosis "
                    f"[{failure['failure_kind']}:{failure['error_class']}] and "
                    "AI_DOCTOR_AGENT_FALLBACK=fail forbids substituting the offline "
                    "engine. No remediation was attempted."
                ),
                "openrouter_failure": failure,
            }
        )
        record_log(
            "WARN",
            f"Incident {incident_id}: OpenRouter unavailable and fallback disabled; "
            "escalating to a human without acting.",
            service="agent",
        )
        return AgentOutcome(
            report=_with_contract(report),
            telemetry=telemetry,
            status=STATUS_OPENROUTER_UNAVAILABLE,
            diagnosis_outcome=STATUS_FAILED,
            bedrock_invoked=False,
            bedrock_failure=failure,
        )

    telemetry = _deterministic_telemetry(config, started, baseline, error=failure)
    report = dict(baseline)
    report.update(
        {
            "agent_mode": MODE_DETERMINISTIC,
            "agent_status": STATUS_FALLBACK_DETERMINISTIC,
            "diagnosis_outcome": STATUS_DIAGNOSED,
            "bedrock_invoked": False,
            "used_llm": False,
            "agent_note": (
                f"OpenRouter was requested but could not be used "
                f"[{failure['failure_kind']}:{failure['error_class']}]. This diagnosis came "
                "from the offline deterministic rule engine in runner/diagnosis.py, not from "
                "a model."
            ),
            "openrouter_failure": failure,
        }
    )
    record_log(
        "WARN",
        f"Incident {incident_id}: falling back to the deterministic engine "
        f"after OpenRouter failure ({failure['error_class']}); the incident is "
        f"labelled {STATUS_FALLBACK_DETERMINISTIC} and no model diagnosis is claimed.",
        service="agent",
    )
    return AgentOutcome(
        report=_with_contract(report),
        telemetry=telemetry,
        status=STATUS_FALLBACK_DETERMINISTIC,
        diagnosis_outcome=STATUS_DIAGNOSED,
        bedrock_invoked=False,
        bedrock_failure=failure,
    )


def _handle_bedrock_failure(
    baseline: Dict[str, Any],
    config: AgentConfig,
    started: float,
    failure: Dict[str, Any],
    incident_id: Optional[str],
) -> AgentOutcome:
    """
    Bedrock could not be used. Either fail the incident or run the offline
    engine with the substitution stated plainly on the record.
    """
    if not config.allow_fallback:
        telemetry = _deterministic_telemetry(
            config, started, baseline, error=failure, mode=MODE_BEDROCK
        )
        report = dict(baseline)
        report.update(
            {
                "root_cause": f"Agent diagnosis failed: {failure['error_class']}",
                "recommended_remediation": "none",
                "confidence": 0.0,
                "requires_human": True,
                "agent_mode": MODE_BEDROCK,
                "agent_status": STATUS_BEDROCK_UNAVAILABLE,
                "diagnosis_outcome": STATUS_FAILED,
                "bedrock_invoked": False,
                "used_llm": False,
                "notes": None,
                "agent_note": (
                    f"Amazon Bedrock could not perform the diagnosis "
                    f"[{failure['failure_kind']}:{failure['error_class']}] and "
                    "AI_DOCTOR_AGENT_FALLBACK=fail forbids substituting the offline "
                    "engine. No remediation was attempted."
                ),
            }
        )
        record_log(
            "WARN",
            f"Incident {incident_id}: bedrock unavailable and fallback disabled; "
            "escalating to a human without acting.",
            service="agent",
        )
        return AgentOutcome(
            report=_with_contract(report),
            telemetry=telemetry,
            status=STATUS_BEDROCK_UNAVAILABLE,
            diagnosis_outcome=STATUS_FAILED,
            bedrock_invoked=False,
            bedrock_failure=failure,
        )

    telemetry = _deterministic_telemetry(config, started, baseline, error=failure)
    report = dict(baseline)
    report.update(
        {
            "agent_mode": MODE_DETERMINISTIC,
            "agent_status": STATUS_FALLBACK_DETERMINISTIC,
            "diagnosis_outcome": STATUS_DIAGNOSED,
            "bedrock_invoked": False,
            "used_llm": False,
            # `notes` is left exactly as the rule engine wrote it - the engine
            # really did produce this answer, so its reasoning is the reasoning.
            # The substitution is stated separately, where it cannot be missed
            # and cannot be mistaken for the engine's own words.
            "agent_note": (
                f"Amazon Bedrock was requested but could not be used "
                f"[{failure['failure_kind']}:{failure['error_class']}]. This diagnosis came "
                "from the offline deterministic rule engine in runner/diagnosis.py, not from "
                "a model."
            ),
            "bedrock_failure": failure,
        }
    )
    record_log(
        "WARN",
        f"Incident {incident_id}: falling back to the deterministic engine "
        f"({failure['error_class']}); the incident is labelled "
        f"{STATUS_FALLBACK_DETERMINISTIC} and no model diagnosis is claimed.",
        service="agent",
    )
    return AgentOutcome(
        report=_with_contract(report),
        telemetry=telemetry,
        status=STATUS_FALLBACK_DETERMINISTIC,
        diagnosis_outcome=STATUS_DIAGNOSED,
        bedrock_invoked=False,
        bedrock_failure=failure,
    )


def _deterministic_outcome(
    baseline: Dict[str, Any], config: AgentConfig, started: float, status: str
) -> AgentOutcome:
    report = dict(baseline)
    report["agent_mode"] = MODE_DETERMINISTIC
    report["agent_status"] = status
    report["diagnosis_outcome"] = STATUS_DIAGNOSED
    report["bedrock_invoked"] = False
    report["used_llm"] = False
    report["agent_note"] = (
        "Deterministic offline rule engine: no model was invoked and no AWS call "
        "was made. Set AI_DOCTOR_AGENT_MODE=bedrock for a model diagnosis."
    )
    return AgentOutcome(
        report=_with_contract(report),
        telemetry=_deterministic_telemetry(config, started, baseline),
        status=status,
        diagnosis_outcome=STATUS_DIAGNOSED,
        bedrock_invoked=False,
    )


def _deterministic_telemetry(
    config: AgentConfig,
    started: float,
    baseline: Dict[str, Any],
    error: Optional[Dict[str, Any]] = None,
    mode: str = MODE_DETERMINISTIC,
) -> AgentTelemetry:
    """
    Telemetry for a path where no model produced the answer.

    `model_id` and `aws_region` stay empty even when bedrock mode was requested,
    because nothing was sent to that model. What was attempted is recorded in the
    failure payload instead, where it cannot be misread as attribution.
    """
    return AgentTelemetry(
        agent_mode=mode,
        model_id=None,
        aws_region=None,
        agent_latency_ms=int((time.monotonic() - started) * 1000),
        diagnosis_confidence=float(baseline.get("confidence") or 0.0),
        tool_calls={},
        tool_call_count=0,
        turns=0,
        input_tokens=None,
        output_tokens=None,
        total_tokens=None,
        bedrock_request_id=None,
        stop_reason=None,
        strands_sdk_version=strands_sdk_version() if strands_sdk_available() else None,
        error_class=(error or {}).get("error_class"),
        error_detail=(error or {}).get("error_detail"),
        failure_kind=(error or {}).get("failure_kind"),
        aws_error_code=(error or {}).get("aws_error_code"),
    )


def _with_contract(report: Dict[str, Any]) -> Dict[str, Any]:
    """Guarantees both contracts are satisfied, whatever produced the report."""
    out = dict(report)
    for key in REPORT_CONTRACT_KEYS:
        out.setdefault(key, None)
    for key in AGENT_RECORD_KEYS:
        out.setdefault(key, None)
    return out


def describe_agent(config: Optional[AgentConfig] = None) -> Dict[str, Any]:
    """
    Human-facing statement of which engine is running, for `/api/system-status`
    and the dashboard banner. Includes the warnings that make a misconfigured
    bedrock request visible before an incident happens.
    """
    try:
        cfg = config or load_agent_config()
    except AgentConfigurationError as exc:
        return {
            "agent_mode": None,
            "mode_uses_llm": False,
            "llm_operational": False,
            "configured": False,
            "warnings": [sanitize_deep(str(exc))[:400]],
        }

    warnings: List[str] = []
    if cfg.is_bedrock:
        if not strands_sdk_available():
            warnings.append(
                "bedrock mode is configured but the AWS Strands Agents SDK is not installed "
                "(pip install -r requirements-aws.txt); incidents will fall back to the "
                "deterministic engine and be labelled as such."
            )
        elif not credential_source_hint():
            warnings.append(
                "bedrock mode is configured but no AWS credential source was detected; the "
                "first incident will report the real credential error rather than a model "
                "diagnosis."
            )
    else:
        warnings.append(
            "deterministic offline mode: no model is invoked and no AWS call is made. "
            "Diagnoses are produced by the rule engine in runner/diagnosis.py."
        )

    detail = cfg.describe()
    # Two separate facts, because conflating them is how a dashboard ends up
    # claiming "Bedrock powered" when nothing could reach Bedrock:
    #   mode_uses_llm   - what the configuration asks for
    #   llm_operational - whether a model call could actually succeed right now
    operational = bool(cfg.is_bedrock and strands_sdk_available() and credential_source_hint())
    return {
        "agent_mode": cfg.mode,
        "mode_uses_llm": cfg.is_bedrock,
        "llm_operational": operational,
        "configured": True,
        "provider": "Amazon Bedrock via AWS Strands Agents SDK" if cfg.is_bedrock else "offline rule engine",
        "model_id": cfg.model_id if cfg.is_bedrock else None,
        "aws_region": cfg.aws_region if cfg.is_bedrock else None,
        "strands_sdk_version": detail.get("strands_sdk_version"),
        "boto3_version": detail.get("boto3_version"),
        "sdk_available": detail.get("sdk_available"),
        "credential_sources": detail.get("credential_sources") or [],
        "fallback_policy": cfg.fallback,
        "limits": detail.get("limits"),
        "input_caps": detail.get("input_caps"),
        "warnings": warnings,
    }
