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
    AgentConfig,
    AgentConfigurationError,
    credential_source_hint,
    load_agent_config,
    strands_sdk_available,
    strands_sdk_version,
)
from .schemas import AgentTelemetry
from .strands_agent import (
    STATUS_DIAGNOSED,
    STATUS_FAILED,
    STATUS_REQUIRES_HUMAN,
    BedrockDiagnosisAgent,
    BedrockUnavailableError,
)

# Reported on every outcome so a consumer can branch on how the answer was made.
STATUS_DETERMINISTIC = "DETERMINISTIC"
STATUS_FALLBACK_DETERMINISTIC = "FALLBACK_DETERMINISTIC"

# The shared report contract. Asserted against both producers in the tests, so
# adding a field to one engine without the other fails loudly.
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


class AgentOutcome:
    """A diagnosis plus an unambiguous statement of how it was produced."""

    def __init__(
        self,
        report: Dict[str, Any],
        telemetry: AgentTelemetry,
        status: str,
        policy_event: Optional[Dict[str, Any]] = None,
        bedrock_failure: Optional[Dict[str, Any]] = None,
    ):
        self.report = report
        self.telemetry = telemetry
        self.status = status
        self.policy_event = policy_event
        self.bedrock_failure = bedrock_failure

    @property
    def agent_mode(self) -> str:
        return self.telemetry.agent_mode

    @property
    def used_llm(self) -> bool:
        """True only when a model actually returned this diagnosis."""
        return self.telemetry.agent_mode == MODE_BEDROCK and self.status in (
            STATUS_DIAGNOSED,
            STATUS_REQUIRES_HUMAN,
        )

    def as_dict(self) -> Dict[str, Any]:
        out = dict(self.report)
        out["agent_status"] = self.status
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

    if not config.is_bedrock:
        return _deterministic_outcome(baseline, config, started, STATUS_DETERMINISTIC)

    if not strands_sdk_available():
        failure = {
            "error_class": "AgentConfigurationError",
            "error_detail": (
                "AI_DOCTOR_AGENT_MODE=bedrock was requested but the AWS Strands Agents SDK "
                "is not installed. Install with: pip install -r requirements-aws.txt"
            ),
            "attempted_model_id": config.model_id,
            "attempted_region": config.aws_region,
        }
        record_log("ERROR", failure["error_detail"], service="agent")
        return _handle_bedrock_failure(baseline, config, started, failure, incident_id)

    try:
        agent = BedrockDiagnosisAgent(config)
        result = agent.diagnose(incident_data, evidence, baseline, incident_id)
    except (BedrockUnavailableError, AgentConfigurationError) as exc:
        failure = {
            "error_class": getattr(exc, "error_class", type(exc).__name__),
            "error_detail": sanitize_deep(str(exc))[:900],
            "attempted_model_id": config.model_id,
            "attempted_region": config.aws_region,
        }
        record_log(
            "ERROR",
            f"Bedrock diagnosis unavailable for incident {incident_id}: "
            f"{failure['error_class']}: {failure['error_detail']}",
            service="agent",
        )
        return _handle_bedrock_failure(baseline, config, started, failure, incident_id)

    # A real model answer. agent_mode is bedrock because Bedrock was invoked.
    report = dict(result.report)
    report["agent_mode"] = MODE_BEDROCK
    report["agent_status"] = result.status
    report["agent_note"] = (
        f"Diagnosis produced by Amazon Bedrock model {config.model_id} in "
        f"{config.aws_region} through the AWS Strands Agents SDK "
        f"({result.telemetry.turns} turn(s), {result.telemetry.tool_call_count} tool call(s))."
    )
    return AgentOutcome(
        report=_with_contract(report),
        telemetry=result.telemetry,
        status=result.status,
        policy_event=result.policy.audit_event(incident_id) if result.policy else None,
    )


# ----------------------------------------------------------------------
# Outcome builders
# ----------------------------------------------------------------------

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
                "agent_status": STATUS_FAILED,
                "notes": None,
                "agent_note": (
                    "Amazon Bedrock could not perform the diagnosis and "
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
            status=STATUS_FAILED,
            bedrock_failure=failure,
        )

    telemetry = _deterministic_telemetry(config, started, baseline, error=failure)
    report = dict(baseline)
    report.update(
        {
            "agent_mode": MODE_DETERMINISTIC,
            "agent_status": STATUS_FALLBACK_DETERMINISTIC,
            # `notes` is left exactly as the rule engine wrote it - the engine
            # really did produce this answer, so its reasoning is the reasoning.
            # The substitution is stated separately, where it cannot be missed
            # and cannot be mistaken for the engine's own words.
            "agent_note": (
                f"Amazon Bedrock was requested but could not be used "
                f"({failure['error_class']}). This diagnosis came from the offline "
                "deterministic rule engine in runner/diagnosis.py, not from a model."
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
        bedrock_failure=failure,
    )


def _deterministic_outcome(
    baseline: Dict[str, Any], config: AgentConfig, started: float, status: str
) -> AgentOutcome:
    report = dict(baseline)
    report["agent_mode"] = MODE_DETERMINISTIC
    report["agent_status"] = status
    report["agent_note"] = (
        "Deterministic offline rule engine: no model was invoked and no AWS call "
        "was made. Set AI_DOCTOR_AGENT_MODE=bedrock for a model diagnosis."
    )
    return AgentOutcome(
        report=_with_contract(report),
        telemetry=_deterministic_telemetry(config, started, baseline),
        status=status,
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
    )


def _with_contract(report: Dict[str, Any]) -> Dict[str, Any]:
    """Guarantees the shared report keys exist, whatever produced the report."""
    out = dict(report)
    for key in REPORT_CONTRACT_KEYS:
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
