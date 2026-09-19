"""
Runtime preflight for AI Doctor — the checks to run BEFORE a real demonstration.

This module orchestrates capabilities that already exist elsewhere. It adds no
detection logic, no execution path and no new dependency:

    agent.config            configuration, credential-source hint, SDK versions
    agent.strands_agent     the real BedrockDiagnosisAgent and the AWS failure
                            taxonomy (`classify_bedrock_failure`)
    runner.ollama_runtime   real Ollama discovery, identity verification and health
    runner.doctor_runner    the real incident loop
    runner.redaction        the sanitisation boundary

Commands
--------
    python -m runner.preflight                     preflight (default)
    python -m runner.preflight preflight           the same, explicitly
    python -m runner.preflight bedrock-smoke-test  one REAL, billable Bedrock call
    python -m runner.preflight live-demo           the complete real demonstration

`preflight` NEVER calls Amazon Bedrock. It resolves credentials, asks STS who the
caller is, and constructs the Bedrock runtime client — none of which invokes the
model. Constructing a boto3 client makes no API call.

The two commands that do call Bedrock are gated on `AI_DOCTOR_RUN_LIVE_BEDROCK=1`
and run the redaction tests first, because a real request must not be made until
it is proven that no secret can travel in it.

Nothing here fabricates a result. Every field is either read from a real response
or reported as null with the reason.

Secrets
-------
Credential material is never printed. Access key IDs and account IDs appear only
in a masked form (last four characters), ARNs are reduced to an identity type, and
every line of output passes through `sanitize_deep` on the way out as a final
guard — so a mistake in this module cannot leak a secret either.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .redaction import sanitize_deep
from .timeutil import now_iso

REPO_ROOT = Path(__file__).resolve().parent.parent

# Opt-in for anything that makes a real, billable AWS call.
LIVE_OPT_IN_ENV = "AI_DOCTOR_RUN_LIVE_BEDROCK"
TRUTHY = ("1", "true", "yes", "on")

# Check outcomes. BLOCKED means a prerequisite is missing so the step was not
# attempted; SKIP means the step does not apply in this configuration.
PASS, FAIL, WARN, SKIP, BLOCKED = "PASS", "FAIL", "WARN", "SKIP", "BLOCKED"

# Packages the real run needs, with the import name used to verify availability.
REQUIRED_PACKAGES: Tuple[Tuple[str, str], ...] = (
    ("strands-agents", "strands"),
    ("boto3", "boto3"),
    ("botocore", "botocore"),
    ("pydantic", "pydantic"),
    ("fastapi", "fastapi"),
    ("uvicorn", "uvicorn"),
    ("psutil", "psutil"),
)

# Environment variables that decide how the agent behaves.
REQUIRED_ENV = ("AI_DOCTOR_AGENT_MODE", "AI_DOCTOR_AWS_REGION", "AI_DOCTOR_BEDROCK_MODEL_ID")
INFORMATIONAL_ENV = (
    "AI_DOCTOR_AGENT_FALLBACK",
    "AI_DOCTOR_AGENT_TIMEOUT_SECONDS",
    "AI_DOCTOR_AGENT_MAX_MODEL_ATTEMPTS",
    "OLLAMA_HOST",
    "OLLAMA_EXECUTABLE",
    LIVE_OPT_IN_ENV,
)

# Redaction tests that must pass before a real request is allowed.
REDACTION_TEST_FILES = (
    "tests/test_agent_redaction.py",
    "tests/test_agent_prompt_injection.py",
)


# =========================================================================
# Masking - the only representation of a credential this module may produce
# =========================================================================


def mask(value: Optional[str], keep: int = 4) -> str:
    """
    The last `keep` characters of a value, or a marker explaining its absence.

    Applied to access key IDs and account IDs. A secret access key or session
    token is never passed here - not masked, not truncated, never read at all.
    """
    if not value:
        return "<none>"
    text = str(value)
    if len(text) <= keep:
        return "*" * len(text)
    # Fixed-width prefix: showing only the last 4 characters, without echoing how
    # many were hidden, so the marker cannot be used to infer the value's length.
    return "****" + text[-keep:]


def identity_type(arn: Optional[str]) -> str:
    """
    The kind of principal an ARN describes, without reproducing the ARN.

    An ARN carries the account ID and the role or user name, so it is not
    reported verbatim; its shape is enough to tell an assumed role from a user.
    """
    if not arn:
        return "unknown"
    parts = str(arn).split(":")
    resource = parts[-1] if parts else ""
    for prefix in ("assumed-role", "federated-user", "role", "user"):
        if resource.startswith(prefix):
            return prefix
    return "other"


def safe(value: Any) -> Any:
    """Final guard: nothing is printed or serialised without passing through here."""
    return sanitize_deep(value)


# =========================================================================
# Check results
# =========================================================================


@dataclass
class Check:
    """One preflight observation: a name, an outcome, and safe supporting data."""

    name: str
    status: str
    detail: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {"check": self.name, "status": self.status, "detail": self.detail, **self.data}


@dataclass
class Report:
    """An ordered set of checks plus the verdict they add up to."""

    title: str
    checks: List[Check] = field(default_factory=list)
    started_at: str = field(default_factory=now_iso)
    finished_at: Optional[str] = None
    duration_ms: Optional[int] = None

    def add(self, name: str, status: str, detail: str = "", **data: Any) -> Check:
        check = Check(name=name, status=status, detail=detail, data=data)
        self.checks.append(check)
        return check

    def section(self, name: str) -> None:
        self.checks.append(Check(name=f"--- {name} ---", status=""))

    @property
    def failures(self) -> List[Check]:
        return [c for c in self.checks if c.status in (FAIL, BLOCKED)]

    @property
    def warnings(self) -> List[Check]:
        return [c for c in self.checks if c.status == WARN]

    @property
    def ready(self) -> bool:
        return not self.failures

    def as_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "ready": self.ready,
            "verdict": "READY" if self.ready else "BLOCKED",
            "counts": {
                "pass": sum(1 for c in self.checks if c.status == PASS),
                "warn": len(self.warnings),
                "fail": sum(1 for c in self.checks if c.status == FAIL),
                "blocked": sum(1 for c in self.checks if c.status == BLOCKED),
                "skip": sum(1 for c in self.checks if c.status == SKIP),
            },
            "checks": [c.as_dict() for c in self.checks if c.status != ""],
        }


# =========================================================================
# Preflight checks
# =========================================================================


def check_packages(report: Report) -> bool:
    """Required Python packages, with the versions actually installed."""
    from importlib.metadata import PackageNotFoundError
    from importlib.util import find_spec

    report.section("Python packages")
    ok = True
    for distribution, module in REQUIRED_PACKAGES:
        try:
            from importlib.metadata import version as dist_version

            installed = dist_version(distribution)
        except PackageNotFoundError:
            installed = None
        importable = find_spec(module) is not None
        if installed and importable:
            report.add(f"package:{distribution}", PASS, f"{installed}", version=installed)
        else:
            ok = False
            hint = (
                "pip install -r requirements-aws.txt"
                if distribution in ("strands-agents", "boto3", "botocore")
                else "pip install -r requirements-core.txt"
            )
            report.add(
                f"package:{distribution}",
                FAIL,
                f"not installed{'' if importable else ' and not importable'} — {hint}",
                version=installed,
            )

    if sys.version_info < (3, 10):
        report.add(
            "python-version", FAIL,
            f"{sys.version.split()[0]} is below 3.10; strands-agents and boto3 "
            "require 3.10 or newer",
        )
        ok = False
    else:
        report.add("python-version", PASS, sys.version.split()[0])
    return ok


def check_environment(report: Report) -> Optional[Any]:
    """
    Configuration and environment variables.

    Region and model ID have defaults in bedrock mode, so relying on one is
    reported as a warning rather than a failure — but a demo should set them
    explicitly, and the report says which case applies.
    """
    from agent.config import AgentConfigurationError, load_agent_config

    report.section("Configuration and environment")
    for name in REQUIRED_ENV:
        value = os.environ.get(name)
        if value and value.strip():
            report.add(f"env:{name}", PASS, value.strip() if name != "AI_DOCTOR_AGENT_MODE"
                       else value.strip().lower())
        else:
            report.add(f"env:{name}", WARN, "not set — a default or deterministic mode applies")
    for name in INFORMATIONAL_ENV:
        value = os.environ.get(name)
        report.add(
            f"env:{name}", PASS if value else SKIP,
            value if value else "not set",
        )

    try:
        config = load_agent_config()
    except AgentConfigurationError as exc:
        report.add("config:load", FAIL, str(exc)[:400])
        return None

    report.add(
        "config:load", PASS, f"mode={config.mode}",
        mode=config.mode,
        region=config.aws_region,
        model_id=config.model_id,
        fallback=config.fallback,
        timeout_seconds=config.request_timeout_seconds,
        max_model_attempts=config.max_model_attempts,
        max_turns=config.max_turns,
        max_tool_calls=config.max_tool_calls,
    )
    if not config.is_bedrock:
        report.add(
            "config:mode", WARN,
            f"AI_DOCTOR_AGENT_MODE={config.mode!r}: no model will be invoked. Set it to "
            "'bedrock' for a real Bedrock demonstration.",
        )
    return config


def check_credentials(report: Report) -> bool:
    """
    Whether the standard AWS credential provider chain resolves.

    Reports AVAILABLE or MISSING and a masked key identifier. The secret access
    key and any session token are never read into a variable that could be
    printed — only their presence is noted.
    """
    from agent.config import credential_source_hint

    report.section("AWS credentials")
    hint = credential_source_hint()
    report.add(
        "aws:credential-source-hint", PASS if hint else WARN,
        ", ".join(hint) if hint else "no source detected by the local heuristic",
        sources=list(hint),
    )

    try:
        import boto3
    except ImportError:
        report.add("aws:credential-resolution", BLOCKED, "boto3 is not installed")
        return False

    try:
        session = boto3.Session()
        credentials = session.get_credentials()
    except Exception as exc:  # noqa: BLE001 - any failure here means "unavailable"
        report.add("aws:credential-resolution", FAIL, f"{type(exc).__name__}: {exc}"[:300])
        return False

    if credentials is None:
        report.add(
            "aws:credentials", BLOCKED,
            "AWS credentials unavailable — nothing was found in the default provider "
            "chain (environment, shared config, IAM role, IMDS)",
            available=False,
        )
        return False

    try:
        frozen = credentials.get_frozen_credentials()
        access_key = getattr(frozen, "access_key", None)
        has_secret = bool(getattr(frozen, "secret_key", None))
        has_token = bool(getattr(frozen, "token", None))
    except Exception as exc:  # noqa: BLE001
        report.add("aws:credentials", FAIL, f"the chain returned credentials that could "
                                            f"not be resolved: {type(exc).__name__}")
        return False

    if not has_secret:
        report.add(
            "aws:credentials", FAIL,
            "the credential chain returned an access key ID without a secret access key",
            available=False, access_key_id=mask(access_key),
        )
        return False

    report.add(
        "aws:credentials", PASS,
        f"AVAILABLE (access key id {mask(access_key)}, secret access key present"
        f"{', session token present' if has_token else ''})",
        available=True,
        access_key_id=mask(access_key),
        session_token_present=has_token,
        method=getattr(credentials, "method", None),
    )
    return True


def check_identity(report: Report, region: Optional[str]) -> bool:
    """
    Who the caller is, via STS `GetCallerIdentity`.

    A real network call, but not to Bedrock: this is the cheapest way to prove the
    credentials work before spending anything on a model invocation. The account ID
    is masked and the ARN is reduced to an identity type.
    """
    report.section("AWS identity")
    try:
        import boto3
    except ImportError:
        report.add("aws:identity", BLOCKED, "boto3 is not installed")
        return False

    try:
        client = boto3.client("sts", region_name=region or "us-east-1")
        identity = client.get_caller_identity()
    except Exception as exc:  # noqa: BLE001 - classified below, never raised
        from agent.strands_agent import classify_bedrock_failure

        kind = classify_bedrock_failure(exc)
        report.add(
            "aws:identity", FAIL,
            f"the AWS SDK could not resolve an identity [{kind}]: "
            f"{type(exc).__name__}"[:300],
            failure_kind=kind, error_class=type(exc).__name__,
        )
        return False

    report.add(
        "aws:identity", PASS, f"account {mask(str(identity.get('Account')))}",
        account=mask(str(identity.get("Account"))),
        identity_type=identity_type(identity.get("Arn")),
        user_id=mask(str(identity.get("UserId")), keep=4),
    )
    return True


def check_bedrock_client(report: Report, config: Any) -> bool:
    """
    Construct the real Bedrock runtime client. NO Bedrock API call is made.

    Building a boto3 client resolves the endpoint and the service model locally;
    asserting the endpoint host is what proves it points at the real regional
    Bedrock runtime rather than something stubbed.
    """
    report.section("Bedrock runtime client")
    if config is None or not config.is_bedrock:
        report.add("bedrock:client", SKIP, "bedrock mode is not configured")
        return False

    try:
        from agent.strands_agent import BedrockDiagnosisAgent

        model = BedrockDiagnosisAgent(config).build_model()
    except Exception as exc:  # noqa: BLE001 - reported, never raised
        from agent.strands_agent import classify_bedrock_failure

        kind = classify_bedrock_failure(exc)
        report.add(
            "bedrock:client", FAIL, f"FAILED [{kind}]: {str(exc)[:300]}",
            failure_kind=kind, error_class=type(exc).__name__,
        )
        return False

    client = getattr(model, "client", None)
    # Every step is defensive: a client that is missing an attribute must produce
    # a FAILED check, not a traceback. The endpoint assertion below is what tells
    # a real regional Bedrock runtime client from something stubbed.
    host = getattr(getattr(client, "_endpoint", None), "host", None)
    meta = getattr(client, "meta", None)
    service = getattr(getattr(meta, "service_model", None), "service_name", None)
    client_region = getattr(meta, "region_name", None)

    if not host or not str(host).startswith("https://bedrock-runtime."):
        report.add("bedrock:client", FAIL, f"the client points at {host!r}, not the real "
                                           "Bedrock runtime endpoint")
        return False

    report.add(
        "bedrock:client", PASS, "CONSTRUCTED (no Bedrock call was made)",
        constructed=True, endpoint=str(host), service=service,
        client_region=client_region, model_id=config.model_id,
        client_class=f"{type(client).__module__}.{type(client).__name__}",
        strands_model_class=f"{type(model).__module__}.{type(model).__name__}",
    )
    return True


def check_ollama(report: Report) -> Tuple[str, Any]:
    """
    Real Ollama discovery, executable identity, process, port and API health.

    Never starts anything and never substitutes a stand-in. An absent runtime is
    reported as NOT_INSTALLED, which is a different finding from an outage.
    """
    from .ollama_runtime import get_runtime

    report.section("Ollama runtime")
    runtime = get_runtime()
    status = runtime.health()

    if not status.installed:
        report.add(
            "ollama:state", BLOCKED, "NOT_INSTALLED — no ollama executable was found on "
            "PATH or in any standard location. Nothing was started and no stand-in "
            "server was substituted.",
            state=status.state, installed=False,
        )
        return status.state, status

    report.add(
        "ollama:executable", PASS, str(status.executable),
        executable=status.executable,
    )
    # Identity is verified by asking the binary itself, not by trusting its name.
    if status.version:
        report.add("ollama:identity", PASS, f"verified, reports version {status.version}",
                   version=status.version)
    else:
        report.add("ollama:identity", WARN,
                   "an executable was found but did not report a version")

    report.add(
        "ollama:process", PASS if status.process_running else WARN,
        f"pid {status.pid}" if status.process_running else "no ollama process is running",
        process_running=status.process_running, pid=status.pid,
    )
    report.add(
        "ollama:port-11434", PASS if status.port_open else WARN,
        "open" if status.port_open else "closed", port_open=status.port_open,
    )
    report.add(
        "ollama:api-health", PASS if status.api_healthy else WARN,
        f"HTTP {status.api_status_code}" if status.api_status_code
        else (status.api_error or "no response"),
        api_healthy=status.api_healthy, api_status_code=status.api_status_code,
    )
    report.add("ollama:state", PASS if status.state == "OLLAMA_RUNNING" else WARN,
               status.detail or status.state, state=status.state)
    return status.state, status


# =========================================================================
# Rendering
# =========================================================================

_ICONS = {PASS: "ok  ", FAIL: "FAIL", WARN: "warn", SKIP: "skip", BLOCKED: "BLOCK"}


def render(report: Report) -> str:
    """Human-readable output. Every value passes through the redaction boundary."""
    lines: List[str] = []
    lines.append("=" * 78)
    lines.append(f"  {report.title}")
    lines.append(f"  {report.started_at}")
    lines.append("=" * 78)
    for check in report.checks:
        if check.status == "":
            lines.append("")
            lines.append(check.name.replace("--- ", "").replace(" ---", "").upper())
            continue
        icon = _ICONS.get(check.status, check.status)
        line = f"  [{icon}] {check.name:<38} {check.detail}"
        lines.append(str(safe(line))[:400])
    lines.append("")
    lines.append("-" * 78)
    counts = report.as_dict()["counts"]
    verdict = "READY" if report.ready else "BLOCKED"
    lines.append(
        f"  {verdict}   pass={counts['pass']} warn={counts['warn']} "
        f"fail={counts['fail']} blocked={counts['blocked']} skip={counts['skip']}"
    )
    for failure in report.failures:
        lines.append(str(safe(f"    {failure.status}: {failure.name} — {failure.detail}"))[:400])
    lines.append("-" * 78)
    return "\n".join(lines)


# =========================================================================
# The redaction gate
# =========================================================================


def run_redaction_tests(report: Report) -> bool:
    """
    Requirement: prove no secret can travel in a real request BEFORE making one.

    Runs the redaction and prompt-injection suites in a subprocess and refuses to
    continue if they do not pass. A real Bedrock request carries evidence that came
    from logs, HTTP payloads and exception text, so this gate is what makes sending
    it defensible.
    """
    report.section("Redaction gate (must pass before any real request)")
    missing = [f for f in REDACTION_TEST_FILES if not (REPO_ROOT / f).exists()]
    if missing:
        report.add("redaction:tests", BLOCKED, f"test files are missing: {missing}")
        return False

    started = time.monotonic()
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", *REDACTION_TEST_FILES, "-q", "-p", "no:randomly"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired:
        report.add("redaction:tests", FAIL, "the redaction tests did not finish in 600s")
        return False

    elapsed_ms = int((time.monotonic() - started) * 1000)
    summary = (completed.stdout or "").strip().split("\n")[-1][:200]
    if completed.returncode == 0:
        report.add("redaction:tests", PASS, f"{summary} ({elapsed_ms}ms)",
                   exit_code=0, duration_ms=elapsed_ms)
        return True

    report.add(
        "redaction:tests", BLOCKED,
        f"the redaction tests did not pass, so no real request was made: {summary}",
        exit_code=completed.returncode, duration_ms=elapsed_ms,
    )
    return False


def opt_in() -> bool:
    """Whether the operator explicitly authorised a real, billable AWS call."""
    return os.environ.get(LIVE_OPT_IN_ENV, "").strip().lower() in TRUTHY


# =========================================================================
# Command: preflight
# =========================================================================


def run_preflight(no_network: bool = False, as_json: bool = False) -> int:
    """
    Everything that can be verified without invoking a model.

    Makes at most one network call (STS GetCallerIdentity) and only when
    credentials exist; `--no-network` skips even that.
    """
    started = time.monotonic()
    report = Report(title="AI Doctor runtime preflight (no Bedrock call is made)")

    packages_ok = check_packages(report)
    config = check_environment(report)
    credentials_ok = check_credentials(report)

    if credentials_ok and not no_network:
        check_identity(report, getattr(config, "aws_region", None))
    elif not credentials_ok:
        report.add("aws:identity", BLOCKED, "AWS credentials unavailable")
    else:
        report.add("aws:identity", SKIP, "skipped by --no-network")

    if packages_ok:
        check_bedrock_client(report, config)
    else:
        report.add("bedrock:client", BLOCKED, "required packages are missing")

    state, status = check_ollama(report)

    report.finished_at = now_iso()
    report.duration_ms = int((time.monotonic() - started) * 1000)

    if as_json:
        print(json.dumps(safe(report.as_dict()), indent=2, default=str))
    else:
        print(render(report))
        print("")
        print("  Ollama state:      " + str(state))
        print("  Bedrock reachable: NOT TESTED (preflight never invokes the model)")
        print("")
        print("  Next: python -m runner.preflight bedrock-smoke-test   (real, billable)")
        print("        AI_DOCTOR_RUN_LIVE_BEDROCK=1 python -m runner.preflight live-demo")
    return 0 if report.ready else 1


# =========================================================================
# Proof fields
# =========================================================================

# The fields that together prove a demonstration happened. A null in any of the
# first five means no real model round trip occurred, whatever else is reported.
PROOF_FIELDS = (
    "agent_mode",
    "agent_status",
    "diagnosis_outcome",
    "bedrock_invoked",
    "used_llm",
    "model_id",
    "aws_region",
    "bedrock_request_id",
    "latency_ms",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "evidence_ids",
    "recommended_action",
    "policy_result",
    "remediation_action",
    "remediation_succeeded",
    "verification_result",
    "runtime_state_after",
    "retry_result",
    "final_http_status",
    "incident_status",
)


def proof_from_outcome(outcome: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts the proof fields from a real `heal_incident` result.

    Every value is read from the outcome. Nothing is defaulted to a plausible
    value: absent means null, so a reader can tell "not provided" from "zero".
    """
    telemetry = outcome.get("agent_telemetry") or {}
    policy = outcome.get("policy_decision") or {}
    verification = outcome.get("verification") or {}
    retry = outcome.get("retry_result")
    action_result = outcome.get("action_result") or {}
    timeline = outcome.get("timeline") or []

    ai_entry = next(
        (e for e in timeline if e.get("stage_code") == "AI_DIAGNOSIS"), {}
    )
    ai_summary = (ai_entry.get("details") or {}).get("ai_diagnosis") or {}

    return {
        "agent_mode": outcome.get("agent_mode"),
        "agent_status": outcome.get("agent_status"),
        "diagnosis_outcome": outcome.get("diagnosis_outcome"),
        "bedrock_invoked": outcome.get("bedrock_invoked"),
        "used_llm": outcome.get("used_llm"),
        "model_id": telemetry.get("model_id"),
        "aws_region": telemetry.get("aws_region"),
        # Only a real round trip produces these; null is the honest alternative.
        "bedrock_request_id": telemetry.get("bedrock_request_id"),
        "latency_ms": telemetry.get("agent_latency_ms"),
        # Token counts are NOT mandatory proof. Recorded when the service sent
        # them, null when it did not — never zero, never inferred.
        "input_tokens": telemetry.get("input_tokens"),
        "output_tokens": telemetry.get("output_tokens"),
        "total_tokens": telemetry.get("total_tokens"),
        "evidence_ids": ai_summary.get("evidence_ids") or [],
        "corroborating_probes": ai_summary.get("corroborating_probes") or [],
        "recommended_action": ai_summary.get("recommended_action")
                              or outcome.get("action_taken"),
        "policy_result": {
            "present": bool(policy),
            "allowed": policy.get("allowed"),
            "approved_action": policy.get("approved_action"),
            "violation": policy.get("violation"),
        },
        "remediation_action": outcome.get("action_taken"),
        "remediation_succeeded": action_result.get("success") if action_result else None,
        "verification_result": {
            "present": bool(verification),
            "success": verification.get("success"),
            "runtime_state": verification.get("runtime_state"),
            "port_open": verification.get("port_open"),
            "api_available": verification.get("api_available"),
            "api_status_code": verification.get("api_status_code"),
        } if verification else None,
        "runtime_state_after": outcome.get("runtime_state"),
        "retry_result": {
            "present": isinstance(retry, dict),
            "success": retry.get("success") if isinstance(retry, dict) else None,
            "status_code": retry.get("status_code") if isinstance(retry, dict) else None,
        },
        "final_http_status": retry.get("status_code") if isinstance(retry, dict) else None,
        "incident_status": outcome.get("status"),
        "failure_kind": telemetry.get("failure_kind"),
        "aws_error_code": telemetry.get("aws_error_code"),
        "bedrock_failure": outcome.get("bedrock_failure"),
    }


def render_proof(proof: Dict[str, Any]) -> str:
    lines = ["", "  PROOF FIELDS (null means the value was not produced, never that it is zero)"]
    for key in PROOF_FIELDS:
        value = proof.get(key)
        rendered = json.dumps(value, default=str) if isinstance(value, (dict, list)) else value
        lines.append(str(safe(f"    {key:<22} {rendered}"))[:300])
    return "\n".join(lines)


# =========================================================================
# Success criteria
# =========================================================================


def evaluate_success_criteria(proof: Dict[str, Any], runtime_state_before: str) -> List[Check]:
    """
    The eleven conditions, evaluated in pipeline order.

    The first failure is the stage to report: everything after it is a
    consequence, so naming the earliest one is what makes the output actionable.
    """
    verification = proof.get("verification_result") or {}
    retry = proof.get("retry_result") or {}
    policy = proof.get("policy_result") or {}

    criteria: List[Tuple[str, bool, str]] = [
        (
            "A real Ollama process exists",
            runtime_state_before != "OLLAMA_NOT_INSTALLED",
            f"runtime state before the run: {runtime_state_before}",
        ),
        (
            "A real application failure was generated",
            bool(proof.get("incident_status")),
            "an incident was recorded by the runner",
        ),
        (
            "Diagnostic evidence was collected",
            bool(proof.get("evidence_ids") or proof.get("corroborating_probes")),
            f"evidence_ids={proof.get('evidence_ids')} "
            f"probes={proof.get('corroborating_probes')}",
        ),
        (
            "The real Strands Agent executed",
            proof.get("agent_mode") == "bedrock" and bool(proof.get("bedrock_invoked")),
            f"agent_mode={proof.get('agent_mode')} bedrock_invoked={proof.get('bedrock_invoked')}",
        ),
        (
            "A real Bedrock request succeeded",
            proof.get("agent_status") == "BEDROCK_SUCCESS" and bool(proof.get("bedrock_request_id")),
            f"agent_status={proof.get('agent_status')} "
            f"bedrock_request_id={proof.get('bedrock_request_id')}",
        ),
        (
            "A DiagnosisResult was produced from the model response",
            bool(proof.get("used_llm")) and proof.get("diagnosis_outcome") in
            ("DIAGNOSED", "REQUIRES_HUMAN"),
            f"used_llm={proof.get('used_llm')} diagnosis_outcome={proof.get('diagnosis_outcome')}",
        ),
        (
            "The policy gate accepted the recommendation",
            # A refusal that escalates to a human is a correct policy outcome, but
            # it is not the demonstration: nothing was approved to run.
            bool(policy.get("present")) and bool(policy.get("allowed")),
            f"policy={policy}",
        ),
        (
            "An allowlisted remediation executed",
            proof.get("remediation_action") not in (None, "", "none")
            and proof.get("remediation_succeeded") is True,
            f"action={proof.get('remediation_action')} "
            f"succeeded={proof.get('remediation_succeeded')}",
        ),
        (
            "Real Ollama verification succeeded",
            verification.get("success") is True
            and verification.get("runtime_state") == "OLLAMA_RUNNING",
            f"verification={verification}",
        ),
        (
            "The original request was retried",
            bool(retry.get("present")),
            f"retry={retry}",
        ),
        (
            "The retry actually returned HTTP 200",
            proof.get("final_http_status") == 200,
            f"final_http_status={proof.get('final_http_status')}",
        ),
    ]

    checks: List[Check] = []
    for index, (name, passed, detail) in enumerate(criteria, start=1):
        checks.append(Check(name=f"criterion-{index:02d}", status=PASS if passed else FAIL,
                            detail=f"{name} — {detail}"))
    return checks


# =========================================================================
# Command: bedrock-smoke-test
# =========================================================================


def run_bedrock_smoke_test(as_json: bool = False) -> int:
    """
    One real, billable Bedrock invocation through the actual production path.

    Real `strands.Agent`, real `strands.models.BedrockModel`, the configured model
    and region, real evidence collected from this machine. Nothing is mocked and
    nothing is fabricated: if the call fails, the real AWS failure category is
    reported; if it succeeds, the request ID and token counts come from the
    service response.
    """
    started = time.monotonic()
    report = Report(title="AI Doctor Bedrock smoke test (ONE real, billable request)")

    if not opt_in():
        report.add(
            "gate:opt-in", BLOCKED,
            f"{LIVE_OPT_IN_ENV}=1 is required — this command makes a real, billable "
            "Amazon Bedrock request",
        )
        print(render(report))
        return 1
    report.add("gate:opt-in", PASS, f"{LIVE_OPT_IN_ENV} is set")

    if not run_redaction_tests(report):
        print(render(report))
        return 1

    config = check_environment(report)
    if config is None or not config.is_bedrock:
        report.add("gate:mode", BLOCKED,
                   "AI_DOCTOR_AGENT_MODE=bedrock is required for a Bedrock smoke test")
        print(render(report))
        return 1

    if not check_credentials(report):
        print(render(report))
        print("\n  BLOCKED: AWS credentials unavailable\n")
        return 1

    check_identity(report, config.aws_region)
    if not check_bedrock_client(report, config):
        print(render(report))
        return 1

    # Ollama is not required for a Bedrock smoke test, but the evidence must be
    # real, so its actual state is collected and reported either way.
    state, _status = check_ollama(report)

    report.section("The real Bedrock request")
    from agent.schemas import DiagnosisResult
    from agent.strands_agent import BedrockDiagnosisAgent, BedrockUnavailableError
    from .doctor_runner import DoctorRunner

    runner = DoctorRunner()
    evidence = runner.collect_evidence()
    incident = {
        "incident_id": f"inc-smoke-{int(time.time())}",
        "detected_error": (
            "Preflight smoke test: verifying that a real Amazon Bedrock request "
            "returns a schema-valid DiagnosisResult."
        ),
        "failure_type": "smoke_test",
        "request_context": None,
    }
    baseline = {"expected_runtime_state": "OLLAMA_RUNNING", "root_cause": "ollama_not_running"}

    agent = BedrockDiagnosisAgent(config)
    call_started = time.monotonic()
    try:
        result = agent.diagnose(incident, evidence, baseline, incident["incident_id"])
    except BedrockUnavailableError as exc:
        elapsed = int((time.monotonic() - call_started) * 1000)
        report.add(
            "bedrock:invoke", FAIL,
            f"FAILURE [{exc.failure_kind}] {exc.error_class} after {elapsed}ms",
            failure_kind=exc.failure_kind, error_class=exc.error_class,
            aws_error_code=exc.aws_error_code, elapsed_ms=elapsed,
        )
        report.finished_at = now_iso()
        report.duration_ms = int((time.monotonic() - started) * 1000)
        print(render(report))
        print("\n  RESULT: FAILURE — no DiagnosisResult was produced and none is claimed.")
        print(f"  AWS failure category: {exc.failure_kind}"
              + (f" (AWS code {exc.aws_error_code})" if exc.aws_error_code else ""))
        print("  The error detail above is the real, redacted AWS error.\n")
        return 1
    except Exception as exc:  # noqa: BLE001 - unexpected, and must not be dressed up
        from agent.strands_agent import classify_bedrock_failure

        elapsed = int((time.monotonic() - call_started) * 1000)
        kind = classify_bedrock_failure(exc)
        report.add("bedrock:invoke", FAIL,
                   f"FAILURE [{kind}] {type(exc).__name__} after {elapsed}ms",
                   failure_kind=kind, error_class=type(exc).__name__, elapsed_ms=elapsed)
        report.finished_at = now_iso()
        print(render(report))
        print(f"\n  RESULT: FAILURE [{kind}] — {type(exc).__name__}\n")
        return 1

    elapsed = int((time.monotonic() - call_started) * 1000)
    telemetry = result.telemetry

    # A real round trip is the only thing that can produce these. They are read
    # from the response, never synthesised, and a null is reported as a null.
    report.add(
        "bedrock:invoke", PASS if result.bedrock_status == "BEDROCK_SUCCESS" else FAIL,
        f"{result.bedrock_status} in {elapsed}ms",
        bedrock_status=result.bedrock_status,
        bedrock_request_id=telemetry.bedrock_request_id,
        latency_ms=telemetry.agent_latency_ms,
        input_tokens=telemetry.input_tokens,
        output_tokens=telemetry.output_tokens,
        total_tokens=telemetry.total_tokens,
        stop_reason=telemetry.stop_reason,
        turns=telemetry.turns,
        tool_calls=telemetry.tool_calls,
    )
    report.add(
        "bedrock:structured-output",
        PASS if isinstance(result.structured, DiagnosisResult) else FAIL,
        "a schema-valid DiagnosisResult was produced from the model response"
        if isinstance(result.structured, DiagnosisResult)
        else "the model answered but produced no schema-valid DiagnosisResult",
        is_diagnosis_result=isinstance(result.structured, DiagnosisResult),
    )
    report.add(
        "bedrock:live-markers",
        PASS if telemetry.bedrock_request_id else FAIL,
        "a service-assigned request ID was returned"
        if telemetry.bedrock_request_id
        else "no request ID: the service was not reached, so this is not a live result",
    )

    proof = {
        "agent_mode": telemetry.agent_mode,
        "agent_status": result.bedrock_status,
        "diagnosis_outcome": result.status,
        "bedrock_invoked": result.bedrock_invoked,
        "used_llm": result.used_llm,
        "model_id": telemetry.model_id,
        "aws_region": telemetry.aws_region,
        "bedrock_request_id": telemetry.bedrock_request_id,
        "latency_ms": telemetry.agent_latency_ms,
        "input_tokens": telemetry.input_tokens,
        "output_tokens": telemetry.output_tokens,
        "total_tokens": telemetry.total_tokens,
        "evidence_ids": list(result.report.get("evidence_ids") or []),
        "recommended_action": result.report.get("recommended_remediation"),
        "policy_result": result.policy.audit_event(incident["incident_id"]) if result.policy else None,
        "remediation_action": None,
        "remediation_succeeded": None,
        "verification_result": None,
        "runtime_state_after": state,
        "retry_result": {"present": False, "success": None, "status_code": None},
        "final_http_status": None,
        "incident_status": "SMOKE_TEST_ONLY",
        "ollama_state": state,
    }

    report.finished_at = now_iso()
    report.duration_ms = int((time.monotonic() - started) * 1000)

    success = (
        result.bedrock_status == "BEDROCK_SUCCESS"
        and isinstance(result.structured, DiagnosisResult)
        and bool(telemetry.bedrock_request_id)
    )
    if as_json:
        payload = report.as_dict()
        payload["result"] = "SUCCESS" if success else "FAILURE"
        payload["proof"] = proof
        print(json.dumps(safe(payload), indent=2, default=str))
    else:
        print(render(report))
        print(render_proof(proof))
        print("")
        print(f"  RESULT: {'SUCCESS' if success else 'FAILURE'}")
        if success:
            print("  A real Amazon Bedrock request returned a schema-valid DiagnosisResult.")
            print("  This proves the model path only — it is NOT the end-to-end demo,")
            print("  which also requires a real Ollama recovery (see live-demo).")
        else:
            print("  No DiagnosisResult is claimed. See the failure detail above.")
        print("")
    return 0 if success else 1


# =========================================================================
# Command: live-demo
# =========================================================================


def run_live_demo(create_failure: bool = False, as_json: bool = False) -> int:
    """
    The complete real demonstration, end to end, with no mocks or stand-ins.

    Requires a real AWS/Bedrock path AND a real Ollama installation. If either is
    absent the run is BLOCKED and says so — it does not start anything, does not
    fabricate a server, and does not claim a recovery.
    """
    started = time.monotonic()
    report = Report(title="AI Doctor live end-to-end demonstration (real AWS + real Ollama)")

    if not opt_in():
        report.add("gate:opt-in", BLOCKED,
                   f"{LIVE_OPT_IN_ENV}=1 is required for the live demonstration")
        print(render(report))
        return 1
    report.add("gate:opt-in", PASS, f"{LIVE_OPT_IN_ENV} is set")

    if not run_redaction_tests(report):
        print(render(report))
        return 1

    config = check_environment(report)
    if config is None or not config.is_bedrock:
        report.add("gate:mode", BLOCKED, "AI_DOCTOR_AGENT_MODE=bedrock is required")
        print(render(report))
        return 1
    if not check_credentials(report):
        print(render(report))
        print("\n  BLOCKED: AWS credentials unavailable\n")
        return 1
    check_identity(report, config.aws_region)
    if not check_bedrock_client(report, config):
        print(render(report))
        return 1

    state, status = check_ollama(report)
    if state == "OLLAMA_NOT_INSTALLED":
        report.finished_at = now_iso()
        report.duration_ms = int((time.monotonic() - started) * 1000)
        print(render(report))
        print("\n  BLOCKED: OLLAMA: NOT_INSTALLED")
        print("  The live demonstration requires a real Ollama installation. Nothing was")
        print("  started, no server was fabricated, and no recovery is claimed.")
        print("  Install Ollama, then re-run this command.\n")
        return 1

    report.section("Generating a real application failure")
    from .doctor_runner import DoctorRunner
    from .ollama_runtime import get_runtime
    from .remediation_registry import RemediationRegistry

    runner = DoctorRunner()
    if state == "OLLAMA_RUNNING" and not create_failure:
        report.add(
            "failure:generation", BLOCKED,
            "Ollama is already RUNNING, so there is no failure to recover from. Re-run "
            "with --create-failure to stop it first using the existing allowlisted "
            "stop_ollama action.",
            runtime_state=state,
        )
        report.finished_at = now_iso()
        print(render(report))
        return 1

    if state == "OLLAMA_RUNNING" and create_failure:
        # Reuses the existing allowlisted action; no new execution path is added.
        stop = RemediationRegistry().execute(
            "stop_ollama", incident_id="inc-live-demo-setup"
        )
        report.add(
            "failure:generation", PASS if stop.get("success") else FAIL,
            f"stopped the real daemon via the allowlisted stop_ollama action: {stop.get('error') or 'ok'}",
            stopped=bool(stop.get("success")),
        )
        if not stop.get("success"):
            print(render(report))
            return 1
        state, status = check_ollama(report)

    if not status.installed:
        report.add("failure:generation", BLOCKED, "the runtime disappeared during setup")
        print(render(report))
        return 1

    # A real request against the real endpoint, which really fails.
    # Reuse the runtime's own read-only probe; DoctorRunner holds registries, not
    # the runtime object, so go to the singleton the rest of the product uses.
    try:
        api_ok, api_code, api_error = get_runtime().api_health(timeout=3.0)
    except Exception as exc:  # noqa: BLE001 - report the real error, never crash
        api_ok, api_code, api_error = False, None, f"{type(exc).__name__}: {exc}"
    report.add(
        "failure:generation", PASS if not api_ok else WARN,
        f"the real Ollama API is not answering ({api_error or f'HTTP {api_code}'})"
        if not api_ok else "the API answered; there may be no failure to recover from",
        api_available=api_ok, api_status_code=api_code,
    )

    report.section("The real end-to-end run")
    incident = {
        "incident_id": f"inc-live-{int(time.time())}",
        "detected_error": api_error or f"Ollama API unavailable (HTTP {api_code})",
        "failure_type": "service_down",
        "request_context": {
            "url": "http://127.0.0.1:11434/api/tags",
            "method": "GET",
        },
    }
    outcome = runner.heal_incident(incident)
    proof = proof_from_outcome(outcome)

    report.add(
        "run:heal-incident", PASS if outcome.get("status") == "RESOLVED" else FAIL,
        f"incident {outcome.get('incident_id')} ended {outcome.get('status')}",
        incident_id=outcome.get("incident_id"),
        incident_status=outcome.get("status"),
    )

    report.section("Success criteria (requirement 10)")
    criteria = evaluate_success_criteria(proof, state)
    for check in criteria:
        report.checks.append(check)

    succeeded = all(c.status == PASS for c in criteria)
    first_failure = next((c for c in criteria if c.status == FAIL), None)

    report.finished_at = now_iso()
    report.duration_ms = int((time.monotonic() - started) * 1000)

    if as_json:
        payload = report.as_dict()
        payload["result"] = "SUCCESS" if succeeded else "FAILURE"
        payload["failed_stage"] = first_failure.detail if first_failure else None
        payload["proof"] = proof
        print(json.dumps(safe(payload), indent=2, default=str))
    else:
        print(render(report))
        print(render_proof(proof))
        print("")
        if succeeded:
            print("  RESULT: SUCCESS — every criterion passed against real AWS and real Ollama.")
        else:
            print("  RESULT: FAILURE")
            if first_failure:
                print(f"  Failed stage: {first_failure.detail}")
            print("  The criteria after the first failure are consequences of it.")
        print("")
    return 0 if succeeded else 1


# =========================================================================
# Entry point
# =========================================================================


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m runner.preflight",
        description="Preflight, Bedrock smoke test and live demonstration for AI Doctor.",
        epilog=(
            "preflight never calls Amazon Bedrock. bedrock-smoke-test makes one real, "
            "billable request. live-demo runs the complete real recovery loop. Both "
            f"require {LIVE_OPT_IN_ENV}=1 and run the redaction tests first."
        ),
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--no-network", action="store_true",
                        help="make no network calls at all (skips the STS identity check)")
    sub = parser.add_subparsers(dest="command")

    # Flags are accepted both before and after the subcommand name. The
    # subparsers use SUPPRESS so an omitted flag cannot clobber a value that was
    # already set on the top-level parser (argparse would otherwise overwrite it
    # with the subparser's own default).
    pre = sub.add_parser("preflight", help="verify the runtime without invoking a model")
    pre.add_argument("--no-network", action="store_true", default=argparse.SUPPRESS,
                     help="make no network calls at all (skips the STS identity check)")
    pre.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                     help="emit machine-readable JSON")

    smoke = sub.add_parser("bedrock-smoke-test",
                           help="ONE real, billable Bedrock request (requires opt-in)")
    smoke.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                       help="emit machine-readable JSON")

    demo = sub.add_parser("live-demo",
                          help="the complete real demonstration (requires opt-in + real Ollama)")
    demo.add_argument("--create-failure", action="store_true",
                      help="stop a running Ollama first, via the existing allowlisted action")
    demo.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                      help="emit machine-readable JSON")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    command = args.command or "preflight"
    as_json = bool(getattr(args, "json", False))

    if command == "preflight":
        return run_preflight(no_network=bool(getattr(args, "no_network", False)), as_json=as_json)
    if command == "bedrock-smoke-test":
        return run_bedrock_smoke_test(as_json=as_json)
    if command == "live-demo":
        return run_live_demo(create_failure=bool(getattr(args, "create_failure", False)),
                             as_json=as_json)
    print(f"unknown command: {command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
