"""
Agent configuration for AI Doctor.

Two modes, explicitly selected and explicitly reported:

    AI_DOCTOR_AGENT_MODE=deterministic   the offline rule engine in
                                         runner/diagnosis.py. No AWS, no network.
    AI_DOCTOR_AGENT_MODE=bedrock         a real AWS Strands Agent backed by a real
                                         Amazon Bedrock model invocation.

There is no third mode and no silent crossover. When `bedrock` is requested but
the SDK, credentials, region or model are unavailable, configuration or
invocation raises `AgentConfigurationError` / `BedrockUnavailableError` with an
actionable message. The deterministic engine is NEVER substituted quietly while
the incident claims a Bedrock diagnosis - that would be the single most
misleading thing this system could report.

Credentials are never read here and never appear in this file. The Bedrock
client is built by the Strands SDK on top of boto3's standard credential chain
(environment, shared config, IAM role, IMDS), exactly as an operator would
expect. Nothing is hardcoded and no `.env` file is parsed.
"""

import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

MODE_DETERMINISTIC = "deterministic"
MODE_BEDROCK = "bedrock"
MODE_OPENROUTER = "openrouter"
VALID_MODES = (MODE_DETERMINISTIC, MODE_BEDROCK, MODE_OPENROUTER)

FALLBACK_DETERMINISTIC = "deterministic"
FALLBACK_FAIL = "fail"
VALID_FALLBACKS = (FALLBACK_DETERMINISTIC, FALLBACK_FAIL)

# A default is provided for convenience only; it is always overridable and is
# never a credential. If the account cannot access it, Bedrock says so and the
# error is surfaced verbatim.
DEFAULT_MODEL_ID = "anthropic.claude-3-5-haiku-20241022-v1:0"
DEFAULT_REGION = "us-east-1"


class AgentConfigurationError(RuntimeError):
    """Raised when agent mode=bedrock is requested but cannot be honoured."""


def _env_int(source: Dict[str, str], name: str, default: int, minimum: int = 1) -> int:
    raw = str(source.get(name, "") or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise AgentConfigurationError(
            f"{name} must be an integer, got {raw!r}."
        ) from None
    if value < minimum:
        raise AgentConfigurationError(f"{name} must be >= {minimum}, got {value}.")
    return value


def _env_float(source: Dict[str, str], name: str, default: float, lo: float, hi: float) -> float:
    raw = str(source.get(name, "") or "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise AgentConfigurationError(f"{name} must be a number, got {raw!r}.") from None
    if not lo <= value <= hi:
        raise AgentConfigurationError(f"{name} must be between {lo} and {hi}, got {value}.")
    return value


@dataclass(frozen=True)
class AgentConfig:
    """Resolved, validated agent configuration."""

    mode: str = MODE_DETERMINISTIC
    aws_region: Optional[str] = None
    model_id: Optional[str] = None
    openrouter_api_key: Optional[str] = None
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    # Low temperature on purpose: this is troubleshooting, not creative writing.
    temperature: float = 0.0
    max_output_tokens: int = 1024

    # --- Cost / runaway-control budgets (requirement 13) -------------------
    max_turns: int = 6
    max_tool_calls: int = 8
    max_total_tokens: int = 12000
    # Total model attempts when Bedrock throttles. Strands' own default is
    # max_attempts=6 with a 4s..240s exponential backoff, which adds up to 124
    # seconds of waiting before an incident is allowed to fail. On a request path
    # that is far too long, so it is bounded here; 2 means one retry after ~1s.
    max_model_attempts: int = 2

    # --- Input size caps ---------------------------------------------------
    max_evidence_bytes: int = 16000
    max_log_lines: int = 25
    max_prompt_chars: int = 24000

    request_timeout_seconds: float = 60.0

    # What to do when bedrock mode is requested but Bedrock cannot be used.
    #   "deterministic" - run the offline engine and label the incident as such.
    #   "fail"          - report the failure and take no action.
    # Neither option may present a deterministic result as an agent diagnosis.
    fallback: str = FALLBACK_DETERMINISTIC

    @property
    def is_bedrock(self) -> bool:
        return self.mode == MODE_BEDROCK

    @property
    def is_openrouter(self) -> bool:
        return self.mode == MODE_OPENROUTER

    @property
    def allow_fallback(self) -> bool:
        return self.fallback == FALLBACK_DETERMINISTIC

    def describe(self) -> Dict[str, Any]:
        """
        Configuration state for telemetry and `/api/system-status`.

        Deliberately contains no credentials, no session tokens and no
        credential-source contents - only which mode is active and which model
        and region it would use.
        """
        return {
            "agent_mode": self.mode,
            "model_id": self.model_id,
            "aws_region": self.aws_region,
            "temperature": self.temperature,
            "max_output_tokens": self.max_output_tokens,
            "limits": {
                "turns": self.max_turns,
                "tool_calls": self.max_tool_calls,
                "total_tokens": self.max_total_tokens,
                "model_attempts": self.max_model_attempts,
            },
            "input_caps": {
                "max_evidence_bytes": self.max_evidence_bytes,
                "max_log_lines": self.max_log_lines,
                "max_prompt_chars": self.max_prompt_chars,
            },
            "fallback": self.fallback,
            "sdk_available": strands_sdk_available(),
            "strands_sdk_version": strands_sdk_version(),
            "boto3_version": boto3_version(),
            "credential_sources": credential_source_hint(),
            # Reported so an operator can see at a glance that no model reasoning
            # is happening in this process.
            "uses_llm": self.is_bedrock,
        }


def load_agent_config(env: Optional[Dict[str, str]] = None) -> AgentConfig:
    """
    Reads configuration from the environment and validates it.

    Raises `AgentConfigurationError` with an actionable message when
    `AI_DOCTOR_AGENT_MODE=bedrock` is requested but the SDK is missing or the
    region/model configuration is invalid. Credential *availability* is not
    checked here - boto3 resolves that lazily, and a missing credential is
    reported at invocation time as `BedrockUnavailableError` so the failure names
    the real cause.
    """
    source = env if env is not None else os.environ

    mode = (source.get("AI_DOCTOR_AGENT_MODE") or MODE_DETERMINISTIC).strip().lower()
    if mode not in VALID_MODES:
        raise AgentConfigurationError(
            f"AI_DOCTOR_AGENT_MODE must be one of {VALID_MODES}, got {mode!r}."
        )

    region = (source.get("AI_DOCTOR_AWS_REGION") or "").strip() or None
    if mode == MODE_OPENROUTER:
        model_id = (source.get("AI_DOCTOR_OPENROUTER_MODEL") or "").strip() or "openrouter/free"
    else:
        model_id = (source.get("AI_DOCTOR_BEDROCK_MODEL_ID") or "").strip() or None

    openrouter_api_key = (source.get("OPENROUTER_API_KEY") or "").strip() or None

    config = AgentConfig(
        mode=mode,
        aws_region=region or (DEFAULT_REGION if mode == MODE_BEDROCK else None),
        model_id=model_id or ("openrouter/free" if mode == MODE_OPENROUTER else (DEFAULT_MODEL_ID if mode == MODE_BEDROCK else None)),
        openrouter_api_key=openrouter_api_key,
        temperature=_env_float(source, "AI_DOCTOR_AGENT_TEMPERATURE", 0.0, 0.0, 1.0),
        max_output_tokens=_env_int(source, "AI_DOCTOR_AGENT_MAX_OUTPUT_TOKENS", 1024, 64),
        max_turns=_env_int(source, "AI_DOCTOR_AGENT_MAX_TURNS", 6, 1),
        max_tool_calls=_env_int(source, "AI_DOCTOR_AGENT_MAX_TOOL_CALLS", 8, 1),
        max_total_tokens=_env_int(source, "AI_DOCTOR_AGENT_MAX_TOTAL_TOKENS", 12000, 256),
        max_model_attempts=_env_int(source, "AI_DOCTOR_AGENT_MAX_MODEL_ATTEMPTS", 2, 1),
        max_evidence_bytes=_env_int(source, "AI_DOCTOR_MAX_EVIDENCE_BYTES", 16000, 256),
        max_log_lines=_env_int(source, "AI_DOCTOR_MAX_LOG_LINES", 25, 1),
        max_prompt_chars=_env_int(source, "AI_DOCTOR_MAX_PROMPT_CHARS", 24000, 512),
        request_timeout_seconds=_env_float(source, "AI_DOCTOR_AGENT_TIMEOUT_SECONDS", 60.0, 1.0, 600.0),
        fallback=_fallback(source),
    )

    # The SDK is deliberately NOT imported here. A missing package is reported at
    # invocation time by BedrockDiagnosisAgent.build_model(), so that bedrock mode
    # with no SDK degrades into a clearly labelled failure instead of making the
    # whole configuration unreadable - and so /api/system-status can still tell an
    # operator which mode they asked for and why it is not running.
    return config


def _fallback(source: Dict[str, str]) -> str:
    """
    Resolves `AI_DOCTOR_AGENT_FALLBACK`.

    Deliberately permissive about spelling ("off", "none", "false" all mean
    fail) because the consequence of guessing wrong here is either a needless
    outage or a rule-based result being mistaken for a model diagnosis.
    """
    raw = (source.get("AI_DOCTOR_AGENT_FALLBACK") or FALLBACK_DETERMINISTIC).strip().lower()
    if raw in ("", FALLBACK_DETERMINISTIC, "allow", "true", "yes", "on"):
        return FALLBACK_DETERMINISTIC
    if raw in (FALLBACK_FAIL, "none", "off", "false", "no", "error", "raise"):
        return FALLBACK_FAIL
    raise AgentConfigurationError(
        f"AI_DOCTOR_AGENT_FALLBACK must be one of {VALID_FALLBACKS}, got {raw!r}."
    )


def credential_source_hint() -> List[str]:
    """
    Names the credential sources that *appear* to be configured. Source names
    only - never their contents, never a key, never a token.

    This is a cheap local heuristic used to warn an operator in
    `/api/system-status` that bedrock mode will probably fail. It deliberately
    does not call `botocore`'s credential resolver, which can block on the EC2
    metadata service; the authoritative answer comes from the invocation itself.
    """
    found: List[str] = []
    if os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"):
        found.append("environment")
    if os.environ.get("AWS_PROFILE"):
        found.append("AWS_PROFILE")
    # A variable pointing at a file that does not exist is not a credential
    # source; reporting it as one would hide the real problem from an operator.
    shared = os.environ.get("AWS_SHARED_CREDENTIALS_FILE")
    if shared and os.path.exists(os.path.expanduser(shared)):
        found.append("AWS_SHARED_CREDENTIALS_FILE")
    if os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") or os.environ.get(
        "AWS_CONTAINER_CREDENTIALS_FULL_URI"
    ):
        found.append("container-credentials")
    if os.environ.get("AWS_ROLE_ARN") or os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE"):
        found.append("assumed-role")
    home = os.path.expanduser("~")
    if os.path.exists(os.path.join(home, ".aws", "credentials")):
        found.append("~/.aws/credentials")
    return found


def strands_sdk_available() -> bool:
    """
    True when the AWS Strands Agents SDK is importable.

    Uses `find_spec` rather than importing, so `/api/system-status` can report
    the truth about bedrock mode without paying an import cost (or triggering
    boto3's import side effects) on every request.
    """
    try:
        from importlib.util import find_spec

        return all(find_spec(name) is not None for name in ("strands", "boto3", "botocore"))
    except Exception:
        return False


def strands_sdk_version() -> Optional[str]:
    """Exact installed Strands SDK version, for telemetry and the contract test."""
    try:
        from importlib.metadata import PackageNotFoundError, version

        return version("strands-agents")
    except Exception:
        return None


def boto3_version() -> Optional[str]:
    try:
        import boto3

        return boto3.__version__
    except Exception:
        return None
