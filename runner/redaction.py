"""
Authoritative secret-redaction path for AI Doctor.

Why this module exists
----------------------
Redaction used to live in `runner/diagnostics.py` and was applied at exactly two
call sites: process command lines and the in-memory log buffer. Incident
documents never passed through it, so `backend/main.py::demo_query` stored the
raw request payload and `/api/incidents` served it straight back to the browser.

This module is the ONE authoritative sanitization path. `sanitize_deep()` walks
an arbitrary JSON-shaped structure and redacts every string it finds, so a
secret cannot survive by hiding in a nested list or dict. It is applied at the
data-model boundary (`Incident`'s Pydantic validator), which means every
downstream consumer inherits it automatically:

    * incident persistence (`IncidentRepository.save`)
    * every API response that serialises an `Incident`
    * future Amazon Bedrock prompt construction
    * future DynamoDB / S3 persistence

Callers must not need to remember to redact. `redact_sensitive_data` is still
re-exported from `runner.diagnostics` for existing callers, but new code should
use `sanitize_deep`.

Ordering matters: the most specific patterns run first so a generic rule cannot
clip a structured token down to a recognisable fragment (for example reducing a
PEM block to its header line, which still discloses the key type).
"""

import re
from typing import Any, Optional

# Depth and breadth caps. A hostile or corrupt payload must not be able to turn
# sanitisation into unbounded recursion or a denial of service.
MAX_DEPTH = 32
MAX_ITEMS = 10000
MAX_STRING_LENGTH = 200_000

REDACTED = "[REDACTED]"

# ---------------------------------------------------------------------------
# Sensitive dictionary KEYS
#
# The patterns above match secrets written *inside* a string ("password=hunter2",
# "Authorization: Bearer ..."). They cannot match a JSON object, where the name
# and the value are separate nodes: {"password": "hunter2"} contains no
# "password=" substring anywhere. `request_context.payload` is exactly such an
# object, so a captured request body would leak its credentials verbatim.
#
# These rules are applied to dict keys by `sanitize_deep` only - never to free
# text - so prose such as "the password rotation policy is documented in the
# runbook" is untouched. Only *string* values are replaced: an int or bool under
# a secret-ish name ({"token_count": 5}, {"token_gate_enabled": true}) carries no
# secret and stays readable.
# ---------------------------------------------------------------------------
SENSITIVE_KEY_RULES = [
    (re.compile(r"private[_-]?key", re.IGNORECASE), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"secret[_-]?access[_-]?key|aws[_-]?secret", re.IGNORECASE), "[REDACTED_AWS_SECRET]"),
    (re.compile(r"access[_-]?key[_-]?id", re.IGNORECASE), "[REDACTED_AWS_KEY_ID]"),
    (re.compile(r"pass(?:word|wd)|\bpwd\b", re.IGNORECASE), "[REDACTED_PASSWORD]"),
    (re.compile(r"api[_-]?key|access[_-]?token|secret|credential", re.IGNORECASE), "[REDACTED_KEY]"),
    (re.compile(r"authorization|\bauth\b|bearer", re.IGNORECASE), "[REDACTED_HEADER]"),
    (re.compile(r"session[_-]?id|cookie", re.IGNORECASE), "[REDACTED_SESSION]"),
    (re.compile(r"token", re.IGNORECASE), "[REDACTED_TOKEN]"),
]


def redact_value_for_key(key: str) -> Optional[str]:
    """
    Returns the marker to substitute for a string value stored under `key`, or
    None when the key is not a sensitive field name.
    """
    if not isinstance(key, str) or not key:
        return None
    for pattern, marker in SENSITIVE_KEY_RULES:
        if pattern.search(key):
            return marker
    return None

CREDENTIAL_PATTERNS = [
    # --- Multi-line structured secrets -----------------------------------
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----",
            re.DOTALL,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    # JSON Web Tokens: three dot-separated base64url segments, header "eyJ".
    (
        re.compile(r"\beyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\b"),
        "[REDACTED_JWT]",
    ),

    # --- Provider-specific token formats ---------------------------------
    # AWS access key IDs (long-term AKIA, temporary ASIA/ABIA/ACCA).
    (re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY_ID]"),
    # Anthropic / OpenAI project keys (contain dashes, so the generic "sk-"
    # rule below does not reach them).
    (re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{16,}\b"), "[REDACTED_API_KEY]"),
    # GitHub personal access tokens (classic and fine-grained).
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    # Slack tokens.
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), "[REDACTED_SLACK_TOKEN]"),
    # Google API keys.
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"), "[REDACTED_GOOGLE_KEY]"),
    # Stripe secret / restricted keys.
    (re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"), "[REDACTED_STRIPE_KEY]"),
    # Generic "sk-" prefixed keys.
    (re.compile(r"(sk-[a-zA-Z0-9]{20,})", re.IGNORECASE), "[REDACTED_API_KEY]"),

    # --- Header and key/value forms --------------------------------------
    (re.compile(r"(Bearer\s+)[a-zA-Z0-9_\.\-]{20,}", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(Basic\s+)[A-Za-z0-9+/=_\-]{16,}"), r"\1[REDACTED_TOKEN]"),
    # Connection-string credentials, e.g. postgres://user:hunter2@host
    (re.compile(r"(://[^/\s:@]+:)[^@\s/]+(@)"), r"\1[REDACTED_PASSWORD]\2"),
    (re.compile(r"(x-api-key\s*[:=]\s*['\"]?)[^\s'\",}]+(['\"]?)", re.IGNORECASE), r"\1[REDACTED_KEY]\2"),
    (re.compile(r"(authorization\s*[:=]\s*['\"]?)[^\s'\",}]+(['\"]?)", re.IGNORECASE), r"\1[REDACTED_HEADER]\2"),
    (re.compile(r"(api[_-]?key\s*[:=]\s*['\"]?)[a-zA-Z0-9_\-]{8,}(['\"]?)", re.IGNORECASE), r"\1[REDACTED_KEY]\2"),
    # AWS_ACCESS_KEY_ID=... / aws_secret_access_key=... / access_key_id: ...
    (
        re.compile(
            r"(aws[_-]?(?:access[_-]?key[_-]?id|secret[_-]?access[_-]?key)|access[_-]?key(?:[_-]?id)?|secret[_-]?access[_-]?key)"
            r"(\s*[:=]\s*['\"]?)[^\s'\",}]+(['\"]?)",
            re.IGNORECASE,
        ),
        r"\1\2[REDACTED_KEY]\3",
    ),
    (re.compile(r"(password|passwd|pwd)(\s*[:=]\s*['\"]?)[^\s'\",}]+(['\"]?)", re.IGNORECASE), r"\1\2[REDACTED_PASSWORD]\3"),
    (re.compile(r"(secret(?:[_-]?key)?)(\s*[:=]\s*['\"]?)[^\s'\",}]+(['\"]?)", re.IGNORECASE), r"\1\2[REDACTED_SECRET]\3"),
    (re.compile(r"(token)(\s*[:=]\s*['\"]?)[^\s'\",}]+(['\"]?)", re.IGNORECASE), r"\1\2[REDACTED_TOKEN]\3"),
    (re.compile(r"(session[_-]?id|cookie)(\s*[:=]\s*['\"]?)[^\s'\",}]+(['\"]?)", re.IGNORECASE), r"\1\2[REDACTED_SESSION]\3"),
]


def redact_sensitive_data(text: Any) -> Any:
    """
    Redacts secrets, credentials, API keys and private key material from a
    string. Non-string input is returned unchanged so this can be called on
    arbitrary values without a type check at every site.
    """
    if not isinstance(text, str) or not text:
        return text
    if len(text) > MAX_STRING_LENGTH:
        # Truncate before matching: an enormous string is more likely to be an
        # attack than evidence, and catastrophic backtracking on multi-megabyte
        # input would stall the request.
        text = text[:MAX_STRING_LENGTH] + "...[TRUNCATED]"
    result = text
    for pattern, replacement in CREDENTIAL_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def sanitize_deep(obj: Any, _depth: int = 0, _budget: Optional[int] = None) -> Any:
    """
    Recursively redacts every string reachable from a JSON-shaped structure.

    Handles dict, list, tuple, set and str; every other type is returned as-is
    (ints, bools, None, floats carry no secret surface). Depth and total-item
    caps prevent a malicious or corrupt payload from causing unbounded
    recursion.

    Returns a NEW structure; the input is never mutated in place, so callers
    cannot accidentally keep a reference to the unsanitised original.
    """
    if _budget is None:
        _budget = [MAX_ITEMS]

    if _depth > MAX_DEPTH:
        return "[REDACTED_DEPTH_LIMIT]"
    if _budget[0] <= 0:
        return "[REDACTED_SIZE_LIMIT]"

    if isinstance(obj, str):
        _budget[0] -= 1
        return redact_sensitive_data(obj)

    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            _budget[0] -= 1
            if _budget[0] <= 0:
                break
            # Keys are sanitised too: a secret can be used as a dict key.
            safe_key = redact_sensitive_data(key) if isinstance(key, str) else key
            marker = redact_value_for_key(key) if isinstance(value, str) else None
            if marker is not None:
                # Value under a sensitive field name: drop it entirely rather
                # than hoping a content pattern happens to match its shape.
                out[safe_key] = marker
            else:
                out[safe_key] = sanitize_deep(value, _depth + 1, _budget)
        return out

    if isinstance(obj, (list, tuple)):
        items = [sanitize_deep(v, _depth + 1, _budget) for v in obj if _budget[0] > 0]
        return type(obj)(items) if isinstance(obj, tuple) else items

    if isinstance(obj, (set, frozenset)):
        items = {sanitize_deep(v, _depth + 1, _budget) for v in obj if _budget[0] > 0}
        return type(obj)(items)

    return obj
