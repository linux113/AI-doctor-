"""
Network egress guard for AI Doctor's `retry_request` remediation.

Why this module exists
----------------------
The previous implementation validated the retry destination with string
prefix matching:

    if not url.startswith("http://127.0.0.1") or ...

Prefix matching does not parse a URL, so it is trivially bypassed. Both of
these satisfy `startswith("http://127.0.0.1")` / `startswith("http://localhost")`
while resolving to an attacker-controlled host:

    http://127.0.0.1.evil.com/steal     -> host is "127.0.0.1.evil.com"
    http://localhost@evil.com/steal     -> userinfo trick, host is "evil.com"

Because `retry_request` replays a captured request body (which may contain
incident evidence, prompts, or credentials), an SSRF here is an exfiltration
primitive. This module validates structurally instead.

Guarantees enforced
-------------------
1. Scheme must be http or https.
2. The URL must parse, and must have a non-empty hostname.
3. Any userinfo component ("user:pass@host") is rejected outright.
4. `hostname` (already lower-cased and de-bracketed by urllib) must exactly
   match an entry in ALLOWED_RETRY_HOSTS. Subdomains, suffixes and prefixes
   of an allowed host are NOT accepted.
5. An explicit port is allowed (services legitimately listen on :11434/:8000)
   but must be a sane integer in range.
"""

from typing import Tuple
from urllib.parse import urlparse

# Exact hostnames `retry_request` is permitted to contact.
# These are loopback spellings only; no wildcards, no subdomain matching.
ALLOWED_RETRY_HOSTS = frozenset({
    "127.0.0.1",
    "localhost",
    "::1",
    # 0.0.0.0 is a bind address rather than a real destination, but as a
    # client target Linux routes it to loopback, and the previous prefix check
    # already accepted it. Kept so this hardening does not silently regress an
    # existing caller. It cannot reach a non-local host.
    "0.0.0.0",
})

ALLOWED_SCHEMES = frozenset({"http", "https"})

MIN_PORT = 1
MAX_PORT = 65535


def validate_retry_url(url: str) -> Tuple[bool, str]:
    """
    Structurally validates a retry destination.

    Returns (is_allowed, reason). `reason` is a human-readable explanation
    suitable for the audit log; it never echoes the rejected URL back, so a
    hostile value cannot be used to smuggle content into logs or responses.
    """
    if not isinstance(url, str) or not url.strip():
        return False, "Rejected: retry destination is empty or not a string."

    try:
        parsed = urlparse(url.strip())
    except Exception:
        return False, "Rejected: retry destination is not a parseable URL."

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return False, (
            "Rejected: scheme must be http or https "
            "(file://, gopher://, ftp:// and similar are not permitted)."
        )

    # Userinfo is the classic prefix-check bypass ("http://localhost@evil.com").
    if parsed.username is not None or parsed.password is not None or "@" in (parsed.netloc or ""):
        return False, "Rejected: retry destination must not contain userinfo credentials."

    hostname = parsed.hostname  # lower-cased, IPv6 brackets stripped
    if not hostname:
        return False, "Rejected: retry destination has no hostname."

    if hostname not in ALLOWED_RETRY_HOSTS:
        return False, (
            "Security validation failed: request destination must be an exact "
            "loopback host. Subdomains and lookalike hostnames are refused."
        )

    if parsed.port is not None and not (MIN_PORT <= parsed.port <= MAX_PORT):
        return False, "Rejected: retry destination port is out of range."

    return True, "Allowed: destination is a loopback host on an approved scheme."
