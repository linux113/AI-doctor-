"""
Time helpers for AI Doctor.

`datetime.utcnow()` is naive and deprecated since Python 3.12 (it emits a
DeprecationWarning and is scheduled for removal). Every timestamp in this
project is serialised as an ISO-8601 string ending in "Z" because
`Incident.created_at` doubles as a DynamoDB RANGE key and is sorted
lexicographically.

`now_iso()` keeps that exact wire format while using a timezone-aware clock,
and always emits six digits of fractional seconds. That makes the string
sort order stable, which the naive `isoformat()` version did not guarantee
(it drops the fractional part entirely when microseconds happen to be 0).
"""

from datetime import datetime, timezone

# Fixed-width ISO-8601 UTC, e.g. 2026-09-17T07:08:09.123456Z
_UTC_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"


def now_iso() -> str:
    """Returns the current UTC time as a fixed-width ISO-8601 string ending in 'Z'."""
    return datetime.now(timezone.utc).strftime(_UTC_FORMAT) + "Z"


def utcnow_aware() -> datetime:
    """Returns the current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)
