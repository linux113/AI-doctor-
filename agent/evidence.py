"""
Evidence preparation for the Bedrock agent.

Two jobs, in this order:

1. **Redact.** Everything here passes through `runner.redaction.sanitize_deep`,
   the same authoritative boundary that guards persistence and API responses.
   Nothing reaches Amazon Bedrock until it has been through it. Redaction happens
   FIRST, before size accounting, so a truncated payload can never expose a tail
   that a full one would have hidden.

2. **Catalogue.** Evidence is flattened into stable IDs (E1, E2, ...) so the model
   must cite what it used. Citations are then verifiable: an ID that is not in the
   catalog is a hallucination and the policy layer refuses the diagnosis rather
   than acting on it.

Size caps are enforced here rather than trusting the model to be brief: a
pathological evidence bundle must not become an unbounded, expensive prompt.
"""

import json
from typing import Any, Dict, List, Optional, Tuple

from runner.redaction import sanitize_deep

# Ordered by evidential weight. When the budget runs out, the tail is dropped
# first - log lines are the least decisive and the most attacker-influenceable.
_PROBE_ORDER = (
    ("runtime", "check_ollama_runtime"),
    ("port_11434", "check_port"),
    ("process_ollama", "check_process"),
    ("ollama_api", "check_ollama"),
)

# Fields inside a probe result that carry no diagnostic value but do carry bytes.
_NOISE_KEYS = ("timestamp", "collected_at", "identities", "strict", "endpoint")


def _compact(value: Any, max_len: int = 700) -> str:
    """Serialises a probe result to a short, readable string."""
    if isinstance(value, str):
        text = value
    else:
        try:
            if isinstance(value, dict):
                value = {k: v for k, v in value.items() if k not in _NOISE_KEYS and v is not None}
            text = json.dumps(value, sort_keys=True, default=str)
        except (TypeError, ValueError):
            text = str(value)
    text = " ".join(text.split())
    if len(text) > max_len:
        text = text[:max_len] + "…[truncated]"
    return text


class EvidenceCatalog:
    """The sanitised, size-capped evidence bundle handed to the model."""

    def __init__(self, items: List[Dict[str, Any]], truncated: bool, dropped: List[str]):
        self.items = items
        self.truncated = truncated
        self.dropped = dropped

    @property
    def ids(self) -> List[str]:
        return [item["id"] for item in self.items]

    def as_list(self) -> List[Dict[str, Any]]:
        return list(self.items)

    def byte_size(self) -> int:
        return len(json.dumps(self.items, default=str).encode("utf-8"))

    def unknown_ids(self, cited: Optional[List[str]]) -> List[str]:
        """Cited IDs that do not exist in this catalog - i.e. hallucinations."""
        if not cited:
            return []
        known = set(self.ids)
        return [cid for cid in cited if cid not in known]


def build_evidence_catalog(
    evidence: Dict[str, Any],
    max_evidence_bytes: int,
    max_log_lines: int,
) -> EvidenceCatalog:
    """
    Redacts and catalogues an evidence bundle.

    `evidence` is the dict produced by `DoctorRunner.collect_evidence()`. The
    input is never mutated; `sanitize_deep` returns a new structure.
    """
    # REDACTION BOUNDARY - authoritative, applied before anything else.
    safe = sanitize_deep(evidence) if isinstance(evidence, dict) else {}

    items: List[Dict[str, Any]] = []
    counter = 1

    for key, source in _PROBE_ORDER:
        if key in safe and safe[key] is not None:
            items.append({"id": f"E{counter}", "source": source, "value": _compact(safe[key])})
            counter += 1

    # Remaining top-level evidence (anything the runner adds later) is catalogued
    # generically so it cannot slip through unredacted and uncounted.
    for key, value in safe.items():
        if key in dict(_PROBE_ORDER) or key in ("recent_logs", "collected_at"):
            continue
        if value is None:
            continue
        items.append({"id": f"E{counter}", "source": str(key), "value": _compact(value)})
        counter += 1

    dropped: List[str] = []
    logs = safe.get("recent_logs") or []
    if isinstance(logs, list) and logs:
        # Cap the line count first: logs are the largest and least decisive input.
        if len(logs) > max_log_lines:
            dropped.append(f"{len(logs) - max_log_lines} log line(s) beyond the cap of {max_log_lines}")
            logs = logs[:max_log_lines]
        for line in logs:
            if isinstance(line, dict):
                text = _compact(
                    {k: v for k, v in line.items() if k in ("level", "message", "service")}, max_len=300
                )
            else:
                text = _compact(line, max_len=300)
            items.append({"id": f"E{counter}", "source": "get_recent_logs", "value": text})
            counter += 1

    # Enforce the byte budget by dropping from the tail (logs) towards the head
    # (probe results), so the most decisive evidence survives.
    catalog = EvidenceCatalog(items, truncated=False, dropped=dropped)
    while catalog.byte_size() > max_evidence_bytes and len(catalog.items) > 1:
        removed = catalog.items.pop()
        catalog.dropped.append(f"{removed['id']} ({removed['source']})")
        catalog.truncated = True

    # Re-number so IDs stay contiguous after truncation.
    for index, item in enumerate(catalog.items, start=1):
        item["id"] = f"E{index}"

    return catalog


def build_incident_summary(incident_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    The small, redacted incident header shown to the model.

    Deliberately excludes `request_context.payload` as a raw blob: the prompt text
    is already catalogued as evidence, and duplicating it invites the model to
    treat user-supplied content as instructions.
    """
    safe = sanitize_deep(incident_data) if isinstance(incident_data, dict) else {}
    summary: Dict[str, Any] = {}
    for key in ("incident_id", "detected_error", "error_class", "http_status", "service", "runtime_state"):
        if safe.get(key) is not None:
            summary[key] = _compact(safe[key], max_len=400)
    return summary


def describe_catalog_for_telemetry(catalog: EvidenceCatalog) -> Tuple[int, int, bool]:
    """(item count, byte size, truncated) - recorded on the incident, not the content."""
    return len(catalog.items), catalog.byte_size(), catalog.truncated
