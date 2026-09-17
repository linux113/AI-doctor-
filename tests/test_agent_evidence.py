"""
Evidence-catalogue and cost-control tests (requirement 13).

Everything the model sees is built here, so every ceiling is enforced here:
maximum evidence bytes, maximum log lines, maximum prompt characters. The rules
that matter:

* decisive probe results are catalogued first and logs last, so when the byte
  budget forces something to be dropped it is the least decisive material;
* truncation is DISCLOSED - in the catalog's `dropped` list and in the prompt
  text itself - never silent, because a model reasoning over a silently
  truncated bundle would be reasoning over a lie;
* IDs stay contiguous after truncation, so a citation can always be checked
  against what was actually sent;
* telemetry records counts and sizes, never content.
"""

import pytest

from agent.evidence import (
    EvidenceCatalog,
    build_evidence_catalog,
    build_incident_summary,
    describe_catalog_for_telemetry,
)
from agent.prompts import EVIDENCE_FENCE, build_user_prompt

FULL_EVIDENCE = {
    "collected_at": "2026-09-17T10:00:00Z",
    "runtime": {"installed": True, "state": "OLLAMA_STOPPED", "binary_path": "/usr/local/bin/ollama"},
    "port_11434": {"is_open": False, "status": "closed"},
    "process_ollama": {"is_running": False, "pids": []},
    "ollama_api": {"is_available": False},
    "recent_logs": [{"level": "ERROR", "message": f"line {i} failed", "service": "demo"} for i in range(40)],
}


def catalog(evidence=None, **kwargs):
    kwargs.setdefault("max_evidence_bytes", 16000)
    kwargs.setdefault("max_log_lines", 25)
    return build_evidence_catalog(evidence if evidence is not None else FULL_EVIDENCE, **kwargs)


# =========================================================================
# Identity and ordering
# =========================================================================


def test_ids_are_contiguous_and_start_at_e1():
    items = catalog().items
    assert items, "catalog was empty"
    assert [item["id"] for item in items] == [f"E{i}" for i in range(1, len(items) + 1)]


def test_decisive_probes_are_catalogued_before_logs():
    """
    The byte budget is enforced by dropping from the tail, so ordering decides
    what survives. Probe results must come first.
    """
    sources = [item["source"] for item in catalog().items]
    first_log = sources.index("get_recent_logs")
    assert all(s != "get_recent_logs" for s in sources[:first_log]), sources
    assert set(sources[:first_log]) >= {"check_port", "check_process", "check_ollama"}


def test_runtime_probe_is_catalogued_first():
    """
    `runtime` is the authoritative installed/stopped distinction; it must never be
    the thing that gets dropped.
    """
    assert catalog().items[0]["source"] == "check_ollama_runtime"


def test_every_item_carries_id_source_and_value():
    for item in catalog().items:
        assert set(item) == {"id", "source", "value"}
        assert isinstance(item["value"], str) and item["value"]


def test_noise_keys_are_dropped_to_save_budget():
    """Timestamps and identity metadata cost bytes and decide nothing."""
    blob = str(catalog().items)
    assert "collected_at" not in blob


def test_unknown_top_level_evidence_is_still_catalogued():
    """
    A field the runner adds later must not slip through unredacted and uncounted.
    """
    evidence = dict(FULL_EVIDENCE)
    evidence["some_new_probe"] = {"detail": "new information"}
    sources = [item["source"] for item in catalog(evidence).items]
    assert "some_new_probe" in sources


# =========================================================================
# Log-line cap
# =========================================================================


@pytest.mark.parametrize("cap", [1, 5, 10, 25])
def test_log_lines_are_capped(cap):
    items = catalog(max_log_lines=cap).items
    log_items = [i for i in items if i["source"] == "get_recent_logs"]
    assert len(log_items) <= cap
    assert len(FULL_EVIDENCE["recent_logs"]) == 40 > cap


def test_dropped_log_lines_are_recorded_not_silently_discarded():
    result = catalog(max_log_lines=5)
    assert result.dropped, "truncation was not disclosed"
    assert any("35 log line(s)" in d for d in result.dropped), result.dropped


def test_all_logs_survive_when_under_the_cap():
    evidence = dict(FULL_EVIDENCE)
    evidence["recent_logs"] = [{"level": "INFO", "message": "one line"}]
    result = catalog(evidence, max_log_lines=25)
    assert result.dropped == []
    assert result.truncated is False


# =========================================================================
# Byte cap
# =========================================================================


def test_byte_budget_is_enforced():
    result = catalog(max_evidence_bytes=1200)
    assert result.byte_size() <= 1200, result.byte_size()
    assert result.truncated is True


def test_byte_truncation_drops_logs_and_keeps_probes():
    result = catalog(max_evidence_bytes=1200)
    sources = [item["source"] for item in result.items]
    assert "check_ollama_runtime" in sources
    assert "check_port" in sources
    assert result.dropped, "byte truncation was not disclosed"


def test_ids_are_renumbered_after_truncation():
    """A citation must always be checkable against what was actually sent."""
    result = catalog(max_evidence_bytes=900)
    assert [item["id"] for item in result.items] == [f"E{i}" for i in range(1, len(result.items) + 1)]
    for dropped in result.dropped:
        # Dropped entries reference IDs that no longer exist in the catalog.
        if dropped.startswith("E"):
            assert dropped.split()[0] not in result.ids


def test_a_single_oversized_item_is_never_dropped_entirely():
    """
    The loop stops at one item rather than emitting an empty catalog: an agent
    with no evidence at all cannot say anything useful, and one compacted probe
    result is better than nothing.
    """
    evidence = {"port_11434": {"is_open": False, "blob": "x" * 5000}}
    result = catalog(evidence, max_evidence_bytes=100)
    assert len(result.items) == 1


def test_catalog_of_empty_and_invalid_evidence_is_safe():
    """
    Calls the builder directly rather than the local helper, which substitutes the
    full fixture for None. A missing or corrupt evidence bundle must produce an
    empty catalog, not an exception and not fabricated evidence.
    """
    for bad in ({}, None, [], "not-a-dict", 42, {"runtime": None, "port_11434": None}):
        result = build_evidence_catalog(bad, max_evidence_bytes=16000, max_log_lines=25)
        assert isinstance(result, EvidenceCatalog)
        assert result.items == [], bad
        assert result.byte_size() < 200
        assert result.truncated is False


# =========================================================================
# Hallucination checking
# =========================================================================


def test_unknown_ids_detects_hallucinated_citations():
    result = catalog()
    assert result.unknown_ids(["E1", "E99"]) == ["E99"]
    assert result.unknown_ids(["E1"]) == []
    assert result.unknown_ids([]) == []
    assert result.unknown_ids(None) == []
    assert set(result.unknown_ids(["E404", "E5150"])) == {"E404", "E5150"}


def test_ids_property_matches_the_items():
    result = catalog()
    assert result.ids == [item["id"] for item in result.items]


# =========================================================================
# Incident summary
# =========================================================================


def test_incident_summary_carries_only_the_header_fields():
    summary = build_incident_summary({
        "incident_id": "inc-1",
        "detected_error": "HTTP 500",
        "error_class": "UpstreamError",
        "http_status": 500,
        "service": "demo",
        "runtime_state": "OLLAMA_STOPPED",
        "request_context": {"payload": {"prompt": "x" * 5000}},
        "evidence": {"blob": "y" * 5000},
    })
    assert set(summary) <= {"incident_id", "detected_error", "error_class", "http_status",
                            "service", "runtime_state"}
    # The raw request blob is deliberately excluded: it is catalogued as evidence
    # instead, and duplicating it invites the model to treat user-supplied
    # content as instructions.
    assert "request_context" not in summary
    assert "evidence" not in summary


def test_incident_summary_of_nothing_is_empty_not_broken():
    assert build_incident_summary({}) == {}
    assert build_incident_summary(None) == {}


# =========================================================================
# Telemetry describes size, never content
# =========================================================================


def test_telemetry_description_is_counts_not_content():
    result = catalog()
    count, size, truncated = describe_catalog_for_telemetry(result)
    assert count == len(result.items)
    assert size == result.byte_size()
    assert truncated is result.truncated
    assert isinstance(count, int) and isinstance(size, int) and isinstance(truncated, bool)
    # No evidence text can hide in three numbers.
    assert "line 0 failed" not in str((count, size, truncated))


# =========================================================================
# Prompt size cap
# =========================================================================


def test_prompt_is_capped_and_truncation_is_disclosed_in_the_prompt():
    prompt = build_user_prompt(
        build_incident_summary({"incident_id": "inc-1", "detected_error": "boom"}),
        catalog().as_list(),
        {"root_cause": "OLLAMA_STOPPED"},
        max_prompt_chars=1200,
    )
    assert len(prompt) <= 1200 + 250, len(prompt)
    assert "truncated" in prompt.lower()
    assert "prompt size cap" in prompt


def test_uncapped_prompt_contains_the_whole_catalog_and_the_fence():
    items = catalog(max_log_lines=3).as_list()
    prompt = build_user_prompt(
        build_incident_summary({"incident_id": "inc-1", "detected_error": "boom"}),
        items,
        {"root_cause": "OLLAMA_STOPPED"},
        max_prompt_chars=24000,
    )
    for item in items:
        assert item["id"] in prompt, f"{item['id']} missing from the prompt"
    assert prompt.count(EVIDENCE_FENCE) == 1
    assert "UNTRUSTED DIAGNOSTIC EVIDENCE ENDS HERE" in prompt
    # The deterministic baseline is presented as a prior the model may contradict,
    # never as the conclusion.
    assert "prior, not an answer" in prompt


def test_prompt_never_exceeds_the_cap_even_with_pathological_evidence():
    evidence = {"port_11434": {"blob": "z" * 200000}}
    items = build_evidence_catalog(evidence, max_evidence_bytes=16000, max_log_lines=25).as_list()
    prompt = build_user_prompt({}, items, {}, max_prompt_chars=4000)
    assert len(prompt) <= 4000 + 250
    assert "truncated" in prompt.lower()
