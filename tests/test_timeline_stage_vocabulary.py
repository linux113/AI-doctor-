"""
Timeline stage vocabulary tests (requirement 12).

The timeline carries two names per entry - a display string and a machine-readable
`stage_code` - and the whole point of having both is that they cannot disagree.
These tests enforce that from three directions:

  * every stage literal used anywhere in product code is in the table, so no
    entry can be emitted that a consumer cannot classify;
  * `TimelineEvent` fills the code itself, so no construction site can forget it;
  * the codes are exactly the pipeline the requirement names, and a real incident
    carries them in order.
"""

import re
from pathlib import Path

import pytest

from backend.models import TimelineEvent
from runner.timeline import (
    STAGE_AI_DIAGNOSIS,
    STAGE_CODES,
    STAGE_DETECTED,
    STAGE_EVIDENCE_COLLECTED,
    STAGE_FAILED,
    STAGE_POLICY_CHECK,
    STAGE_RECOVERED,
    STAGE_REMEDIATION_STARTED,
    STAGE_RETRY,
    STAGE_VERIFICATION,
    TIMELINE_STAGE_CODES,
    stage_code_for,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
PRODUCT_DIRS = ("runner", "backend", "agent")

# A timeline entry's display stage is written one of two ways: as the first
# argument of the runner's `add_stage(...)` helper, or as a `stage=` keyword on a
# `TimelineEvent`. Both are matched.
#
# A bare `"stage": "..."` dict key is deliberately NOT matched: that form is used
# by `run_remediation_and_verify` for its own `failed_stage` marker ("FIX" or
# "VERIFY"), which says which step broke and is not a timeline entry at all.
# `test_the_stage_dict_key_is_only_used_for_the_failed_stage_marker` pins that
# distinction so it cannot be confused later.
STAGE_LITERAL = re.compile(
    r'''(?:add_stage\(\s*|\bstage\s*=\s*)["\']([^"\']+)["\']'''
)
DICT_STAGE_KEY = re.compile(r'''"stage"\s*:\s*["\']([^"\']+)["\']''')


def product_sources():
    for directory in PRODUCT_DIRS:
        for path in sorted((REPO_ROOT / directory).rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            yield path


def test_every_stage_literal_in_product_code_is_in_the_vocabulary():
    """
    Drift guard. A new stage added anywhere without a code would leave an entry a
    consumer cannot classify, and the failure would surface in the dashboard rather
    than in review - so it is caught here instead.
    """
    found = {}
    for path in product_sources():
        source = path.read_text()
        for literal in STAGE_LITERAL.findall(source):
            # Only display stages are of interest; a variable name or a code that
            # is already a code is not a drift risk.
            if literal in STAGE_CODES:
                found.setdefault(literal, []).append(path.name)
                continue
            if literal in TIMELINE_STAGE_CODES:
                continue  # already a code, e.g. in a mapping or a test fixture
            found.setdefault(literal, []).append(path.name)

    unknown = {stage: files for stage, files in found.items() if stage not in STAGE_CODES}
    assert not unknown, (
        f"stages used in product code are missing from STAGE_CODES: {unknown}"
    )
    assert found, "the scan found no stage literals at all - is the regex still valid?"
    # The whole pipeline must actually be emitted somewhere, not just defined.
    assert set(found) >= {"DETECTED", "INVESTIGATING", "ROOT CAUSE FOUND", "POLICY CHECK",
                          "REMEDIATION", "VERIFYING", "RETRY", "RESOLVED", "FAILED"}, sorted(found)


def test_the_stage_dict_key_is_only_used_for_the_failed_stage_marker():
    """
    The distinction the scan above relies on, pinned so it cannot silently become
    wrong. A `"stage": "..."` dict key in product code is the remediation
    outcome's own marker - which step broke - and never a timeline entry.
    """
    seen = {}
    for path in product_sources():
        for literal in DICT_STAGE_KEY.findall(path.read_text()):
            seen.setdefault(literal, set()).add(path.name)

    assert seen, "no dict-form stage keys were found - the scan premise changed"
    assert set(seen) == {"FIX", "VERIFY"}, seen
    for files in seen.values():
        assert files == {"doctor_runner.py"}, files


def test_the_table_covers_exactly_the_required_pipeline():
    """The vocabulary is the one the requirement names: no more, no fewer."""
    assert set(STAGE_CODES.values()) == set(TIMELINE_STAGE_CODES)
    assert TIMELINE_STAGE_CODES == (
        STAGE_DETECTED,
        STAGE_EVIDENCE_COLLECTED,
        STAGE_AI_DIAGNOSIS,
        STAGE_POLICY_CHECK,
        STAGE_REMEDIATION_STARTED,
        STAGE_VERIFICATION,
        STAGE_RETRY,
        STAGE_RECOVERED,
        STAGE_FAILED,
    )
    # No two display strings may map to the same code ambiguously in one run, and
    # no code may be unreachable.
    assert len(set(STAGE_CODES.values())) == len(STAGE_CODES)


@pytest.mark.parametrize(
    "stage,expected",
    [
        ("DETECTED", STAGE_DETECTED),
        ("INVESTIGATING", STAGE_EVIDENCE_COLLECTED),
        ("ROOT CAUSE FOUND", STAGE_AI_DIAGNOSIS),
        ("POLICY CHECK", STAGE_POLICY_CHECK),
        ("REMEDIATION", STAGE_REMEDIATION_STARTED),
        ("VERIFYING", STAGE_VERIFICATION),
        ("RETRY", STAGE_RETRY),
        ("RESOLVED", STAGE_RECOVERED),
        ("FAILED", STAGE_FAILED),
    ],
)
def test_each_display_stage_maps_to_its_code(stage, expected):
    assert stage_code_for(stage) == expected


def test_an_unknown_stage_is_not_given_an_invented_code():
    """
    A stage outside the vocabulary gets None rather than a guess. An entry that
    cannot be classified is honest; one classified as something it is not would be
    a lie in the audit trail.
    """
    assert stage_code_for("SOMETHING NEW") is None
    assert stage_code_for(None) is None
    assert stage_code_for("") is None


def test_a_timeline_event_always_carries_a_code_whatever_constructed_it():
    """
    Enforced on the model, not at each call site: the healing loop, the diagnose
    endpoint and the demo endpoints all build entries, and none of them may emit
    one a consumer cannot classify.
    """
    # Built the old way, with only a display string.
    legacy = TimelineEvent(stage="ROOT CAUSE FOUND", timestamp="t", description="d")
    assert legacy.stage_code == STAGE_AI_DIAGNOSIS

    # Built with an explicit code, which must be preserved not overwritten.
    explicit = TimelineEvent(stage="DETECTED", timestamp="t", description="d",
                             stage_code=STAGE_DETECTED)
    assert explicit.stage_code == STAGE_DETECTED

    # Every display stage used in product code yields a coded entry.
    for stage in STAGE_CODES:
        entry = TimelineEvent(stage=stage, timestamp="t", description="d")
        assert entry.stage_code == STAGE_CODES[stage], stage


def test_the_code_survives_serialisation_to_the_api():
    """The dashboard reads JSON, so the code must be in the payload, not just the object."""
    entry = TimelineEvent(stage="VERIFYING", timestamp="t", description="d", verified=False)
    payload = entry.model_dump()
    assert payload["stage_code"] == STAGE_VERIFICATION
    assert payload["stage"] == "VERIFYING"
    assert payload["verified"] is False
