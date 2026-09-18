"""
The incident timeline's stage vocabulary.

Every timeline entry carries two names for the same moment:

    stage       the human-readable string that has always been rendered
    stage_code  a stable machine-readable identifier from this module

A consumer must branch on `stage_code`, never on the display string. The two are
defined together in one table so they cannot drift, and `TimelineEvent` fills the
code from that table on construction - so no code path, present or future, can
emit an entry that a consumer cannot classify.

This module is deliberately dependency-free: `backend.models` and
`runner.doctor_runner` both import it, and neither may import the other.
"""

from typing import Dict, Optional

# The pipeline, in order. RETRY appears only when a captured request was really
# replayed; a stage that did not happen must not be reported.
STAGE_DETECTED = "DETECTED"
STAGE_EVIDENCE_COLLECTED = "EVIDENCE_COLLECTED"
STAGE_AI_DIAGNOSIS = "AI_DIAGNOSIS"
STAGE_POLICY_CHECK = "POLICY_CHECK"
STAGE_REMEDIATION_STARTED = "REMEDIATION_STARTED"
STAGE_VERIFICATION = "VERIFICATION"
STAGE_RETRY = "RETRY"
STAGE_RECOVERED = "RECOVERED"
STAGE_FAILED = "FAILED"

TIMELINE_STAGE_CODES = (
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

# Display string -> code.
STAGE_CODES: Dict[str, str] = {
    "DETECTED": STAGE_DETECTED,
    "INVESTIGATING": STAGE_EVIDENCE_COLLECTED,
    "ROOT CAUSE FOUND": STAGE_AI_DIAGNOSIS,
    "POLICY CHECK": STAGE_POLICY_CHECK,
    "REMEDIATION": STAGE_REMEDIATION_STARTED,
    "VERIFYING": STAGE_VERIFICATION,
    "RETRY": STAGE_RETRY,
    "RESOLVED": STAGE_RECOVERED,
    "FAILED": STAGE_FAILED,
}


def stage_code_for(stage: Optional[str]) -> Optional[str]:
    """
    The code for a display stage, or None if the stage is not in the vocabulary.

    Unknown stages are not invented a code for: an entry that cannot be
    classified is more honest than one classified as something it is not, and
    `test_timeline_stage_vocabulary` fails the suite if any stage used in product
    code is missing from the table.
    """
    if not stage:
        return None
    return STAGE_CODES.get(stage)
