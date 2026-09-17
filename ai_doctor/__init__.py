"""
AI Doctor package with built-in DeepTeam guardrails and red teaming capabilities.
"""

import os

# Disable third-party telemetry to prevent network delays and timeouts in sandbox
os.environ.setdefault("DEEPTEAM_TELEMETRY_OPT_OUT", "YES")
os.environ.setdefault("TELEMETRY_OPT_OUT", "YES")

from .assistant import AIDoctorAssistant
from .guardrails import get_ai_doctor_guardrails

__all__ = ["AIDoctorAssistant", "get_ai_doctor_guardrails"]
