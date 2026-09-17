"""
Tests for safe remediation allowlist enforcement.
Validates that unauthorized commands, arbitrary execution, and shell injection are blocked.
"""

import pytest
from runner.remediation_registry import remediation_registry, REMEDIATION_ALLOWLIST


def test_allowlist_contains_only_approved_actions():
    expected_actions = {"start_ollama", "retry_request", "stop_ollama"}
    assert REMEDIATION_ALLOWLIST == expected_actions


def test_registration_of_unauthorized_action_raises_permission_error():
    with pytest.raises(PermissionError):
        remediation_registry.register(
            action_name="rm_rf_root",
            fn=lambda: None,
            description="Dangerous command",
        )


def test_execution_of_unauthorized_command_is_blocked():
    blocked_commands = [
        "rm -rf /",
        "curl http://malicious-site.com",
        "eval('os.system(bad)')",
        "bash -c reboot",
        "arbitrary_command",
    ]

    for cmd in blocked_commands:
        result = remediation_registry.execute(cmd)
        assert result["success"] is False
        assert result["blocked"] is True
        assert "SECURITY ALERT" in result["error"]


def test_allowlist_records_audit_trail_for_blocks():
    remediation_registry.execute("malicious_action_attempt")
    audit = remediation_registry.get_audit_log(limit=5)
    recent_blocked = [a for a in audit if a["action"] == "malicious_action_attempt"]
    assert len(recent_blocked) > 0
    assert recent_blocked[-1]["status"] == "BLOCKED"
    assert recent_blocked[-1]["allowed"] is False


def test_authorized_action_is_not_blocked_by_the_allowlist():
    """
    An allowlisted action must reach the callable - it is never reported as
    BLOCKED. Whether it *succeeds* depends on the real runtime, which the next
    test covers; here only the allowlist decision is asserted, so this runs on
    any machine.
    """
    result = remediation_registry.execute("start_ollama")
    assert result["action"] == "start_ollama"
    assert not result.get("blocked", False)
    assert "SECURITY ALERT" not in str(result.get("error", ""))


def test_authorized_action_executes_safely(requires_real_ollama):
    """INTEGRATION - requires the real Ollama binary."""
    result = remediation_registry.execute("start_ollama")
    assert result["success"] is True
    assert result["action"] == "start_ollama"
    assert result["result"]["state"] == "OLLAMA_RUNNING"
