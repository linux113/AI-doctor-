"""
Tests for post-remediation verification stage.
"""

from runner.doctor_runner import doctor_runner
from runner.remediation import stop_ollama


def test_verification_stage_succeeds_when_service_recovers():
    # Stop Ollama first
    stop_ollama()

    # Execute remediation and verify
    result = doctor_runner.run_remediation_and_verify(
        remediation_action="start_ollama"
    )

    assert result["success"] is True
    assert result["verification"]["port_open"] is True
    assert result["verification"]["api_available"] is True
    assert "verification_time" in result["verification"]


def test_verification_detects_failure_if_action_does_not_open_port():
    # Attempting to verify stop_ollama should fail verification
    result = doctor_runner.run_remediation_and_verify(
        remediation_action="stop_ollama"
    )
    assert result["success"] is False
    assert result["stage"] == "VERIFY"
