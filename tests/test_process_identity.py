"""
Process-identity regression tests.

These pin the fix for substring process matching, which both misreported a dead
daemon as alive (corrupting root-cause attribution) and put unrelated processes
in `stop_ollama`'s kill list.

A real decoy shell is spawned here on purpose: the defect is only reproducible
with an actual process whose command line *mentions* the service without *being*
it.
"""

import os
import subprocess
import time

import psutil
import pytest

from runner.diagnostics import check_process
from runner.procmatch import OLLAMA_IDENTITIES, matches_process
from runner.remediation import start_ollama, stop_ollama


@pytest.fixture
def decoy_shell():
    """
    A live process whose argv contains "runner.ollama_service" as part of a
    longer string - exactly the shape of a wrapper shell, a script, an editor
    or `tail -f`. It is not the service and must never be treated as such.
    """
    proc = subprocess.Popen(
        ["/bin/bash", "-c", "sleep 45  # decoy mentioning runner.ollama_service"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        yield proc
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


# =========================================================================
# Matcher semantics
# =========================================================================


def test_exact_process_name_matches():
    matched, reason = matches_process("ollama", ["ollama", "serve"], OLLAMA_IDENTITIES)
    assert matched is True
    assert "name" in reason.lower()


def test_module_argument_matches_the_local_service():
    matched, _ = matches_process(
        "python",
        ["/usr/bin/python3", "-m", "runner.ollama_service"],
        OLLAMA_IDENTITIES,
    )
    assert matched is True


def test_binary_basename_matches_absolute_path():
    matched, _ = matches_process("ollama", ["/usr/local/bin/ollama", "serve"], OLLAMA_IDENTITIES)
    assert matched is True


def test_wrapper_shell_mentioning_the_service_does_not_match():
    """The core defect: argv contains the marker only inside a longer string."""
    matched, reason = matches_process(
        "bash",
        ["/bin/bash", "-c", "/usr/bin/python3 -m runner.ollama_service"],
        OLLAMA_IDENTITIES,
    )
    assert matched is False, "a wrapper shell must not be identified as the service"


def test_unrelated_process_mentioning_ollama_does_not_match():
    for argv in (
        ["vim", "runner/ollama_service.py"],
        ["tail", "-f", "/var/log/ollama.log"],
        # "ollama" is a whole argument here, but it is search data rather than
        # an executable. Whole-argument equality alone is NOT sufficient; the
        # matcher must consider argument position.
        ["grep", "-r", "ollama", "."],
        ["grep", "-rn", "runner.ollama_service", "."],
        ["curl", "-sS", "http://127.0.0.1:8000/api/demo/stop-ollama"],
        ["/bin/bash", "-l", "-c", 'echo "Processes whose cmdline mentions ollama"'],
        ["pytest", "tests/test_ollama_recovery.py"],
    ):
        matched, _ = matches_process(argv[0].split("/")[-1], argv, OLLAMA_IDENTITIES)
        assert matched is False, f"{argv} must not be identified as the Ollama runtime"


def test_legacy_substring_mode_is_opt_in_only():
    argv = ["/bin/bash", "-c", "python -m runner.ollama_service"]
    assert matches_process("bash", argv, OLLAMA_IDENTITIES, strict=True)[0] is False
    assert matches_process("bash", argv, OLLAMA_IDENTITIES, strict=False)[0] is True


def test_custom_identity_does_not_inherit_ollama_aliases():
    from runner.procmatch import default_identities

    assert default_identities("ollama") == OLLAMA_IDENTITIES
    assert default_identities("redis") == ("redis",)


# =========================================================================
# Live behaviour: detection must not be fooled
# =========================================================================


def test_check_process_ignores_the_decoy_shell(decoy_shell):
    result = check_process("ollama")
    assert decoy_shell.pid not in result["pids"]
    assert result["identities"] == list(OLLAMA_IDENTITIES)
    assert result["strict"] is True


def test_check_process_finds_the_real_service(decoy_shell):
    start_ollama()
    try:
        result = check_process("ollama")
        assert result["is_running"] is True
        assert result["pid_count"] >= 1
        assert decoy_shell.pid not in result["pids"]
        # Every reported PID must justify itself.
        assert all(d.get("match_reason") for d in result["details"])
    finally:
        stop_ollama()


def test_dead_daemon_is_not_reported_as_running_by_a_decoy(decoy_shell):
    """
    The exact live-sandbox failure: with the daemon dead but a decoy alive,
    check_process claimed it was running and the engine produced the wrong
    root cause ("hung / unbound" instead of "terminated").
    """
    stop_ollama()
    assert decoy_shell.poll() is None, "the decoy must still be alive"
    assert check_process("ollama")["is_running"] is False

    from runner.diagnosis import diagnose
    from runner.doctor_runner import doctor_runner

    evidence = doctor_runner.collect_evidence()
    d = diagnose(evidence, "ConnectionRefusedError")
    assert d.hypothesis == "ollama_daemon_terminated"
    assert d.confidence >= 0.85


# =========================================================================
# Live behaviour: the kill list must not include bystanders
# =========================================================================


def test_stop_ollama_does_not_signal_the_decoy_shell(decoy_shell):
    start_ollama()
    out = stop_ollama()

    assert decoy_shell.pid not in out["terminated_pids"], (
        "stop_ollama signalled a process that merely mentioned the service"
    )
    assert decoy_shell.poll() is None, "the decoy shell was killed"
    assert out["port_11434_closed"] is True
    start_ollama()


def test_stop_ollama_still_stops_the_real_service():
    start_ollama()
    assert psutil.pid_exists  # sanity: psutil imported
    out = stop_ollama()
    assert out["port_11434_closed"] is True
    assert out["terminated_pids"], "the real service should have been terminated"
    start_ollama()
