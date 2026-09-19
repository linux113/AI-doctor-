"""
Process-identity regression tests.

These pin the fix for substring process matching, which both misreported a dead
daemon as alive (corrupting root-cause attribution) and put unrelated processes
in `stop_ollama`'s kill list.

A real decoy shell is spawned here on purpose: the defect is only reproducible
with an actual process whose command line *mentions* the service without *being*
it.

Since the Python stand-in (`runner.ollama_service`) was deleted, the only Ollama
identity is the real `ollama` binary. Tests that need a live daemon use
`requires_real_ollama` and skip explicitly when it is absent.
"""

import os
import subprocess
import time

import psutil
import pytest

from runner.diagnostics import check_process
from runner.ollama_runtime import OLLAMA_NOT_INSTALLED
from runner.procmatch import OLLAMA_IDENTITIES, matches_process
from runner.remediation import start_ollama, stop_ollama


@pytest.fixture
def decoy_shell():
    """
    A live process whose argv mentions "ollama" inside a longer string - exactly
    the shape of a wrapper shell, a script, an editor, a grep or `tail -f`.
    It is not the runtime and must never be treated as such.
    """
    if os.name == "nt":
        cmd = [
            os.environ.get("ComSpec", "cmd.exe"),
            "/d",
            "/c",
            "ping 127.0.0.1 -n 46 >nul",
        ]
    else:
        cmd = ["/bin/bash", "-c", "sleep 45  # decoy mentioning ollama serve"]

    proc = subprocess.Popen(
        cmd,
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
# Matcher semantics (pure - no processes, no Ollama required)
# =========================================================================


def test_only_the_real_binary_is_an_identity():
    """The deleted stand-in must not remain a recognised identity."""
    assert OLLAMA_IDENTITIES == ("ollama",)
    assert "runner.ollama_service" not in OLLAMA_IDENTITIES


def test_exact_process_name_matches():
    matched, reason = matches_process("ollama", ["ollama", "serve"], OLLAMA_IDENTITIES)
    assert matched is True
    assert "name" in reason.lower()


def test_the_deleted_module_form_is_no_longer_an_identity():
    """
    `python -m runner.ollama_service` used to be a valid identity because a
    Python HTTP server impersonated Ollama. That module is gone, so this argv
    must NOT match: keeping it would let any Python process claim to be the
    runtime and be signalled by stop_ollama.
    """
    matched, _ = matches_process(
        "python",
        ["/usr/bin/python3", "-m", "runner.ollama_service"],
        OLLAMA_IDENTITIES,
    )
    assert matched is False


def test_binary_basename_matches_absolute_path():
    matched, _ = matches_process("ollama", ["/usr/local/bin/ollama", "serve"], OLLAMA_IDENTITIES)
    assert matched is True


def test_wrapper_shell_mentioning_the_service_does_not_match():
    """The core defect: argv contains the marker only inside a longer string."""
    matched, reason = matches_process(
        "bash",
        ["/bin/bash", "-c", "/usr/local/bin/ollama serve"],
        OLLAMA_IDENTITIES,
    )
    assert matched is False, "a wrapper shell must not be identified as the service"


def test_unrelated_process_mentioning_ollama_does_not_match():
    for argv in (
        ["vim", "/etc/ollama/config"],
        ["tail", "-f", "/var/log/ollama.log"],
        # "ollama" is a whole argument here, but it is search data rather than
        # an executable. Whole-argument equality alone is NOT sufficient; the
        # matcher must consider argument position.
        ["grep", "-r", "ollama", "."],
        ["grep", "-rn", "ollama serve", "."],
        ["curl", "-sS", "http://127.0.0.1:8000/api/demo/stop-ollama"],
        ["curl", "-sS", "http://127.0.0.1:11434/api/tags"],
        ["/bin/bash", "-l", "-c", 'echo "Processes whose cmdline mentions ollama"'],
        ["pytest", "tests/test_ollama_recovery.py"],
        ["journalctl", "-u", "ollama"],
    ):
        matched, _ = matches_process(argv[0].split("/")[-1], argv, OLLAMA_IDENTITIES)
        assert matched is False, f"{argv} must not be identified as the Ollama runtime"


def test_legacy_substring_mode_is_opt_in_only():
    argv = ["/bin/bash", "-c", "ollama serve"]
    assert matches_process("bash", argv, OLLAMA_IDENTITIES, strict=True)[0] is False
    assert matches_process("bash", argv, OLLAMA_IDENTITIES, strict=False)[0] is True


def test_custom_identity_does_not_inherit_ollama_aliases():
    from runner.procmatch import default_identities

    assert default_identities("ollama") == OLLAMA_IDENTITIES
    assert default_identities("redis") == ("redis",)


# =========================================================================
# Live behaviour: detection must not be fooled (no Ollama needed)
# =========================================================================


def test_check_process_ignores_the_decoy_shell(decoy_shell):
    result = check_process("ollama")
    assert decoy_shell.pid not in result["pids"]
    assert result["identities"] == list(OLLAMA_IDENTITIES)
    assert result["strict"] is True


def test_dead_daemon_is_not_reported_as_running_by_a_decoy(decoy_shell, ollama_state):
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

    if ollama_state == OLLAMA_NOT_INSTALLED:
        # Absent runtime outranks the outage hypotheses - that is the point of
        # the runtime probe. Either way, the decoy did not fool the engine into
        # claiming a live daemon.
        assert d.hypothesis == "ollama_not_installed"
    else:
        assert d.hypothesis == "ollama_daemon_terminated"
    assert d.confidence >= 0.85
    assert d.hypothesis != "ollama_process_hung_or_unbound"


def test_stop_ollama_does_not_signal_the_decoy_shell(decoy_shell):
    """
    The kill list must never contain a bystander - with or without a real daemon.
    """
    out = stop_ollama()

    assert decoy_shell.pid not in out["terminated_pids"], (
        "stop_ollama signalled a process that merely mentioned the service"
    )
    assert decoy_shell.poll() is None, "the decoy shell was killed"
    assert out["port_11434_closed"] is True
    assert os.getpid() not in out["terminated_pids"], "stop_ollama must never signal itself"


# =========================================================================
# Live behaviour: requires the real daemon
# =========================================================================


def test_check_process_finds_the_real_service(decoy_shell, requires_real_ollama):
    runtime = requires_real_ollama
    if runtime.health().state == OLLAMA_NOT_INSTALLED:
        pytest.skip("no real Ollama runtime.")
    runtime.start()
    try:
        result = check_process("ollama")
        assert result["is_running"] is True
        assert result["pid_count"] >= 1
        assert decoy_shell.pid not in result["pids"]
        # Every reported PID must justify itself.
        assert all(d.get("match_reason") for d in result["details"])
    finally:
        pass


def test_stop_ollama_still_stops_the_real_service(requires_real_ollama):
    runtime = requires_real_ollama
    assert runtime.start().success, "could not reach a running baseline"

    out = stop_ollama()
    assert out["port_11434_closed"] is True
    assert out["port_closed"] is True
    assert out["terminated_pids"], "the real daemon should have been terminated"
    assert out["success"] is True

    # Restore for any later test.
    runtime.start()
