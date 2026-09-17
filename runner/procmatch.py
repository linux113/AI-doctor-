"""
Process identity matching for AI Doctor.

The defect this closes
----------------------
`check_process()` originally identified the Ollama daemon by *substring* search
over the process name and the joined command line:

    if process_name.lower() in name.lower() or process_name.lower() in cmdline.lower()

Any process whose command line merely *mentions* the word "ollama" was counted
as the running daemon. Observed live in the sandbox:

    pid=2116  name='bash'  cmdline='/bin/bash -l -c ... print("Processes whose cmd...'

That was a diagnostic shell running a script containing the word "ollama". It
caused two distinct failures:

1. **Wrong root cause.** With the daemon genuinely dead, `check_process` still
   reported it running, so the engine concluded "process exists but has not
   bound to port 11434 or is hanging" (confidence 0.85) instead of the true
   "daemon process is terminated" (0.90). Recovery still worked only because
   both branches happen to recommend `start_ollama`.

2. **Killing unrelated processes.** `stop_ollama` used the same substring test
   to build its kill list. A shell running `curl .../api/demo/stop-ollama`, an
   editor with the file open, or `tail -f ollama.log` would all be SIGTERMed by
   the very endpoint they invoked.

Matching rule
-------------
An identity counts only when it appears in a position that *identifies what the
process is*, never in a position that is merely data it happens to be carrying:

  * the process name (psutil `name()`), or
  * `argv[0]`, or the basename of `argv[0]` (the executable path), or
  * the argument immediately following a `-m` flag (a Python module invocation,
    which is how this project starts its local runtime).

Naive "whole argument" equality is NOT sufficient and was rejected: it still
matches `grep -r ollama .`, where "ollama" is a whole argument but is search
data, not an executable. Position is what disambiguates the two.

Consequences, all intended:
    python -m runner.ollama_service          -> MATCH  (-m position)
    /usr/local/bin/ollama serve              -> MATCH  (argv[0] basename)
    ollama serve                             -> MATCH  (process name)
    bash -c "python -m runner.ollama_service"-> no     (marker is inside a longer arg)
    grep -r ollama .                         -> no     (marker is search data)
    vim runner/ollama_service.py             -> no     (marker is a file operand)
    tail -f /var/log/ollama.log              -> no     (marker is a file operand)

A runtime started as a plain script (`python runner/ollama_service.py`) is not
matched, because matching the first operand would re-open the `vim`/`grep`
holes. This project always launches with `-m`, so nothing is lost.
"""

import os
from typing import List, Optional, Sequence, Tuple

# Identities that legitimately refer to the Ollama runtime:
#   "ollama"                -> the upstream daemon binary (name or argv[0] basename)
#   "runner.ollama_service" -> this project's local runtime, started with
#                              `python -m runner.ollama_service`
OLLAMA_IDENTITIES: Tuple[str, ...] = ("ollama", "runner.ollama_service")

# Flag after which the next argument is a Python module name.
_MODULE_FLAG = "-m"


def default_identities(process_name: str) -> Tuple[str, ...]:
    """
    Identities to match for a requested process name.

    Asking for "ollama" means "the Ollama runtime", which in this project can
    be either the upstream binary or the local `runner.ollama_service` module.
    Any other name matches only itself.
    """
    return OLLAMA_IDENTITIES if process_name.strip().lower() == "ollama" else (process_name,)


def _identity_positions(name: Optional[str], cmdline: Sequence[str]) -> List[Tuple[str, str]]:
    """
    Returns (value, position) pairs for every argument slot that asserts what
    the process *is*.
    """
    found: List[Tuple[str, str]] = []

    cleaned = [a for a in (cmdline or ()) if isinstance(a, str) and a]

    if name and name.strip():
        found.append((name.strip().lower(), "process name"))

    if cleaned:
        argv0 = cleaned[0]
        found.append((argv0.lower(), "argv[0]"))
        base = os.path.basename(argv0).lower()
        if base:
            found.append((base, "argv[0] basename"))

        for i, arg in enumerate(cleaned[:-1]):
            if arg == _MODULE_FLAG:
                found.append((cleaned[i + 1].lower(), "python -m module"))

    return found


def matches_process(
    name: Optional[str],
    cmdline: Optional[Sequence[str]],
    identities: Sequence[str],
    strict: bool = True,
) -> Tuple[bool, str]:
    """
    Decides whether a process is one of `identities`.

    Returns (matched, reason). With strict=False the legacy substring behaviour
    is restored for callers that genuinely want a fuzzy search; it is never used
    on a kill path.
    """
    targets = tuple(t.strip().lower() for t in identities if t and t.strip())
    if not targets:
        return False, "No identities supplied."

    if not strict:
        lname = (name or "").strip().lower()
        joined = " ".join(a for a in (cmdline or ()) if isinstance(a, str)).lower()
        if any(t in lname or t in joined for t in targets):
            return True, "Legacy substring match (strict=False)."
        return False, "No substring match."

    for value, position in _identity_positions(name, cmdline or ()):
        if value in targets:
            return True, f"Identity '{value}' found in {position}."

    return False, "No executable-name or module-position match."
