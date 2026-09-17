# AI Doctor — Security Model & Technical Audit

This document records the security boundary of the autonomous recovery loop and
the findings of the technical audit performed against the request lifecycle, the
deterministic root-cause logic, and that boundary.

Every finding below was **reproduced**, not inferred from reading code, and each
has a regression test that fails if the guardrail is later relaxed.

---

## 1. The security model

Three invariants, in order of importance:

| Invariant | Mechanism | Location |
|---|---|---|
| No arbitrary code execution | No `eval`, `exec`, `compile`, `os.system`, `__import__`, or `shell=True` anywhere in the codebase. The single `subprocess.Popen` uses a fixed argv list built from `sys.executable`. | `runner/remediation.py` |
| Diagnostics cannot mutate state | The diagnostic registry refuses to register any tool with `read_only=False`. | `runner/tool_registry.py` |
| Remediation is allowlisted | A `frozenset` allowlist; `register()` raises `PermissionError` for anything outside it, and `execute()` blocks and audit-logs unlisted actions. | `runner/remediation_registry.py` |

These held up under audit and were not weakened. Everything below is about the
*gaps around* them.

### Verifying the no-exec invariant

```bash
grep -rnE "\b(eval|exec|compile)\s*\(|os\.system|shell\s*=\s*True|__import__|pickle\.loads" \
  --include=*.py --include=*.tsx --include=*.js . | grep -v node_modules | grep -v '\.cursor'
```

The only hits are `re.compile` (regex construction, not code execution) and a
string literal inside `tests/test_remediation_allowlist.py` asserting that
`eval('os.system(bad)')` is **blocked**.

---

## 2. Findings

### F1 — SSRF: retry destination validated by string prefix *(High)*

`retry_request` replays a captured request body, so its destination check is an
exfiltration boundary. It was implemented as:

```python
if not (url.startswith("http://127.0.0.1") or url.startswith("http://localhost") or ...):
```

Prefix matching does not parse a URL. Both of these satisfy the check while
naming an attacker-controlled host:

```
http://127.0.0.1.evil.com/steal     -> host is "127.0.0.1.evil.com"
http://localhost@evil.com/steal     -> userinfo trick; host is "evil.com"
```

**Reproduced:** both were accepted and dialled. They failed only because the
sandbox has no DNS for them — the guard did not stop them.

**Fix:** `runner/security.py::validate_retry_url` parses the URL and enforces
scheme ∈ {http, https}, rejects any userinfo component, and requires `hostname`
to *exactly* equal an entry in `ALLOWED_RETRY_HOSTS`. Subdomains, suffixes and
prefixes of allowed hosts are refused. Rejected destinations are logged by
reason only, never echoed, so a hostile URL cannot be laundered into logs.

**Tests:** `test_ssrf_bypass_attempts_are_rejected` (13 vectors),
`test_legitimate_loopback_destinations_are_allowed`,
`test_retry_request_does_not_leak_the_hostile_url`.

---

### F2 — `stop_ollama` could signal an arbitrary process *(High)*

Two compounding problems:

1. It read `/tmp/ollama.pid` — a **world-writable** path — and immediately
   `os.kill(pid, SIGTERM)`'d whatever integer it found. Any local user could
   pre-seed that file and use the AI Doctor backend as a confused deputy to
   signal a process of their choosing.
2. It selected process-table targets by substring, so it also killed unrelated
   processes (see F3).

**Fix:** `runner/pidfile.py`. A PID is treated as a *hint, never as authority*.
`is_trusted_ollama_pid()` inspects the live process and confirms its identity
before anything is signalled, refuses stale PIDs, refuses PIDs whose identity
cannot be inspected, and refuses to signal the AI Doctor process itself. The
service now writes the file `0600` via `os.open` with an explicit mode (never
briefly world-writable), and the reader warns when it finds insecure
permissions. Refused PIDs are returned in `refused_pids` and audit-logged.

**Tests:** `test_refuses_to_signal_the_ai_doctor_process_itself`,
`test_refuses_a_stale_or_foreign_pid`, `test_refuses_a_malformed_pid_file`,
`test_stop_ollama_refuses_a_tampered_pid_file`,
`test_accepts_the_real_service_pid_file`.

---

### F3 — Process identity decided by substring mention *(High)*

`check_process` matched with:

```python
if process_name.lower() in name.lower() or process_name.lower() in cmdline.lower():
```

Any process whose command line merely *mentions* "ollama" was counted as the
running daemon. Observed live in the sandbox:

```
pid=2116  name='bash'  cmdline='/bin/bash -l -c ... print("Processes whose cmd...'
```

That was a diagnostic shell running a script containing the word "ollama". Two
consequences:

- **Wrong root cause.** With the daemon genuinely dead, `check_process` reported
  it running, so the engine concluded *"process exists but has not bound to port
  11434 or is hanging"* at confidence **0.85** instead of the true *"daemon
  process is terminated"* at **0.90**. Recovery still succeeded only because
  both branches happen to recommend `start_ollama` — the correct outcome was
  luck, not logic.
- **Killing bystanders.** `stop_ollama` used the same substring test to build
  its kill list, so a shell running `curl .../api/demo/stop-ollama` would be
  SIGTERMed by the endpoint it had just called.

**Fix:** `runner/procmatch.py` matches by *identity position*, not by mention.
An identity counts only as the process name, `argv[0]` (or its basename), or the
argument immediately following a `-m` flag.

Note that naive "whole argument" equality is **not** sufficient and was rejected
during the fix: it still matches `grep -r ollama .`, where "ollama" is a whole
argument but is search data rather than an executable. Position is what
disambiguates them.

```
python -m runner.ollama_service            -> MATCH  (-m position)
/usr/local/bin/ollama serve                -> MATCH  (argv[0] basename)
ollama serve                               -> MATCH  (process name)
bash -c "python -m runner.ollama_service"  -> no     (marker inside a longer arg)
grep -r ollama .                           -> no     (marker is search data)
vim runner/ollama_service.py               -> no     (marker is a file operand)
tail -f /var/log/ollama.log                -> no     (marker is a file operand)
```

`strict=False` retains the legacy substring search for callers that genuinely
want a fuzzy lookup; it is never used on a kill path.

**Tests:** `tests/test_process_identity.py` (12), including a live decoy shell
spawned to prove bystanders are neither counted nor killed.

---

### F4 — Remediation registry masked the action's own failure *(Medium-High)*

`RemediationRegistry.execute()` returned `success: True` whenever the callable
did not **raise**, ignoring the verdict in its return value:

```python
result = fn(**kwargs)
return {"success": True, "action": action_name, "result": result}   # result["success"] may be False
```

`start_ollama` returns `{"success": False, ...}` when the daemon spawns but
never binds port 11434. That failure was reported as a successful **FIX**, and
the incident was then blamed on the **VERIFY** stage.

**Reproduced:** inner result `success=False`, registry reported `success=True`.

**Fix:** the registry honours the action's own `success` key when present,
records `FAILED` in the audit log, and propagates the error. Actions that report
no `success` key (e.g. `stop_ollama`) remain successful on a clean return.
`heal_incident` now records which stage actually broke via `failed_stage`, and
the timeline marks `VERIFYING` as *Skipped* rather than implying a service was
checked and found down when the fix never ran.

**Tests:** `test_registry_propagates_inner_failure`,
`test_registry_records_failed_status_in_audit_log`,
`test_registry_treats_actions_without_success_key_as_successful`,
`test_fix_failure_is_attributed_to_the_fix_stage`,
`test_timeline_separates_fix_failure_from_verification`.

---

### F5 — `retry_request` remediation always failed at FIX *(Medium-High)*

`run_remediation_and_verify` invoked the action with no arguments:

```python
remediation_result = self.remediation_registry.execute(remediation_action)
```

For `start_ollama` that is fine. For `retry_request` — which the engine
recommends whenever the infrastructure looks healthy — `url` is required:

```
success: False
error: retry_request() missing 1 required positional argument: 'url'
```

So every "infrastructure is healthy, cause is unknown" incident failed at the
FIX stage with a `TypeError`, and would then have been replayed a second time by
the RETRY step had it succeeded.

**Fix:** the runner detects that the chosen remediation *is* the replay,
supplies the captured request context, and does not issue it twice. Missing
context now fails with an explicit message instead of a `TypeError`.

**Tests:** `test_retry_remediation_replays_the_captured_request`,
`test_retry_remediation_does_not_replay_twice`,
`test_retry_remediation_without_context_fails_cleanly`.

---

### F6 — Hardcoded confidence of 0.98 on every branch *(Medium)*

`diagnose_root_cause` returned `"confidence": 0.98` for all four branches,
including *"Unknown application-level error"*. A constant is not a confidence
score; it asserted near-certainty about precisely the case where the engine has
no idea what is wrong.

**Fix:** `runner/diagnosis.py` computes confidence from how many of the three
independent probes (socket, process table, HTTP API) corroborate the chosen
hypothesis and how many contradict it:

| Evidence | Hypothesis | Action | Confidence | Consistent |
|---|---|---|---|---|
| port closed, no process, API down | `ollama_daemon_terminated` | `start_ollama` | **0.90** | yes |
| process alive, port closed | `ollama_process_hung_or_unbound` | `start_ollama` | **0.85** | yes |
| port open, API unhealthy | `ollama_api_unhealthy` | `start_ollama` | **0.70** | yes |
| port closed **but** API answered | `contradictory_probes` | `start_ollama` | **0.28** | **no** |
| everything healthy | `unexplained_application_error` | `retry_request` | **0.30** | yes |

The contradictory case is checked **first**. A closed socket and a successful
HTTP response through that same socket cannot both be true, so at least one
probe is lying; previously that combination was absorbed by the "process alive
but unbound" branch and reported at high confidence.

Each diagnosis also carries `corroborating_probes`, `contradicting_probes`,
`evidence_consistent` and `notes` so a low score is explainable.

**Tests:** `test_confidence_is_not_a_constant`,
`test_unexplained_failure_gets_low_confidence`,
`test_fully_corroborated_outage_gets_high_confidence`,
`test_impossible_probe_combination_is_caught_before_any_hypothesis`,
`test_healthy_api_with_blind_process_probe_is_flagged`,
`test_confidence_is_monotonic_in_corroboration`.

---

### F7 — Duplicated root-cause logic had already drifted *(Medium)*

The decision table existed twice: in `runner/doctor_runner.py` (the live path)
and in `agent/strands_agent.py` (`StrandsAgentPlaceholder`, which **nothing
imported** — confirmed by grep). The copies differed in branch order, wording
and confidence values, so a fix to one silently did not apply to the other.

**Fix:** `runner/diagnosis.py` is now the single source of truth and both
delegate to it. `agent/` imports it lazily so the agent package remains
importable without the runner's native dependencies. This is also the intended
Phase 2 seam: swapping the deterministic engine for Amazon Bedrock is now one
call site that must return the same `Diagnosis` shape, with the deterministic
path retained as the fallback when the model is unreachable or returns an action
outside the allowlist.

**Test:** `test_runner_and_agent_root_cause_logic_no_longer_drift` asserts the
two agree exactly across all five evidence patterns.

---

### F8 — CORS wildcard combined with credentials *(Medium)*

```python
allow_origins=["*"], allow_credentials=True
```

Browsers reject this combination outright, and it is the wrong default for an
API that spawns and signals OS processes. The dashboard reaches the backend
through Next.js rewrites, so it is same-origin from the browser's perspective
and needs no permissive CORS at all.

**Fix:** origins come from `AIDOCTOR_CORS_ORIGINS` (default `*`), and
credentials are enabled **only** when the wildcard is absent — making the unsafe
pairing unrepresentable.

**Tests:** `test_cors_never_combines_wildcard_origin_with_credentials`,
`test_explicit_cors_origins_enable_credentials`.

---

### F9 — Destructive endpoints were unauthenticated *(Medium)*

`/api/heal`, `/api/demo/stop-ollama`, `/api/demo/start-ollama` and
`/api/demo/simulate-incident` spawn or signal OS processes and required no
credentials.

**Fix:** an opt-in bearer-token gate (`AIDOCTOR_API_TOKEN`) applied via
`Depends` to those four routes. It is **disabled when the variable is unset**,
so local development and the existing test suite behave identically, while any
real deployment gets an enforced boundary. Comparison is constant-time
(`secrets.compare_digest`) so the token cannot be recovered character by
character. Read-only endpoints stay open.

`frontend/src/middleware.ts` injects the token **server-side** into the proxy,
so the browser never receives, stores or transmits it. (Next.js `rewrites()`
cannot attach request headers — a long-standing open limitation — which is why
this lives in middleware rather than `next.config.js`.)

`/api/system-status` now reports the effective posture (`token_gate_enabled`,
`cors_origins`, `cors_allow_credentials`, `remediation_allowlist`) without ever
exposing a secret value.

**Tests:** `test_token_gate_is_disabled_by_default`,
`test_token_gate_enforces_on_process_controlling_endpoints`,
`test_system_status_reports_security_posture_without_leaking_secrets`.

---

### F10 — Credential redaction covered only five patterns *(Medium)*

Redaction missed AWS access key IDs, Anthropic/OpenAI project keys, GitHub PATs,
Slack and Google tokens, Stripe keys, JWTs, PEM private key blocks,
connection-string passwords, and `x-api-key` / `Authorization` / `token`
headers. Since diagnostics feed an evidence bundle that may later be sent to
Bedrock or stored in S3, this is the boundary that keeps secrets out of an LLM
prompt.

**Fix:** 20 patterns, ordered most-specific-first so a generic rule cannot clip
a structured token down to a recognisable fragment (e.g. reducing a PEM block to
its header line, which still discloses the key type).

Verified against 16 secret classes, plus a false-positive check asserting that
the operational log lines the app actually produces are left **byte-identical**
— over-redaction would destroy the evidence the agent exists to collect.

**Tests:** `test_secret_is_redacted` (16 parametrised),
`test_operational_log_lines_are_not_over_redacted` (6 parametrised).

---

### F11 — Deprecated naive timestamps *(Low)*

17 call sites used `datetime.utcnow()`, deprecated since Python 3.12. Worse,
`isoformat()` omits the fractional part when microseconds happen to be exactly
zero, and `Incident.created_at` is a DynamoDB **RANGE** key sorted
lexicographically — so sort order was not stable.

**Fix:** `runner/timeutil.py::now_iso()` uses a timezone-aware clock and a
fixed-width format, always emitting six fractional digits.

**Test:** `test_timestamps_are_fixed_width_utc_with_z_suffix`.

---

### F12 — Broken dependency metadata and test collection *(Low, but blocking)*

`pytest tests/` failed at **collection** in a clean environment:

```
tests/test_ai_doctor.py -> ModuleNotFoundError: No module named 'deepeval'
```

`requirements.txt` installed `deepteam` but not `deepeval`, which
`ai_doctor/guardrails.py` imports directly, and omitted `psutil`, `pytest` and
`httpx` entirely — the packages the *primary* project and its tests need.
`pyproject.toml` declared the red-teaming packages as hard dependencies while
omitting everything the recovery agent imports.

This also explains the "25/25 tests pass" claim: it is true only with an
undocumented extra dependency installed. The repository in fact contains **two
unrelated projects** — the autonomous recovery agent (`runner/`, `backend/`,
`frontend/`, `agent/`) and a medical-triage assistant (`ai_doctor/`,
`deepteam_config.yaml`, `example_redteam.py`) — and their metadata described
only the latter.

**Fix:**
- `requirements-core.txt` — minimal, complete install for the recovery agent.
- `requirements.txt` — now `-r requirements-core.txt` plus the red-team extra,
  with `deepeval` listed explicitly.
- `pyproject.toml` — core dependencies corrected; red-team and AWS moved to
  optional extras (`pip install -e ".[redteam]"`, `".[aws]"`).
- `tests/test_ai_doctor.py` — `pytest.importorskip("deepeval")` so the module
  **skips** instead of aborting collection of the 18 unrelated core tests.
- `package.json` / `pyproject.toml` descriptions now describe the actual
  primary project.

---

### F13 — Key mismatches between the model and the runner *(Low)*

Two silent `None`s caused by reading the wrong dictionary key:

- `heal_incident` returned `incident_data.get("id")`, but the field is
  `incident_id` — so every heal result reported a null incident id.
- It read `incident_data.get("error")`, but the field is `detected_error` — so
  every `DETECTED` timeline entry read *"Failure detected: Unknown error"*,
  discarding the one detail an on-call engineer reads first.

Both fixed, with a fallback to the alternate key for ad-hoc callers.

**Tests:** `test_heal_incident_returns_the_incident_id`,
`test_heal_incident_surfaces_the_detected_error`.

---

## 3. Known limitations (deliberately not fixed)

Recorded so they are decisions rather than oversights.

- **In-memory state.** `incident_repo` and the log buffer are module-level
  globals. Under `uvicorn --workers >1` each worker gets its own store, so
  incidents appear and disappear depending on which worker answers. Run a single
  worker until the DynamoDB repository lands (Phase 2 goal 3).
- **`/api/heal` blocks.** Evidence collection, a 5 s start poll and a 4.5 s
  verification poll run synchronously in the request. Acceptable for a demo;
  needs to become an async job (Step Functions in the AWS design) for real use.
- **`stop_ollama` will still terminate a genuine upstream `ollama` daemon**
  reached by exact process-name match. That is the documented intent of the
  chaos-testing remediation, but it is worth knowing on a workstation that runs
  Ollama for other purposes.
- **The mock Ollama runtime binds `0.0.0.0:11434` with no authentication.** This
  is required for the sandbox preview and is a stand-in for the real daemon, but
  it should bind loopback in any environment that is not ephemeral.
- **Redaction is denylist-based.** Regex redaction reduces leakage; it cannot
  prove absence. For Phase 2, pair it with CloudWatch Logs data-protection
  policies and keep secrets in Secrets Manager rather than in log lines.

---

## 4. Configuration reference

| Variable | Default | Effect |
|---|---|---|
| `AIDOCTOR_API_TOKEN` | *(unset)* | Enables the bearer-token gate on the four process-controlling routes. Disabled when unset. |
| `AIDOCTOR_CORS_ORIGINS` | `*` | Comma-separated allowed origins. Credentials are enabled only when this is not `*`. |
| `AIDOCTOR_BACKEND_ORIGIN` | `http://127.0.0.1:8000` | Backend the Next.js proxy targets (used by both `next.config.js` and `src/middleware.ts`). |
| `AIDOCTOR_OLLAMA_PID_FILE` | `/tmp/ollama.pid` | PID file path. Point at a non-world-writable directory such as `$XDG_RUNTIME_DIR` in production. |

Set `AIDOCTOR_API_TOKEN` on **both** the backend and the frontend; the frontend
injects it server-side into the proxy so the browser never sees it.

---

## 5. Test summary

```
102 passed, 1 skipped
```

| Suite | Tests | Scope |
|---|---|---|
| `test_security_hardening.py` | 72 | F1, F2, F4, F5, F6, F7, F8, F9, F10, F11, F13 |
| `test_process_identity.py` | 12 | F3, incl. a live decoy shell |
| `test_api_endpoints.py` | 3 | Full DETECT→DIAGNOSE→FIX→VERIFY→RETRY lifecycle |
| `test_remediation_allowlist.py` | 5 | Allowlist enforcement and audit trail |
| `test_ollama_detection.py`, `test_ollama_recovery.py`, `test_port_detection.py` | 5 | Probes and daemon lifecycle |
| `test_failure_detection.py`, `test_retry.py`, `test_verification.py` | 5 | Failure injection, replay, verification |
| `test_ai_doctor.py` | 7 *(skipped)* | Optional medical-triage component; skips without `deepeval` |

84 tests were added by this audit. All 18 pre-existing core tests still pass
unchanged, and their assertions were not weakened to accommodate any fix.
