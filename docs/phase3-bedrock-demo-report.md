# Phase 3 report — making the real Bedrock path demo-ready

**Branch:** `arena/01a0ae32-ai-doctor` · **PR:** [#2](https://github.com/linux113/AI-doctor-/pull/2) · **Date:** 2026-09-17

**Commits this phase:** `decfba7`, `32ccab3`, `ce0463e`, `db8a3ec`, `e431c72`, `3ebabab`, `7e43722`

---

## A. The headline, stated plainly

**No real Amazon Bedrock request has been made.** This machine has no AWS
credentials, so the live path has never been exercised end to end against the
service. Everything below that claims verification claims verification of
*behaviour around* the call — classification, redaction, gating, labelling — not
of the call itself.

**No real Ollama runtime exists on this machine either.** There is no `ollama`
executable on `PATH` or in any standard location, so recovery has never been
verified against a real daemon. No stand-in server was substituted, and the
deleted Python Ollama fake was not reintroduced.

What *has* been verified is the thing that decides whether the first live demo can
be trusted: that the system cannot claim a model answered when one did not, cannot
claim a recovery it did not verify, cannot send a credential to Bedrock, and cannot
execute anything a model recommends unless the allowlist permits it.

---

## B. Was a real Bedrock request made?

**No.** Proof, not assertion:

```
$ env | grep -c '^AWS'
0
```

`/api/system-status` reports the two facts separately, which is the whole point of
separating them:

```json
"agent": {
  "agent_mode": "bedrock",
  "mode_uses_llm": true,        // what the configuration asks for
  "llm_operational": false,     // whether it can actually be used
  "credential_sources": [],
  "sdk_available": true,
  "strands_sdk_version": "1.56.0",
  "boto3_version": "1.43.96",
  "model_id": "anthropic.claude-3-5-haiku-20241022-v1:0",
  "aws_region": "us-east-1"
}
```

The live suite skips rather than runs, and says why:

```
SKIPPED tests/test_bedrock_live.py:205: live Bedrock call not requested: set
AI_DOCTOR_RUN_LIVE_BEDROCK=1 (this test makes a real, billable AWS call)
SKIPPED tests/test_bedrock_live.py:220: (same)
SKIPPED tests/test_bedrock_live.py:277: (same)
```

## C. Was real Ollama available?

**No — `NOT_INSTALLED`, and it is reported as absence, never as an outage.** The
detection path states it explicitly:

> `ConnectionRefusedError: ... The Ollama runtime is NOT INSTALLED on this machine
> (no executable was found on PATH or in any standard location), so nothing can be
> listening on port 11434. This is an absent runtime, not an outage.`

13 tests skip on this precondition. None of them is satisfied by a substitute.

---

## D. The actual end-to-end result

Driven through the **running API** (uvicorn on :8000, `AI_DOCTOR_AGENT_MODE=bedrock`,
no credentials, no Ollama), not through a unit-test harness:

```
POST /api/demo/simulate-incident   → incident inc-eeccf5ba, runtime_state OLLAMA_NOT_INSTALLED
POST /api/heal                     → FAILED
GET  /api/incidents/inc-eeccf5ba   →
```

| Field | Value | Why it is the honest value |
|---|---|---|
| `status` | `FAILED` | remediation could not start an absent runtime |
| `agent_mode` | `deterministic` | the rule engine is what actually answered |
| `agent_status` | `FALLBACK_DETERMINISTIC` | Bedrock was requested and could not be used |
| `diagnosis_outcome` | `DIAGNOSED` | a root cause *was* reached — by the offline engine |
| `bedrock_invoked` | `false` | no request reached Bedrock |
| `used_llm` | `false` | no model produced this diagnosis |
| `model_id` / `aws_region` | `null` / `null` | nothing to report; not fabricated |
| `bedrock_request_id` | `null` | only a real round trip can produce one |
| `input/output/total_tokens` | `null` ×3 | recorded as null, never as 0 |
| `bedrock_failure.failure_kind` | `NO_CREDENTIALS` | machine-readable, dashboard-branchable |
| `bedrock_failure.error_class` | `NoCredentialsError` | the real botocore class |
| `runtime_state` | `OLLAMA_NOT_INSTALLED` | absence, not `OLLAMA_NOT_RUNNING` |
| `requires_human` | `true` | no allowlisted action can install software |
| `resolved_at` | `null` | nothing was recovered |
| `final_result` | `Recovery Failed` | |

`agent_note`, verbatim:

> Amazon Bedrock was requested but could not be used [NO_CREDENTIALS:NoCredentialsError].
> This diagnosis came from the offline deterministic rule engine in
> runner/diagnosis.py, not from a model.

Timeline, as persisted and returned by the API:

```
DETECTED           → DETECTED
INVESTIGATING      → EVIDENCE_COLLECTED
ROOT CAUSE FOUND   → AI_DIAGNOSIS
POLICY CHECK       → POLICY_CHECK
REMEDIATION        → REMEDIATION_STARTED
VERIFYING          → VERIFICATION
FAILED             → FAILED
```

No `RETRY` entry: nothing was replayed, and a stage that did not happen must not
appear. No `RECOVERED` entry, no "Port 11434 restored", no "HTTP 200 replayed".

**Interpretation:** the pipeline is correct and honest on the failure path. The
success path — real Bedrock → structured `DiagnosisResult` → policy →
`start_ollama` → real verify → retry → HTTP 200 — remains **unverified end to
end** and cannot be verified here.

---

## E. Defects found and fixed

Each was found by writing the test the requirement asked for against real shapes,
not by reading code. Every one is reproducible from the commit that fixes it.

| # | Defect | Why it mattered | Fix |
|---|---|---|---|
| E1 | `ResourceNotFoundException` — a **documented** `Converse` error (404) — fell through to `UNKNOWN_AWS_ERROR` | The single most likely live-demo misconfiguration (typo'd model id, model not enabled in region) reported as an unclassifiable error | Mapped to `INVALID_MODEL`; message names `AI_DOCTOR_BEDROCK_MODEL_ID` |
| E2 | `ModelNotReadyException` (429, model not serving yet) was classified `TIMEOUT` | Would have told the operator to raise the request timeout — the one thing that cannot help | Mapped to `SERVICE_UNAVAILABLE`; message says retry after backoff |
| E3 | A Strands wrapper **erased the AWS error code**. `ThrottlingException` surfaced as `ModelThrottledException` with `aws_error_code=None` | An incident that cannot be cross-referenced against CloudTrail; violated "do not collapse ClientError codes" | `aws_error_code()` now walks the exception chain, bounded at 8 links, cycle-safe |
| E4 | Chain-walking created a new risk: a `StructuredOutputException` with an AWS-looking cause could be relabelled an AWS validation error | Would report an outage where a model reply actually arrived | Strands wrapper types now take precedence over chained codes; regression test added |
| E5 | **Credentials inside serialized JSON survived redaction.** Every key/value rule required the key name to be followed directly by `:` or `=`, so `"password": "hunter2"` — the shape a captured request body, environment dump or log line actually has — was never redacted | Secrets would have been sent to Bedrock | All eight key/value rules tolerate an optional closing quote before the separator; still idempotent, prose and counters still survive |
| E6 | **A nested exception leaked verbatim.** `sanitize_deep` returned any non-primitive untouched, documented on the assumption that the only such values were ints, bools, None and floats | An exception from a failed HTTP call embeds the credentials it was given; it reached the model when the evidence bundle was serialized | Scalars keep their type; every other object becomes redacted text. An unrenderable object becomes `[REDACTED_UNRENDERABLE_OBJECT]` rather than passing through |
| E7 | **Absent token usage was recorded as `0/0/0`**, not null | Strands accumulates onto a zero-initialised counter, so "not provided" and "billed nothing" were indistinguishable. Requirement 5 says record null rather than fabricate | `_token_count_or_none()`: zero is treated as absent, per field |
| E8 | **`stage_code` was lost at the API.** The runner emitted codes correctly; `backend/main.py` rebuilds `TimelineEvent` in four places and each dropped it | `GET /api/incidents/{id}` returned a timeline no consumer could classify | Filled on the model via a validator, so no call site can forget; explicit codes still preserved |
| E9 | `delete_everything` was refused only by the generic not-permitted branch | The audit trail read "Refused non-permitted model recommendation" for a destructive request — indistinguishable from a typo | Destructive vocabulary added to `FORBIDDEN_ACTION_TOKENS`; both requirement-8 strings now refuse as `forbidden_action` |
| E10 | Four dashboard claims were not earned (see §H) | The dashboard is what a demo audience reads | All four now read backend fields |

E5 and E6 are the serious ones: both were paths by which a real credential could
have reached Amazon Bedrock.

---

## F. Failure classification (requirement 3)

Thirteen stable kinds, published as `FAILURE_KINDS`:

`NO_CREDENTIALS` · `PARTIAL_CREDENTIALS` · `ACCESS_DENIED` · `INVALID_MODEL` ·
`VALIDATION_ERROR` · `THROTTLED` · `TIMEOUT` · `NETWORK_UNREACHABLE` ·
`SERVICE_UNAVAILABLE` · `CONTEXT_OVERFLOW` · `SCHEMA_REFUSED` · `SDK_MISSING` ·
`UNKNOWN_AWS_ERROR`

Classification order is deliberate: configuration errors → Strands wrapper types →
AWS service code (through the chain) → botocore exception class → `UNKNOWN`. The
original AWS code is preserved separately in every case, so nothing is collapsed.

**All nine documented `Converse` errors were verified against the service model
shipped with the installed botocore** (`bedrock-runtime/*/service-2.json.gz`)
rather than from memory, and each is mapped:

| Code | HTTP | Kind |
|---|---|---|
| `AccessDeniedException` | 403 | `ACCESS_DENIED` |
| `ValidationException` | 400 | `VALIDATION_ERROR` (→ `INVALID_MODEL` when the message names the model identifier) |
| `ResourceNotFoundException` | 404 | `INVALID_MODEL` |
| `ModelTimeoutException` | 408 | `TIMEOUT` |
| `ModelErrorException` | 424 | `SERVICE_UNAVAILABLE` |
| `ModelNotReadyException` | 429 | `SERVICE_UNAVAILABLE` |
| `ThrottlingException` | 429 | `THROTTLED` |
| `InternalServerException` | 500 | `SERVICE_UNAVAILABLE` |
| `ServiceUnavailableException` | 503 | `SERVICE_UNAVAILABLE` |

`ModelAccessDeniedException` was dropped from the test matrix after this check: it
is **not** a documented Bedrock error, and inventing it would have been exactly the
kind of guess the phase forbids.

An unrecognised future code is named, not swallowed — `failure_kind=UNKNOWN_AWS_ERROR`
with `aws_error_code` carrying the original string and the message showing it.

## G. Two statuses, because one field was answering two questions

`agent_status` was overloaded: it had to say both whether Bedrock was reached and
what the pipeline decided. A schema refusal reached Bedrock and produced no
diagnosis; a fallback produced a diagnosis without reaching Bedrock. Neither fits
one field.

- **`agent_status`** — the **round trip**: `BEDROCK_SUCCESS`, `BEDROCK_SCHEMA_REFUSED`,
  `BEDROCK_UNAVAILABLE`, `FALLBACK_DETERMINISTIC`, `DETERMINISTIC`
- **`diagnosis_outcome`** — the **decision**: `DIAGNOSED`, `REQUIRES_HUMAN`, `FAILED`
- **`bedrock_invoked`** — true only when a real request reached Bedrock and answered
- **`used_llm`** — true only when a model produced the *validated* diagnosis. A schema
  refusal does not count: Bedrock answered, but nothing usable came back

All four are propagated to the incident record and the API (`_apply_agent_record`,
`heal_incident`), because a dashboard cannot check a claim it has no field for.

## H. Dashboard claims (requirement 11)

Four were unearned:

1. The heal toast said *"original request retried successfully"* whenever the
   incident resolved. `RESOLVED` only means the service came back — the replay can
   have failed, or nothing may have been captured. Now built from `retry_result`.
2. The engine label keyed off `agent_mode`, so a Bedrock-unavailable incident still
   read *"AWS Strands + Amazon Bedrock (model)"*. Now gated on `used_llm`, with
   distinct wording for "produced no diagnosis" and "returned no usable diagnosis".
3. The footer banner said *"AWS Strands & Bedrock Ready"* unconditionally — false on
   any machine without the SDK or credentials — and still described Phase 2 as
   future work. Now derived from `/api/system-status`.
4. The DynamoDB banner implied a table exists, which requirement 13 forbids. Now
   states that nothing is deployed.

`tests/test_dashboard_honesty.py` audits the dashboard source with comments
stripped. **Verified non-vacuous**: seven of its assertions fail against the
pre-fix `page.tsx` (`git show db8a3ec:...`) and none fail now.

## I. Three separated suites (requirement 10)

| Suite | File | AWS | Ollama | In CI |
|---|---|---|---|---|
| **A** Offline deterministic | `tests/test_e2e_offline_deterministic.py` (18) | none | none | yes |
| **B** Bedrock contract | `tests/test_bedrock_contract.py` (53) | real `Agent` + real `BedrockModel`; only `client.converse` answered locally | none | yes |
| **C** Live AWS | `tests/test_bedrock_live.py` (7; 3 skip) | **real, billable** | not required | opt-in only |

**Suite C fails rather than skips once opted in.** With `AI_DOCTOR_RUN_LIVE_BEDROCK=1`
set and no credentials, the run exits **1** with:

```
Failed: AI_DOCTOR_RUN_LIVE_BEDROCK=1 was set, so a real Bedrock call was requested,
but it cannot be made:
  - no AWS credential source was found in the default chain (environment, shared
    config, IAM role, IMDS) - a live Bedrock call cannot authenticate
A live test that skips here would be indistinguishable from one that never ran,
which is how an unverified integration gets reported as tested.
```

Without the opt-in it exits **0** with three skips. A skipped live test and a
never-run live test look identical in a report; that ambiguity is how "tested
against real Bedrock" gets claimed without ever having happened.

Suite C also cannot fake the transport: it does not import `_fake_bedrock` at all,
an AST-based test reads the module's own source to keep it that way (a text search
would be tripped by the docstring, which discusses the fake by name), and the live
path asserts the client is a genuine `botocore.client.BedrockRuntime` whose
`converse` is botocore's own method, pointed at
`https://bedrock-runtime.{region}.amazonaws.com`.

## J. Prompt injection and tool invention (requirement 7)

Injected text stays evidence. Beyond the existing fences, the new assertion is the
second half of the requirement: **the model cannot invent a tool.**

Simulated by making the transport answer with an unregistered tool name. Observed
behaviour — the Strands registry refused it four times
(`tool not found in registry`), and:

- the invented name was **never offered**: `toolConfig` contained exactly
  `check_ollama, check_port, check_process, get_recent_logs, health_check` +
  `DiagnosisResult`, with **zero** intersection with `REMEDIATION_ALLOWLIST`
- `structured=None`, `used_llm=False`, `bedrock_status=BEDROCK_SCHEMA_REFUSED`,
  `status=REQUIRES_HUMAN`, recommended remediation `none`
- the attempt is still recorded in `telemetry.tool_calls` — honest about what the
  model *asked for*, never implying it ran

`start_ollama` is deliberately in the invented-name list: it is a real allowlisted
remediation, but the model must recommend it through the policy gate, never call it.

## K. Policy gate (requirement 8)

Both requirement strings refused **before execution**, at all three layers —
because a gate in only one of them is a gate that can be routed around:

| Layer | `arbitrary_shell_command` | `delete_everything` |
|---|---|---|
| Agent policy | `allowed=False`, `violation=forbidden_action` | same |
| Remediation registry | `is_allowed=False`; `register()` **raises**; `execute()` returns `success=False`, `BLOCKED` | same |
| Runner | `action_taken="none"`, `status=FAILED`, nothing executed | same |

Verified end to end through the runner: a model recommending either action ends
`FAILED` with no action taken, and the refusal is its own visible `POLICY_CHECK`
timeline stage naming the violation.

## L. Redaction (requirement 6)

All six named strings are asserted individually **and** in eight container shapes
(bare string, nested dict, list, dict key, exception message, exception inside a
dict, header value, deep nesting). The end-to-end test embeds all six across nested
evidence, headers, logs, an environment dump and an exception object, runs the real
agent stack, and searches the exact payload that would have been transmitted —
system prompt, user prompt, message history and tool config each checked separately
so a failure names the leak.

`credential_source_hint()` — which feeds `/api/system-status` — is asserted to
report only source **names** with distinctive credential values set in the
environment: no key, no secret, no session token, no prefix of either.

## M. Test results

```
647 passed, 16 skipped, 0 failed        (pytest tests/ -q -p no:randomly)
```

The 16 skips, all environmental, none hiding a failure:

- **13** — require a real Ollama runtime; none substituted
- **3** — require `AI_DOCTOR_RUN_LIVE_BEDROCK=1`; a real billable call

Phase 3 test growth:

| File | Before | After |
|---|---|---|
| `test_e2e_offline_deterministic.py` | — | **18** (new) |
| `test_dashboard_honesty.py` | — | **16** (new) |
| `test_timeline_stage_vocabulary.py` | — | **15** (new) |
| `test_bedrock_live.py` | 6 | 7 |
| `test_agent_prompt_injection.py` | 58 | 66 |
| `test_agent_policy.py` | 58 | 62 |
| `test_agent_modes.py` | 43 | 57 |
| `test_bedrock_contract.py` | 47 | 53 |
| `test_agent_redaction.py` | 10 | 19 |
| `test_agent_schemas.py` | 58 | 58 |

Environment: Python 3.11.2, strands-agents 1.56.0, boto3/botocore 1.43.96,
pydantic 2.13.5, fastapi 0.141.1.

## N. Files changed

21 files, +2784 / −287 from the Phase 2 report commit.

**Product code** — `agent/strands_agent.py` (taxonomy, status split, chain walk,
token nulls), `agent/diagnosis_agent.py` (two contracts, provenance),
`agent/policy.py` (destructive vocabulary), `agent/schemas.py` (telemetry fields),
`runner/redaction.py` (E5, E6), `runner/doctor_runner.py` (timeline codes,
POLICY_CHECK, RETRY, provenance), **`runner/timeline.py` (new** — neutral home for
the vocabulary; `backend.models` and `runner.doctor_runner` both import it and
neither may import the other**)**, `runner/diagnosis.py` (untouched this phase),
`backend/models.py` (`stage_code` validator, provenance fields),
`backend/main.py` (`_apply_agent_record`), `frontend/src/app/page.tsx` (§H).

**Tests** — 3 new files, 6 extended, `tests/_fake_bedrock.py` gained a `tool_name`
parameter so a test can simulate a model that invents a tool. It still replaces
only `client.converse`.

## O. Remaining blockers

1. **AWS credentials — the only hard blocker for the demo.** Nothing can be
   verified against the real service without them. Everything else on this list is
   a consequence.
2. **Model access for the configured region.** `anthropic.claude-3-5-haiku-20241022-v1:0`
   must be enabled in the account for `us-east-1`, or the call returns
   `AccessDeniedException` / `ResourceNotFoundException` — both now classified and
   actionable, but both still block the demo.
3. **A real Ollama installation.** Without it the loop ends `FAILED` at the FIX
   stage, so `REMEDIATION_STARTED → VERIFICATION → RETRY → RECOVERED` and the
   HTTP 200 replay cannot be demonstrated at all. `NOT_INSTALLED` is correctly
   reported, but it is not a recovery demo.
4. **The success path is untested end to end.** Suite B proves request
   construction, telemetry capture, tool gating and redaction against the real SDK;
   only a real call can prove the model returns a schema-valid `DiagnosisResult`
   and that `bedrock_request_id` and token counts arrive as expected.

## P. How to run the live demo

### Prerequisites

```bash
pip install -r requirements-aws.txt          # strands-agents + boto3
curl -fsSL https://ollama.com/install.sh | sh   # a REAL Ollama; no stand-in exists
ollama pull llama3.2                          # or any model, so the runtime can serve
```

The principal needs `bedrock:InvokeModelWithResponseStream` on the chosen model,
and the model must be enabled for the account in the chosen region.

### Environment

```bash
# Credentials: the standard boto3 chain only. Never in source, never in .env,
# never committed. Any of: AWS_PROFILE, AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY
# (+ AWS_SESSION_TOKEN for temporary credentials), an IAM role, or IMDS.
export AWS_PROFILE=your-profile

# Required
export AI_DOCTOR_AGENT_MODE=bedrock
export AI_DOCTOR_AWS_REGION=us-east-1
export AI_DOCTOR_BEDROCK_MODEL_ID=anthropic.claude-3-5-haiku-20241022-v1:0

# Optional but recommended for a first demo: fail loudly rather than fall back,
# so a Bedrock problem cannot be masked by a rule-engine answer.
export AI_DOCTOR_AGENT_FALLBACK=fail

# Only for the live test suite - it makes a real, billable call
export AI_DOCTOR_RUN_LIVE_BEDROCK=1
```

### 1. Prove the live path before demoing it

```bash
pytest tests/test_bedrock_live.py -v
```

This must **pass**, not skip. If it fails, read the message: it names every
unmet prerequisite at once. A skip here means the opt-in was not set.

### 2. Confirm the system considers itself operational

```bash
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 &
curl -s localhost:8000/api/system-status | python -m json.tool | sed -n '/"agent"/,/}/p'
```

Require `llm_operational: true` and a non-empty `credential_sources`. If
`mode_uses_llm` is true but `llm_operational` is false, the warnings array says
exactly why.

### 3. Run the incident loop

```bash
cd frontend && npm install && npm run dev     # dashboard on :3000
```

Then in the dashboard: simulate the incident, heal it, and read the timeline. Or
drive it directly:

```bash
INC=$(curl -s -X POST localhost:8000/api/demo/simulate-incident \
      -H 'Content-Type: application/json' -d '{}' \
      | python -c 'import json,sys; print(json.load(sys.stdin)["incident_id"])')
curl -s -X POST localhost:8000/api/heal -H 'Content-Type: application/json' \
     -d "{\"incident_id\":\"$INC\"}" > /dev/null
curl -s "localhost:8000/api/incidents/$INC" | python -m json.tool
```

### 4. What a genuine success looks like

All of these, or the claim is not earned:

```
status              RESOLVED
agent_mode          bedrock
agent_status        BEDROCK_SUCCESS
diagnosis_outcome   DIAGNOSED
bedrock_invoked     true
used_llm            true
model_id            anthropic.claude-3-5-haiku-20241022-v1:0
aws_region          us-east-1
bedrock_request_id  <a service-assigned UUID>      ← null means no real call
input_tokens        > 0                             ← null means not provided
output_tokens       > 0
total_tokens        > 0
agent_latency_ms    > 0
runtime_state       OLLAMA_RUNNING                  ← verified, not assumed
resolved_at         <timestamp>
```

Timeline: `DETECTED → EVIDENCE_COLLECTED → AI_DIAGNOSIS → POLICY_CHECK →
REMEDIATION_STARTED → VERIFICATION → RETRY → RECOVERED`.

**If `bedrock_request_id` is null or the token counts are null, no real round trip
happened** — regardless of what anything else says. Those fields cannot be produced
by the offline engine or by the contract-test transport, which is why they are the
markers.

### 5. The full suite

```bash
pytest tests/ -q
```

Expected on a machine with credentials and a real Ollama: the 13 Ollama skips and
3 live skips become passes. Nothing should fail.

## Q. Not done, deliberately

- **No cloud deployment** (requirement 13). No Lambda, API Gateway or DynamoDB.
  The dashboard banner now says so explicitly rather than implying a table exists.
- **No new dependencies.** The dashboard is audited from Python source tests; a
  JavaScript test runner was not added for it.
- **No fake Ollama or fake Bedrock server**, and the deleted Python Ollama stand-in
  was not reintroduced. `tests/_fake_bedrock.py` replaces only `client.converse`.
- **No `bedrock_request_id` is ever manufactured.** It comes from a botocore
  response hook reading `ResponseMetadata.RequestId`, or it is null.
- **No unrelated features.** Everything above traces to a numbered requirement or
  to a defect found while testing one.
