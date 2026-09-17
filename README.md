# AI Doctor — Autonomous Developer Troubleshooting & Recovery Agent

> **AWS First Commit Hackathon Project**  
> An autonomous agent that detects application outages, diagnoses root causes via verifiable system evidence, executes allowlisted remediations, verifies health, and retries failed transactions without human intervention.

---

## The Autonomous Recovery Loop

```
  ┌──────────────┐      ┌───────────────┐      ┌─────────────┐      ┌──────────────┐      ┌─────────────┐
  │ 1. DETECT    │ ───► │ 2. DIAGNOSE   │ ───► │ 3. FIX      │ ───► │ 4. VERIFY    │ ───► │ 5. RETRY    │
  │ Intercept    │      │ Inspect logs, │      │ Allowlisted │      │ Probe port   │      │ Replay      │
  │ HTTP 500 &   │      │ ports, socket │      │ remediation │      │ 11434 & HTTP │      │ original    │
  │ ConnRefused  │      │ & processes   │      │ start_ollama│      │ endpoints    │      │ request     │
  └──────────────┘      └───────────────┘      └─────────────┘      └──────────────┘      └─────────────┘
                                                                                                 │
                                                                                                 ▼
                                                                                           ┌───────────┐
                                                                                           │ RESOLVED  │
                                                                                           └───────────┘
```

---

## Key Architecture & Features

### 1. Intentional & Realistic Failure Mechanism
- The demo application endpoint (`POST /api/demo/query`) connects to Ollama on TCP port 11434.
- An outage simulation trigger (`POST /api/demo/stop-ollama` or UI button) halts the daemon and drops port 11434.
- Subsequent application traffic fails immediately with an authentic `ConnectionRefusedError` (HTTP 500).
- The incident is automatically intercepted, registered, and timestamped in the incident store.

### 2. SAFE Diagnostic Tool Registry
All diagnostics are strictly **read-only**:
- `check_ollama()`: Checks HTTP API response on `http://127.0.0.1:11434/api/tags`.
- `check_port(port)`: Raw socket connection probe determining `OPEN` vs `CLOSED`.
- `check_process(name)`: Read-only process inspector using `psutil`.
- `get_recent_logs(limit)`: In-memory structured telemetry stream.
- `health_check()`: Overall system readiness probe.
- **Log Scrubbing**: All diagnostics automatically scrub API keys, tokens, Bearer secrets, and passwords using regex redaction masks before evidence storage or display.

### 3. SAFE Remediation Registry & Strict Allowlist
- **Strict Allowlist**: Only explicitly registered functions can be invoked:
  - `start_ollama()`: Launches local Ollama daemon on port 11434.
  - `retry_request()`: Safely replays the original failed transaction against local endpoints.
  - `stop_ollama()`: Outage simulator for chaos/recovery testing.
- **Zero Command Execution Risk**:
  - `eval()` is strictly forbidden.
  - `exec()` is strictly forbidden.
  - `os.system(user_input)` is strictly forbidden.
  - Arbitrary shell commands or LLM-generated code are rejected at the registry boundary and logged as security violations.
  - The single `subprocess.Popen` in the codebase uses a fixed argv list built from `sys.executable` — there is no shell and no user-controlled string on any execution path.

### 3a. Hardened Security Boundary
Audited and hardened — see **[SECURITY.md](SECURITY.md)** for the full findings, reproductions and regression tests.

- **SSRF-safe retries**: `retry_request` destinations are validated structurally (`runner/security.py`), not by string prefix. `http://127.0.0.1.evil.com` and `http://localhost@evil.com` are both refused; userinfo components are rejected outright.
- **Process identity, not mention**: `check_process` and `stop_ollama` match on executable name or `-m` module position (`runner/procmatch.py`). A shell that merely *mentions* "ollama" is no longer counted as the daemon — nor killed by it.
- **PID files are hints, never authority**: every PID is identity-verified before it is signalled, and the file is written `0600` (`runner/pidfile.py`). This closes a confused-deputy path through world-writable `/tmp`.
- **Failures are attributed correctly**: the registry honours an action's own failure verdict, so a broken FIX is no longer misreported as a VERIFY timeout.
- **Evidence-derived confidence**: root-cause confidence is computed from how many of the three independent probes corroborate the hypothesis. Contradictory evidence is detected and reported at low confidence instead of being absorbed by a high-confidence branch.
- **One decision table**: `runner/diagnosis.py` is the single source of truth; `doctor_runner` and the Strands agent both delegate to it, so they cannot drift.
- **Wider credential redaction**: 20 patterns covering AWS/Anthropic/OpenAI/GitHub/Slack/Google/Stripe keys, JWTs, PEM private-key blocks, connection strings and common auth headers — verified not to over-redact operational log lines.
- **Correct CORS**: a wildcard origin is never combined with `allow_credentials`.
- **Optional auth gate**: `AIDOCTOR_API_TOKEN` protects the four process-controlling routes (disabled by default so local development is unchanged). The dashboard injects it server-side, so the browser never holds it.

### 4. Developer Dashboard (Next.js + React + Tailwind + Framer Motion)
- **Live System Health Cards**: Application, Ollama Runtime, TCP Port 11434, Backend API, Doctor Runner.
- **Current Incident Banner**: Real-time error message, HTTP status code, service name, timestamps.
- **Visual Recovery Timeline**: Step-by-step state machine tracking with animated Framer Motion transitions:
  `DETECTED` → `INVESTIGATING` → `ROOT CAUSE FOUND` → `REMEDIATION` → `VERIFYING` → `RESOLVED`
- **Interactive Controls**:
  - *Simulate Failure*: Injects an outage and tests failure detection.
  - *Query App API*: Exercises the demo inference route.
  - *Run Diagnosis*: Collects telemetry and deduces root cause.
  - *Heal Incident*: Executes autonomous recovery loop.
- **Evidence Inspector**: Shows raw port status, process IDs, API reachability, and redacted audit logs.

### 5. Diagnosis Engines: AWS Strands + Amazon Bedrock, and the Offline Rule Engine

The system has **two** diagnosis engines and it always tells you which one ran.

| | `DETERMINISTIC OFFLINE MODE` | `BEDROCK AGENT MODE` |
|---|---|---|
| `AI_DOCTOR_AGENT_MODE` | `deterministic` *(default)* | `bedrock` |
| Reasoning | Rule engine, `runner/diagnosis.py` | Amazon Bedrock foundation model via the **AWS Strands Agents SDK** |
| AWS / network | none | real `bedrock-runtime` calls |
| Credentials needed | no | yes (standard boto3 chain) |
| Reproducible | yes, exactly | no — a model answer varies |
| `Incident.agent_mode` | `deterministic` | `bedrock` |

**Nothing is faked.** `agent/strands_agent.py` builds a real
`strands.models.BedrockModel` and a real `strands.Agent`, and calls it with
`structured_output_model=DiagnosisResult`. The earlier
`StrandsAgentPlaceholder` and `BedrockClientPlaceholder` — a rule engine and a
stub client wearing agent-shaped coats — have been **deleted**, along with the
`BedrockClientInterface` / `StrandsAgentInterface` abstractions whose only
implementation was local.

#### Agent execution flow

```
DETECT  ->  COLLECT EVIDENCE  ->  [redact + catalogue]  ->  STRANDS AGENT + BEDROCK
        ->  structured DiagnosisResult  ->  SCHEMA VALIDATION  ->  POLICY VALIDATION
        ->  existing REMEDIATION_ALLOWLIST  ->  EXECUTE  ->  VERIFY  ->  RETRY  ->  RESOLVED
```

The model **analyses and recommends**. It never executes. Its reply is a
`DiagnosisResult`; the policy layer maps it onto a canonical action constant and
the existing allowlisted registry performs it. Verification and retry remain the
deterministic code they always were.

#### Tools the model may call

Exactly five, all read-only, all loopback-bound: `check_ollama`, `check_port`,
`check_process`, `get_recent_logs`, `health_check`.

There is **no** `run_command`, no shell, no `exec`/`eval`, no arbitrary
filesystem access and no arbitrary HTTP tool — and no parameter on any of the
five that would let the model supply a host, a path or a command. Tool calls are
counted against a per-incident budget.

#### Honest failure

If Bedrock cannot be used — no credentials, unroutable endpoint, model not
enabled, throttled past the bounded retry budget, SDK missing — the incident
records the **real AWS error class and message**. With
`AI_DOCTOR_AGENT_FALLBACK=deterministic` (default) the offline engine then runs
and the incident is labelled `agent_mode=deterministic`,
`agent_status=FALLBACK_DETERMINISTIC` with no `model_id`, because no model was
invoked. With `AI_DOCTOR_AGENT_FALLBACK=fail` no substitution happens and no
remediation is attempted.

A rule-based conclusion is never reported as a Bedrock diagnosis, and a
diagnosis is never labelled "AI" when a Python `if` statement produced it.

#### Cloud deployment (next phase, not built here)

The code is structured so a later phase can deploy
Browser → API Gateway → Lambda → Strands → Bedrock → diagnostic/policy →
local Doctor Runner. The agent layer has no server-side state, takes its
configuration from the environment, and returns a plain report dict — so it can
run inside a Lambda unchanged. `infrastructure/aws_architecture.md` and
`infrastructure/dynamodb_schema.json` describe that target. **No cloud resource
is deployed by this repository.**

> **Note:** incident storage is still in-process, so run the backend with a
> **single** uvicorn worker until the DynamoDB repository lands. With
> `--workers >1` each worker holds its own incident store.


---

## Directory Structure

```
AI-doctor-/
├── SECURITY.md                     # Security model, audit findings & reproductions
├── requirements-core.txt           # Minimal install: the recovery agent (no AWS)
├── requirements-aws.txt            # Real AWS Strands Agents SDK + boto3, for bedrock mode
├── requirements.txt                # Full install: recovery agent + DeepTeam red teaming
├── agent/
│   ├── config.py                   # Env-driven config, validation, credential-source hint
│   ├── diagnosis_agent.py          # THE mode switch: bedrock | deterministic, honest fallback
│   ├── strands_agent.py            # Real Strands Agent + real BedrockModel (no placeholder)
│   ├── schemas.py                  # DiagnosisResult / AgentTelemetry / PolicyDecision
│   ├── prompts.py                  # System prompt, evidence fence, prompt assembly
│   ├── evidence.py                 # Redact-first evidence catalogue with IDs and caps
│   ├── tools.py                    # The five read-only tools + per-incident call budget
│   ├── policy.py                   # Allowlist gate between the model and the executor
│   └── interfaces.py               # Plain data holders (the fake-AWS interfaces are gone)
├── backend/
│   ├── main.py                     # FastAPI REST server, failure injection, auth gate
│   ├── models.py                   # Pydantic schemas (DynamoDB-compatible)
│   └── storage.py                  # Thread-safe incident document repository
├── frontend/
│   ├── src/app/page.tsx            # Next.js + Framer Motion interactive dashboard
│   ├── src/app/layout.tsx          # Dashboard layout & metadata
│   ├── src/middleware.ts           # Server-side proxy; injects the API token
│   ├── next.config.js              # Reverse proxy configuration
│   └── package.json                # React 18, Next 14, Tailwind, Framer Motion
├── infrastructure/
│   ├── aws_architecture.md         # AWS native service mapping & security specs
│   └── dynamodb_schema.json        # DynamoDB table and GSI definition
├── runner/
│   ├── diagnostics.py              # Read-only tools (re-exports the scrubber)
│   ├── diagnosis.py                # Deterministic root-cause engine (single source of truth)
│   ├── doctor_runner.py            # Autonomous loop orchestrator
│   ├── ollama_runtime.py           # Drives the REAL ollama binary; no stand-in server
│   ├── pidfile.py                  # Verified PID handling (no confused deputy)
│   ├── preflight.py                # Real-run CLI: preflight, bedrock-smoke-test, live-demo
│   ├── procmatch.py                # Process identity matching (not substring mention)
│   ├── redaction.py                # THE authoritative sanitisation path (sanitize_deep)
│   ├── remediation.py              # Allowlisted safe remediation functions
│   ├── remediation_registry.py     # Strict security allowlist & incident-scoped audit log
│   ├── security.py                 # SSRF guard for retry destinations
│   ├── timeutil.py                 # Timezone-aware, fixed-width UTC timestamps
│   └── tool_registry.py            # Diagnostic tool registry
├── ai_doctor/                      # QUARANTINED medical-triage prototype (see
│   │                               # ai_doctor/QUARANTINE.md) - not imported by the product
└── tests/                            # 572 collected: 556 pass, 16 skip (13 Ollama, 3 live AWS)
    ├── conftest.py                   # Real-Ollama detection + explicit integration skips
    ├── _fake_bedrock.py              # Fakes ONLY the HTTP transport; the SDK stays real
    ├── test_agent_tools.py           # 93: tool surface, no dangerous parameter, call budget
    ├── test_security_hardening.py    # 77: SSRF, PID trust, registry, confidence, CORS, auth, redaction
    ├── test_agent_schemas.py         # 58: DiagnosisResult strictness, telemetry field set
    ├── test_agent_prompt_injection.py# 58: adversarial evidence, fence escape, persuaded model
    ├── test_agent_policy.py          # 58: allowlist gate, forbidden vocabulary, hallucinations
    ├── test_bedrock_contract.py      # 47: real SDK/boto3 construction, request payload, no creds
    ├── test_agent_modes.py           # 43: mode labelling, honest AWS failure, no silent fallback
    ├── test_agent_evidence.py        # 25: evidence caps, truncation disclosure
    ├── test_defect_regressions.py    # 24: D1 false-positive recovery, D2 secret leak, D3 error class
    ├── test_ollama_integration.py    # 17: runtime matrix A-F (installed/running/stopped/absent/failed)
    ├── test_process_identity.py      # 13: process matching incl. a live decoy shell
    ├── test_agent_redaction.py       # 10: nothing secret reaches the Bedrock request
    ├── test_ai_doctor.py             #  7: QUARANTINED medical component - not product coverage
    ├── test_retry.py                 #  6: request replay unit tests
    ├── test_remediation_allowlist.py #  6: security boundary & block verification
    ├── test_ollama_recovery.py       #  6: daemon recovery lifecycle
    ├── test_ollama_detection.py      #  6: service probe unit tests
    ├── test_bedrock_live.py          #  6: real Bedrock call (3 skip) + negative controls
    ├── test_verification.py          #  4: post-remediation health verification
    ├── test_port_detection.py        #  4: TCP port socket probe tests
    ├── test_api_endpoints.py         #  3: full recovery lifecycle integration tests
    └── test_failure_detection.py     #  1: intentional failure & incident generation
```

### Two components in this repository

This repository contains two distinct pieces of work that share a name:

1. **The autonomous recovery agent** — `runner/`, `backend/`, `frontend/`, `agent/`.
   This is what the rest of this README describes. Install with
   `requirements-core.txt`; no LLM or AWS credentials required.
2. **A quarantined medical-triage prototype** — `ai_doctor/`, `deepteam_config.yaml`,
   `example_redteam.py`. It is **not** part of this product: nothing in `backend/`,
   `runner/`, `agent/` or `frontend/` imports it, and it is excluded from
   `requirements-core.txt`. Read `ai_doctor/QUARANTINE.md` before touching it. Its
   7 tests validate that prototype only and are **not** security coverage for the
   recovery agent — `npm run test:core` excludes them for exactly that reason.

---

## Active Services & Ports

| Service | Port | Description |
|---|---|---|
| **AI Doctor Dashboard** | `3000` | Next.js + Framer Motion developer UI (bound to `0.0.0.0:3000`) |
| **Backend REST API** | `8000` | FastAPI application (`/health`, `/api/incidents`, `/api/heal`, `/api/diagnose`) |
| **Ollama Daemon** | `11434` | The real upstream [Ollama](https://ollama.com) runtime. **Not provided by this repo** — install it separately. When it is absent the agent reports `OLLAMA_NOT_INSTALLED` and substitutes nothing. |

---

## Installation

```bash
# Recovery agent only (recommended; no LLM or AWS credentials needed)
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-core.txt

# Or everything, including the optional DeepTeam red-teaming component
pip install -r requirements.txt

# Only for AI_DOCTOR_AGENT_MODE=bedrock: the real AWS Strands Agents SDK.
# Requires Python >=3.10 and AWS credentials. Deterministic mode needs neither.
pip install -r requirements-aws.txt
```

Verified versions for `requirements-aws.txt`: **strands-agents 1.56.0**,
**boto3 1.43.96** (botocore 1.43.96). `tests/test_bedrock_contract.py` asserts
the installed SDK version rather than trusting this line. There is no
`strands-agents[bedrock]` extra — boto3 is a core dependency of the SDK.

Dashboard:

```bash
cd frontend && npm install
```

## Running the Stack

```bash
ollama serve                                                      # :11434 (real upstream binary)
uvicorn backend.main:app --host 0.0.0.0 --port 8000               # :8000
cd frontend && npm run dev                                        # :3000
```

Or via the root `package.json` scripts: `npm run ollama`, `npm run backend`, `npm run dashboard`.

### Ollama is a real external dependency

This repository previously shipped a ~180-line Python HTTP server
(`runner/ollama_service.py`) that answered on port 11434 and was documented as
"the local Ollama daemon". **It has been deleted.** A Python `http.server` is not
Ollama, and its presence let the demo report recoveries that had never happened —
including a "successful" start whose child process was already dead.

The agent now discovers and drives the real binary via `runner/ollama_runtime.py`
and reports `OLLAMA_NOT_INSTALLED` when it is absent:

- discovery order: `$OLLAMA_EXECUTABLE` → `shutil.which("ollama")` → standard
  Linux locations (`/usr/local/bin`, `/usr/bin`, `/opt/ollama/bin`,
  `~/.ollama/bin`) — no hardcoded single path;
- **identity is verified by running `ollama --version`**, so a file merely named
  `ollama` is rejected;
- `start()` reports success only when the spawned child is alive, the listening
  socket belongs to that child or a descendant, the port is open **and** the HTTP
  API answers. A foreign listener on the port is identified and rejected, never
  adopted.

Without Ollama the 13 integration tests skip with an explicit reason. No
substitute server is started to make them pass.

## Configuration

| Variable | Default | Effect |
|---|---|---|
| `AIDOCTOR_API_TOKEN` | *(unset)* | Bearer token required by `/api/heal` and the `/api/demo/*` process-controlling routes. Gate is off when unset. Set it on **both** backend and frontend — the frontend injects it server-side so the browser never sees it. |
| `AIDOCTOR_CORS_ORIGINS` | `*` | Comma-separated allowed origins. Credentials are enabled only when this is not `*`. |
| `AIDOCTOR_BACKEND_ORIGIN` | `http://127.0.0.1:8000` | Backend targeted by the Next.js proxy. |
| `AIDOCTOR_OLLAMA_PID_FILE` | `/tmp/ollama.pid` | PID file path. Point at a non-world-writable directory in production. |

Diagnosis-engine configuration (all optional; `agent/config.py` validates them at
startup and refuses an unrecognised value rather than guessing):

| Variable | Default | Effect |
|---|---|---|
| `AI_DOCTOR_AGENT_MODE` | `deterministic` | `bedrock` for a real Amazon Bedrock agent, `deterministic` for the offline rule engine. |
| `AI_DOCTOR_AWS_REGION` | `us-east-1` *(bedrock only)* | Bedrock region. |
| `AI_DOCTOR_BEDROCK_MODEL_ID` | `anthropic.claude-3-5-haiku-20241022-v1:0` | Model to invoke. Must be enabled in that region for your account. |
| `AI_DOCTOR_AGENT_FALLBACK` | `deterministic` | `fail` to refuse any substitution when Bedrock is unavailable. |
| `AI_DOCTOR_AGENT_TEMPERATURE` | `0.0` | 0.0–1.0. Low by design: this is troubleshooting, not creative writing. |
| `AI_DOCTOR_AGENT_MAX_OUTPUT_TOKENS` | `1024` | Per-response output cap. |
| `AI_DOCTOR_AGENT_MAX_TURNS` | `6` | Agent iterations before escalation to a human. |
| `AI_DOCTOR_AGENT_MAX_TOOL_CALLS` | `8` | Diagnostic tool calls per incident. |
| `AI_DOCTOR_AGENT_MAX_TOTAL_TOKENS` | `12000` | Token ceiling per incident. |
| `AI_DOCTOR_AGENT_MAX_MODEL_ATTEMPTS` | `2` | Bedrock attempts on throttling. The SDK default (6 attempts, 4s–240s backoff) would hold an incident for ~124s. |
| `AI_DOCTOR_AGENT_TIMEOUT_SECONDS` | `60` | boto3 read timeout. |
| `AI_DOCTOR_MAX_EVIDENCE_BYTES` | `16000` | Evidence bundle cap; logs are dropped first. |
| `AI_DOCTOR_MAX_LOG_LINES` | `25` | Log lines catalogued for the model. |
| `AI_DOCTOR_MAX_PROMPT_CHARS` | `24000` | Prompt cap. Truncation is disclosed inside the prompt. |

Credentials are **never** set here. `bedrock` mode uses the standard boto3 chain
(environment, shared config, IAM role, IMDS). No credential value appears in
source, in `.env`, in telemetry or in logs — `GET /api/system-status` reports only
the *names* of the credential sources it found.

## Preparing a real-world run

`runner/preflight.py` is the product CLI for proving that a real run can actually
happen — before any money is spent and before any claim is made. Three commands,
in increasing order of cost and consequence:

| Command | What it touches | Cost |
|---|---|---|
| `python -m runner.preflight` | local discovery, plus at most one STS `GetCallerIdentity` call | free |
| `python -m runner.preflight bedrock-smoke-test` | one real Bedrock `Converse` request | **billable** |
| `AI_DOCTOR_RUN_LIVE_BEDROCK=1 python -m runner.preflight live-demo` | Bedrock **and** the real local Ollama daemon | **billable** |

Global flags: `--json` (machine-readable report) and `--no-network` (preflight
then makes no network call at all, skipping the STS identity check). Exit code is
`0` when the runtime is ready and `1` when anything is FAIL or BLOCKED.

Neither real command runs unless `AI_DOCTOR_RUN_LIVE_BEDROCK=1` is exported, and
both first run `tests/test_agent_redaction.py` and
`tests/test_agent_prompt_injection.py` in a subprocess and refuse to continue if
they do not pass. **Ordinary preflight never invokes a model** — it constructs
the real client and asserts its endpoint, which requires no API call.

### Prerequisites

1. **Python ≥ 3.10** — strands-agents and boto3 both require it. Deterministic
   mode still runs on 3.9.
2. `pip install -r requirements-core.txt -r requirements-aws.txt` → verified
   against **strands-agents 1.56.0**, **boto3 1.43.96**, **botocore 1.43.96**.
   Preflight reports the versions it actually finds rather than trusting this line.
3. **A real AWS account** with Amazon Bedrock model access enabled for the model
   *and* the region you configure.
4. **A real Ollama installation** for `live-demo`. Preflight and the smoke test do
   not need one, but they report its true state either way.

### AWS setup

Credentials come from the standard boto3 provider chain only: environment
variables, `~/.aws/credentials` / `~/.aws/config` shared profiles, an assumed IAM
role, or IMDS on EC2. No credential value is read into this repository and none
may be committed.

| Permission | Why |
|---|---|
| `bedrock:InvokeModel` on the configured model | the `Converse` call. Use `bedrock:InvokeModel*` when the model is reached through a cross-region inference profile. |
| `sts:GetCallerIdentity` | preflight's identity check, so credentials are proven before anything billable is attempted |

```bash
export AWS_REGION=us-east-1
export AI_DOCTOR_AGENT_MODE=bedrock
export AI_DOCTOR_AWS_REGION=us-east-1
export AI_DOCTOR_BEDROCK_MODEL_ID=anthropic.claude-3-5-haiku-20241022-v1:0
```

The model must be enabled for the account **in that region**. A model available in
`us-west-2` but not `us-east-1` produces a real `ResourceNotFoundException`,
which is reported as `INVALID_MODEL` alongside the raw AWS code.

### Ollama

Install the real binary from <https://ollama.com/download>, then confirm it is
genuinely present:

```bash
ollama --version          # preflight runs exactly this to verify identity
ollama pull llama3.2      # a model must exist before the daemon can serve one
```

Discovery order is `$OLLAMA_EXECUTABLE` → `shutil.which("ollama")` → standard
locations (`/usr/local/bin`, `/usr/bin`, `/opt/ollama/bin`, `~/.ollama/bin`). A
file merely *named* `ollama` is rejected, because identity is verified by asking
the binary for its version. When nothing is found the report says
`OLLAMA: NOT_INSTALLED`: preflight starts nothing, fabricates no server and
claims no recovery.

### Environment variables for a real run

| Variable | Needed for | Value |
|---|---|---|
| `AI_DOCTOR_AGENT_MODE` | smoke test, live demo | `bedrock` |
| `AI_DOCTOR_AWS_REGION` | recommended | e.g. `us-east-1`; defaults to `us-east-1` in bedrock mode |
| `AI_DOCTOR_BEDROCK_MODEL_ID` | recommended | defaults to `anthropic.claude-3-5-haiku-20241022-v1:0` |
| `AI_DOCTOR_AGENT_FALLBACK` | optional | `fail` forbids any substitution — recommended for a demonstration, so a Bedrock failure cannot be masked by the offline rule engine |
| AWS credentials | smoke test, live demo | via the provider chain; never stored here |
| `AI_DOCTOR_RUN_LIVE_BEDROCK` | smoke test, live demo | `1` (also accepts `true`/`yes`/`on`) |
| `OLLAMA_EXECUTABLE` | optional | absolute path, to override discovery |

### 1. Preflight — free, and it never calls Bedrock

```bash
python -m runner.preflight
python -m runner.preflight --json --no-network
```

It checks, in order: the installed packages and their real versions; the
configuration and every relevant environment variable; whether the credential
chain resolves anything at all; who the caller is (STS); whether the real Bedrock
client constructs and points at `https://bedrock-runtime.<region>.amazonaws.com`;
and the real Ollama state — executable identity, process identity, port 11434 and
HTTP API health.

Every line is `ok`, `warn`, `FAIL`, `skip` or `BLOCK`. The run ends with a verdict,
the reasons for each failure, and the exact command to run next.

### 2. Bedrock smoke test — one real, billable request

```bash
export AI_DOCTOR_RUN_LIVE_BEDROCK=1
export AI_DOCTOR_AGENT_MODE=bedrock
python -m runner.preflight bedrock-smoke-test
```

This builds the real `strands.Agent` with the real `strands.models.BedrockModel`,
collects real evidence from this machine, and makes one real `Converse` request.
The `DiagnosisResult` is the model's, parsed and schema-validated. Nothing is
simulated: if the request fails, the actual AWS failure category is reported; if
it succeeds, the request ID, latency and token counts come from the service
response and from nowhere else.

### 3. Live demo — the complete recovery loop

```bash
export AI_DOCTOR_RUN_LIVE_BEDROCK=1
export AI_DOCTOR_AGENT_MODE=bedrock
export AI_DOCTOR_AGENT_FALLBACK=fail        # refuse substitution during the demo
python -m runner.preflight live-demo --create-failure
```

`live-demo` requires **both** a real AWS/Bedrock path and a real Ollama
installation; with either missing it reports BLOCKED and stops. `--create-failure`
generates a genuine outage first by stopping the running daemon through the
existing allowlisted `stop_ollama` action — the same code path the product uses,
not a test hook.

Success is claimed only when all eleven criteria hold. They are evaluated in
pipeline order, so the report names the **earliest** failed stage instead of a
downstream consequence of it:

| # | Criterion |
|---|---|
| 1 | a real Ollama process exists (the state before the run is not `OLLAMA_NOT_INSTALLED`) |
| 2 | a real application failure was generated and an incident recorded |
| 3 | diagnostic evidence was collected |
| 4 | the real Strands Agent executed (`agent_mode=bedrock` and Bedrock was invoked) |
| 5 | a real Bedrock request succeeded (`BEDROCK_SUCCESS` with a service request ID) |
| 6 | a `DiagnosisResult` was produced from the model response |
| 7 | the policy allowlist gate accepted the recommendation |
| 8 | an allowlisted remediation executed and succeeded |
| 9 | real Ollama verification succeeded (`OLLAMA_RUNNING`) |
| 10 | the original request was retried |
| 11 | the retry actually returned HTTP 200 |

### What success looks like

The report prints the proof fields, every one of them read from the real run:

`agent_mode`, `agent_status`, `diagnosis_outcome`, `bedrock_invoked`, `used_llm`,
`model_id`, `aws_region`, `bedrock_request_id`, `latency_ms`, `input_tokens`,
`output_tokens`, `total_tokens`, `evidence_ids`, `recommended_action`,
`policy_result`, `remediation_action`, `remediation_succeeded`,
`verification_result`, `runtime_state_after`, `retry_result`,
`final_http_status`, `incident_status`.

A genuine success shows `agent_mode=bedrock`, `agent_status=BEDROCK_SUCCESS`, a
non-null `bedrock_request_id` issued by the service, a measured `latency_ms`,
`final_http_status=200`, and all eleven criteria `ok`.

Token counts are **not** mandatory proof: they are recorded when the service
returns them and are `null` when it does not. Every absent value prints as `None`
— never as `0`, never as an estimate, never as a plausible-looking placeholder.

### What failure looks like

| In the report | Meaning | Fix |
|---|---|---|
| `aws:credentials` **BLOCK** | nothing found in the provider chain | export credentials or attach a role, then re-run preflight |
| `aws:identity` FAIL `[NO_CREDENTIALS]` | the chain resolved nothing at call time | same as above |
| FAIL `[ACCESS_DENIED]` | the principal lacks `bedrock:InvokeModel`, or model access is not enabled | grant the permission / enable access for that region |
| FAIL `[INVALID_MODEL]` (`ResourceNotFoundException`) | no such model **in that region** | check `AI_DOCTOR_BEDROCK_MODEL_ID` and `AI_DOCTOR_AWS_REGION` |
| FAIL `[SERVICE_UNAVAILABLE]` (`ModelNotReadyException`, `InternalServerException`, 5xx) | the service or model is not serving yet | retry once provisioning completes |
| FAIL `[THROTTLED]` | rate limited | back off; `AI_DOCTOR_AGENT_MAX_MODEL_ATTEMPTS` controls retries |
| FAIL `[TIMEOUT]` | exceeded `AI_DOCTOR_AGENT_TIMEOUT_SECONDS` | raise the timeout or reduce the evidence bundle |
| FAIL `[NETWORK_UNREACHABLE]` (`EndpointConnectionError`, `SSLError`) | DNS, egress or TLS/proxy-certificate failure | check outbound access and the proxy CA bundle |
| FAIL `[VALIDATION_ERROR]` | the request shape was rejected | check the model ID and region pairing |
| FAIL `[SCHEMA_REFUSED]` | the model answered, but not in the required schema | reported honestly instead of guessed at |
| FAIL `[SDK_MISSING]` | strands-agents or boto3 not installed | `pip install -r requirements-aws.txt` |
| `ollama:state` **BLOCK** `NOT_INSTALLED` | no real binary found | install Ollama; nothing is started and nothing is substituted |
| `redaction:tests` **BLOCK** | the security suites did not pass | no real request is made until they do |
| `gate:opt-in` **BLOCK** | `AI_DOCTOR_RUN_LIVE_BEDROCK` is not set | deliberate — this is a billable call |

The raw AWS code is always preserved next to the category (`failure_kind` plus
`aws_error_code`), so nothing is collapsed into a generic `UNKNOWN_AWS_ERROR`
unless it genuinely is unrecognised.

### What is never printed

One rule applies to every line of output: nothing leaves the process without
passing through `runner.redaction.sanitize_deep`.

* a secret access key or session token is **never read into a printable value** —
  only its presence is noted;
* an access key ID appears masked to its last four characters (`****Y123`), with a
  fixed-width prefix so the mask cannot disclose the key's length;
* account IDs and user IDs are masked the same way;
* an ARN is reduced to the kind of principal it describes (`assumed-role`, `role`,
  `user`, `federated-user`) — the ARN itself carries the account ID and the role
  name, so it is never reproduced;
* authorization headers, passwords, API keys, bearer tokens, and credentials
  nested inside exception text are redacted;
* the raw prompt is never logged.

`tests/test_preflight.py` asserts each of these against real command runs, and
asserts that an ordinary preflight attempts no AWS API call at all by patching
`botocore.client.BaseClient._make_api_call` — the single funnel every AWS
operation passes through — so "no Bedrock call was made" is an assertion, not a
claim.

## Running Verification & Tests

Run the full automated test suite (**736 passed, 17 skipped**):

```bash
pytest tests/ -v
```

Recovery-agent tests only, without the optional medical component:

```bash
pytest tests/ -v --ignore=tests/test_ai_doctor.py
```

Most of these tests were added by the technical audit and pin each fix in
[SECURITY.md](SECURITY.md); they fail if a guardrail is later relaxed.

The 17 skips are explicit, never substituted: 13 need the real `ollama` binary,
3 make a real, billable Bedrock call and require `AI_DOCTOR_RUN_LIVE_BEDROCK=1`
plus credentials, and 1 is the quarantined optional medical-triage component,
which skips at module level when `deepeval`/`deepteam` are not installed. See
`tests/test_bedrock_live.py` for the exact command, and
[`runner/preflight.py`](#preparing-a-real-world-run) for the supported way to make
a real Bedrock call.

Execute a deterministic end-to-end recovery test via CLI:

```bash
python3 -c "
import urllib.request, json

# 1. Simulate outage
urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:3000/api/demo/stop-ollama', data=b'{}', headers={'Content-Type': 'application/json'}))

# 2. Trigger failed application query -> HTTP 500 intercepted
try:
    urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:3000/api/demo/query', data=b'{\"prompt\":\"emergency triage\"}', headers={'Content-Type': 'application/json'}))
except urllib.error.HTTPError as e:
    incident_id = json.loads(e.read())['incident_id']
    print(f'Incident detected: {incident_id}')

# 3. Heal incident
with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:3000/api/heal', data=json.dumps({'incident_id': incident_id}).encode(), headers={'Content-Type': 'application/json'})) as r:
    print('Recovery status:', json.loads(r.read())['incident']['status'])

# 4. Verify original application query now succeeds (HTTP 200)
with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:3000/api/demo/query', data=b'{\"prompt\":\"emergency triage\"}', headers={'Content-Type': 'application/json'})) as r:
    print('Application query result:', r.getcode(), json.loads(r.read())['status'])
"
```
