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

### 5. AWS Phase 2 Integration Architecture
- `agent/interfaces.py`: Clean abstract interfaces for future **AWS Strands Agents** and **Amazon Bedrock (Claude 3.5 Sonnet)** without fake AWS mocks.
- `infrastructure/dynamodb_schema.json`: Complete DynamoDB table schema with Partition Key (`incident_id`), Sort Key (`created_at`), and `StatusCreatedAtIndex` GSI.
- `infrastructure/aws_architecture.md`: Full architectural specification for AWS cloud deployment (API Gateway, Lambda, Step Functions, Systems Manager, CloudWatch, S3, DynamoDB).

**The Bedrock/Strands seam is now a single call site.** `runner/diagnosis.py`
owns the deterministic decision table, and both `DoctorRunner` and
`StrandsAgentPlaceholder` delegate to it. Swapping in a foundation model means
replacing that one function with a Bedrock call that receives the same evidence
bundle and returns the same `Diagnosis` shape — keeping the deterministic path as
the fallback for when the model is unreachable or proposes an action outside
`REMEDIATION_ALLOWLIST`. `select_remediation()` already enforces that allowlist
independently of what the reasoning layer suggests.

Two prerequisites for the DynamoDB swap are already in place: `created_at` is a
fixed-width UTC string (`runner/timeutil.py`), so lexicographic sort order is
stable for use as a RANGE key, and every diagnosis now carries
`confidence`/`failed_stage` fields that persist through
`Incident.to_dynamodb_item()`.

> **Note:** incident storage is still in-process, so run the backend with a
> **single** uvicorn worker until the DynamoDB repository lands. With
> `--workers >1` each worker holds its own incident store.


---

## Directory Structure

```
AI-doctor-/
├── SECURITY.md                     # Security model, audit findings & reproductions
├── requirements-core.txt           # Minimal install: the recovery agent
├── requirements.txt                # Full install: recovery agent + DeepTeam red teaming
├── agent/
│   ├── interfaces.py               # Clean contracts for Strands & Bedrock
│   ├── strands_agent.py            # Local agent reasoning (delegates to runner/diagnosis.py)
│   └── bedrock_client.py           # Bedrock client placeholder interface
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
│   ├── procmatch.py                # Process identity matching (not substring mention)
│   ├── redaction.py                # THE authoritative sanitisation path (sanitize_deep)
│   ├── remediation.py              # Allowlisted safe remediation functions
│   ├── remediation_registry.py     # Strict security allowlist & incident-scoped audit log
│   ├── security.py                 # SSRF guard for retry destinations
│   ├── timeutil.py                 # Timezone-aware, fixed-width UTC timestamps
│   └── tool_registry.py            # Diagnostic tool registry
├── ai_doctor/                      # QUARANTINED medical-triage prototype (see
│   │                               # ai_doctor/QUARANTINE.md) - not imported by the product
└── tests/                            # 173 collected: 160 pass, 13 skip without real Ollama
    ├── conftest.py                   # Real-Ollama detection + explicit integration skips
    ├── test_security_hardening.py    # 76: SSRF, PID trust, registry, confidence, CORS, auth, redaction
    ├── test_defect_regressions.py    # 24: D1 false-positive recovery, D2 secret leak, D3 error class
    ├── test_ollama_integration.py    # 17: runtime matrix A-F (installed/running/stopped/absent/failed)
    ├── test_process_identity.py      # 13: process matching incl. a live decoy shell
    ├── test_ai_doctor.py             #  7: QUARANTINED medical component - not product coverage
    ├── test_retry.py                 #  6: request replay unit tests
    ├── test_remediation_allowlist.py #  6: security boundary & block verification
    ├── test_ollama_recovery.py       #  6: daemon recovery lifecycle
    ├── test_ollama_detection.py      #  6: service probe unit tests
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
```

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

## Running Verification & Tests

Run the full automated test suite (**102 passed, 1 skipped**):

```bash
pytest tests/ -v
```

Recovery-agent tests only, without the optional medical component:

```bash
pytest tests/ -v --ignore=tests/test_ai_doctor.py
```

84 of these tests were added by the technical audit and pin each fix in
[SECURITY.md](SECURITY.md); they fail if a guardrail is later relaxed.

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
