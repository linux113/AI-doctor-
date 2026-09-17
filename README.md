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

---

## Directory Structure

```
AI-doctor-/
├── agent/
│   ├── interfaces.py               # Clean contracts for Strands & Bedrock
│   ├── strands_agent.py            # Local agent reasoning implementation
│   └── bedrock_client.py           # Bedrock client placeholder interface
├── backend/
│   ├── main.py                     # FastAPI REST server & failure injection
│   ├── models.py                   # Pydantic schemas (DynamoDB-compatible)
│   └── storage.py                  # Thread-safe incident document repository
├── frontend/
│   ├── src/app/page.tsx            # Next.js + Framer Motion interactive dashboard
│   ├── src/app/layout.tsx          # Dashboard layout & metadata
│   ├── next.config.js              # Reverse proxy configuration
│   └── package.json                # React 18, Next 14, Tailwind, Framer Motion
├── infrastructure/
│   ├── aws_architecture.md        # AWS native service mapping & security specs
│   └── dynamodb_schema.json        # DynamoDB table and GSI definition
├── runner/
│   ├── diagnostics.py              # Read-only tools & credential scrubber
│   ├── doctor_runner.py            # Autonomous loop orchestrator
│   ├── ollama_service.py           # Local Ollama HTTP daemon (:11434)
│   ├── remediation.py              # Allowlisted safe remediation functions
│   ├── remediation_registry.py     # Strict security allowlist & audit log
│   └── tool_registry.py            # Diagnostic tool registry
├── tests/
│   ├── test_api_endpoints.py       # Full recovery lifecycle integration tests
│   ├── test_failure_detection.py   # Intentional failure & incident generation
│   ├── test_ollama_detection.py    # Service probe unit tests
│   ├── test_ollama_recovery.py     # Daemon recovery lifecycle
│   ├── test_port_detection.py      # TCP port socket probe tests
│   ├── test_remediation_allowlist.py # Security boundary & block verification
│   ├── test_retry.py               # Request replay unit tests
│   └── test_verification.py        # Post-remediation health verification
```

---

## Active Services & Ports

| Service | Port | Description |
|---|---|---|
| **AI Doctor Dashboard** | `3000` | Next.js + Framer Motion developer UI (bound to `0.0.0.0:3000`) |
| **Backend REST API** | `8000` | FastAPI application (`/health`, `/api/incidents`, `/api/heal`, `/api/diagnose`) |
| **Ollama Daemon** | `11434` | Local Ollama AI runtime HTTP daemon with `/api/tags` and `/api/generate` |

---

## Running Verification & Tests

Run the full automated test suite (25/25 tests passing):

```bash
pytest tests/ -v
```

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
