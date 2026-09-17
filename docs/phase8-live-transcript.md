# Phase 8 — Live demonstration transcript

Captured by issuing real HTTP requests to a running `uvicorn backend.main:app`
process. **Nothing in this file is simulated or hand-written output.**

**Environment:** no `ollama` binary is installed on this machine, and none can be
installed in it — every host that serves Ollama release binaries
(`objects.githubusercontent.com`, `ollama.com`, `registry.ollama.ai`,
`huggingface.co`) is unreachable from this sandbox, and there is no Go toolchain
to build from source. Steps that require a real daemon are therefore marked
`NOT PERFORMED` with the reason, as instructed, rather than faked with a
substitute server.

---

## Step 0 — Baseline system status

```
GET /api/system-status
HTTP 200   [PERFORMED]
{
  "application": "degraded",
  "ollama": "not_installed",
  "runtime_state": "OLLAMA_NOT_INSTALLED",
  "port_11434_open": false,
  "active_incidents_count": 0,
  "timestamp": "2026-09-17T09:19:55.772923Z"
}
```

`ollama` reports **`not_installed`**, not `down`: an absent runtime is not an
outage, and no allowlisted action can fix it.

## Step 1 — Ollama running → query → HTTP 200

```
NOT PERFORMED
```

Requires a running real Ollama daemon. None is installed, so a 200 baseline
cannot be produced. Reporting this honestly is the requirement; substituting a
Python HTTP server on port 11434 is explicitly forbidden and was not done.

## Step 2 — Intentional failure trigger

```
POST /api/demo/stop-ollama
HTTP 200   [PERFORMED]
{
  "status": "no_runtime_stopped",
  "success": false,
  "state": "OLLAMA_NOT_INSTALLED",
  "message": "Nothing to stop: Ollama is not installed and no listener is present."
}
```

Before this pass the endpoint claimed `"outage_simulated"` unconditionally.
It now reports that there was nothing to stop.

## Step 3 — Query fails → HTTP 500 → incident detected

```
POST /api/demo/query
HTTP 500   [PERFORMED]
{
  "status": "error",
  "http_status": 500,
  "error_class": "ConnectionRefusedError",
  "error_detail": "Connection refused by http://127.0.0.1:11434/api/generate: nothing accepted a TCP connection on that port. The Ollama runtime is NOT INSTALLED on this machine (no executable was found on PATH or in any standard location), so nothing can be listening on port 11434. This is an absent runtime, not an outage.",
  "runtime_state": "OLLAMA_NOT_INSTALLED",
  "requires_human": true,
  "incident_id": "inc-47ea9bfa",
  "incident_status": "DETECTED"
}
```

**D3 fixed:** `error_class` is derived from the real exception
(`ConnectionRefusedError` here because the connection genuinely was refused).
Previously every failure type stored one hardcoded `ConnectionRefusedError`
string and the caught exception was thrown away.

## Step 4 — Incident persisted with evidence

```
GET /api/incidents/inc-47ea9bfa
HTTP 200   [PERFORMED]
{
  "incident_id": "inc-47ea9bfa",
  "status": "DETECTED",
  "http_status": 500,
  "error_class": "ConnectionRefusedError",
  "runtime_state": "OLLAMA_NOT_INSTALLED",
  "requires_human": true,
  "service": "demo-inference-service",
  "request_context": {
    "url": "http://127.0.0.1:8000/api/demo/query",
    "method": "POST",
    "payload": {
      "prompt": "Summarise the latest deployment health report",
      "model": "llama3:latest"
    }
  }
}
```

`evidence` is `null` at the DETECTED stage — it is collected during diagnosis,
not fabricated at detection time.

## Step 5 — Root cause identified

```
POST /api/diagnose → diagnosis
HTTP 200   [PERFORMED]
{
  "hypothesis": "ollama_not_installed",
  "root_cause": "OLLAMA_NOT_INSTALLED: no ollama executable was found on PATH or in any standard location. The runtime is absent from this machine.",
  "confidence": 0.9,
  "recommended_remediation": "start_ollama",
  "requires_human": true,
  "runtime_state": "OLLAMA_NOT_INSTALLED",
  "corroborating_probes": [
    "check_ollama_runtime",
    "check_port",
    "check_ollama"
  ],
  "contradicting_probes": []
}
```

Evidence bundle captured by the read-only diagnostic tools:

```json
{
  "state": "OLLAMA_NOT_INSTALLED",
  "installed": false,
  "executable": null,
  "version": null,
  "pid": null,
  "process_running": false,
  "port_open": false,
  "api_healthy": false,
  "api_status_code": null,
  "api_error": null,
  "detail": "No verified 'ollama' executable was found on PATH or in the standard install locations. This is not an outage: the runtime is absent. Set OLLAMA_EXECUTABLE or install Ollama.",
  "timestamp": "2026-09-17T09:19:55.793339Z",
  "tool": "check_ollama_runtime"
}
```

`requires_human: true` — the diagnosis states that no allowlisted remediation
can install software.

## Step 6 — Autonomous recovery loop

```
POST /api/heal → outcome
HTTP 200   [PERFORMED]
{
  "incident_id": "inc-47ea9bfa",
  "status": "FAILED",
  "failed_stage": "FIX",
  "root_cause": "OLLAMA_NOT_INSTALLED: no ollama executable was found on PATH or in any standard location. The runtime is absent from this machine.",
  "confidence": 0.9,
  "runtime_state": "OLLAMA_NOT_INSTALLED",
  "requires_human": true,
  "action_taken": "start_ollama",
  "error": "Cannot start Ollama: no verified 'ollama' executable was found. No stand-in service is substituted.",
  "resolved_at": null
}
```

`action_result` — what the allowlisted action itself reported (**D5**, now a
first-class field on the Incident):

```json
{
  "action": "start_ollama",
  "success": false,
  "state": "OLLAMA_NOT_INSTALLED",
  "pid": null,
  "returncode": null,
  "port_open": false,
  "api_healthy": false,
  "socket_owned_by_child": false,
  "foreign_listener_pid": null,
  "output_tail": null,
  "already_running": false,
  "elapsed_seconds": null,
  "detail": "Cannot start Ollama: no verified 'ollama' executable was found. No stand-in service is substituted."
}
```

`audit_log` — incident-scoped allowlist decisions (**D4**, persisted, not just
returned):

```json
[
  {
    "action": "start_ollama",
    "incident_id": "inc-47ea9bfa",
    "timestamp": "2026-09-17T09:19:55.807309Z",
    "allowed": true,
    "status": "FAILED",
    "result": {
      "action": "start_ollama",
      "success": false,
      "state": "OLLAMA_NOT_INSTALLED",
      "pid": null,
      "returncode": null,
      "port_open": false,
      "api_healthy": false,
      "socket_owned_by_child": false,
      "foreign_listener_pid": null,
      "output_tail": null,
      "already_running": false,
      "elapsed_seconds": null,
      "detail": "Cannot start Ollama: no verified 'ollama' executable was found. No stand-in service is substituted."
    },
    "error": "Cannot start Ollama: no verified 'ollama' executable was found. No stand-in service is substituted."
  }
]
```

Timeline: `["DETECTED", "INVESTIGATING", "ROOT CAUSE FOUND", "REMEDIATION", "VERIFYING", "FAILED"]`

**D1 fixed:** the loop reports `FAILED` at the `FIX` stage with `resolved_at:
null`. It does not claim a recovery that did not happen.

## Step 7 — Attempt to start the real runtime

```
POST /api/demo/start-ollama
HTTP 500   [PERFORMED]
{
  "status": "failed",
  "success": false,
  "state": "OLLAMA_NOT_INSTALLED",
  "message": "Cannot start Ollama: no verified 'ollama' executable was found. No stand-in service is substituted."
}
```

```json
{
  "pid": null,
  "returncode": null,
  "port_open": false,
  "api_healthy": false,
  "socket_owned_by_child": false,
  "foreign_listener_pid": null,
  "elapsed_seconds": null
}
```

This endpoint previously answered `{"status": "started"}` unconditionally —
the HTTP-layer half of **D1**. It now returns HTTP 500 with `success: false`.

## Steps 8–11 — Verify process/port/tags → retry → HTTP 200 → RESOLVED

```
NOT PERFORMED
```

These steps require a real daemon to have started. With no `ollama` binary
there is no process to verify, no `/api/tags` to answer, and no request that
can succeed. The incident correctly remains `FAILED`.

## Final incident state

```
GET /api/incidents/inc-47ea9bfa   HTTP 200
status            = 'FAILED'
resolved_at       = None
runtime_state     = 'OLLAMA_NOT_INSTALLED'
requires_human    = True
failed_stage      = 'FIX'
action_taken      = 'start_ollama'
action_result     = success=False state='OLLAMA_NOT_INSTALLED'
audit_log entries = 1
timeline          = ['DETECTED', 'INVESTIGATING', 'ROOT CAUSE FOUND', 'REMEDIATION', 'VERIFYING', 'FAILED']
```

---

## Additional live evidence — D2 secret redaction

> Note: credential-shaped literals have been replaced with `<BEARER_TOKEN>` /
> `<AWS_ACCESS_KEY_ID>` placeholders in this committed copy. The requests were
> issued with real-shaped secrets; the leak-check results below are the actual
> output.

A credential is placed in the request payload and in the prompt, then the
incident is read back from storage through the API.

Sent prompt (contains a real-shaped bearer token and a real-shaped AWS access key
ID). The literal values are **deliberately not committed** — credential-shaped
strings in a repository trip GitHub secret-scanning push protection and are bad
hygiene even when fake. They were assembled at runtime from a filler constant:

```
Deploy using Bearer sk-proj-<24 hex-ish chars> and key AKIA<16 uppercase alnum>
```

Stored and served incident — `request_context` and `detected_error`:

```json
{
  "request_context": {
    "url": "http://127.0.0.1:8000/api/demo/query",
    "method": "POST",
    "payload": {
      "prompt": "Deploy using Bearer [REDACTED_API_KEY] and key [REDACTED_AWS_KEY_ID]",
      "model": "llama3:latest"
    }
  },
  "detected_error": "ConnectionRefusedError: Connection refused by http://127.0.0.1:11434/api/generate: nothing accepted a TCP connection on that port. The Ollama runtime is NOT INSTALLED on this machine (no executable was found on PATH or in any standard location), so nothing can be listening on port 11434. This is an "
}
```

Leak check performed against the full serialised incident:

```
bearer token           present in stored incident? False
AWS access key ID      present in stored incident? False
[REDACTED markers      count = 2
```

Also verified: `/api/incidents`, `/api/incidents/latest` and the timeline
`details` for the same incident.

- `GET /api/incidents` → HTTP 200, secret present: False
- `GET /api/incidents/latest` → HTTP 200, secret present: False

---

## Reproducing

```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000
curl -s localhost:8000/api/system-status | jq '.ollama, .runtime_state'
curl -s -X POST localhost:8000/api/demo/query -H 'Content-Type: application/json' \
     -d '{"prompt":"health check"}' | jq '.error_class, .runtime_state, .incident_id'
```
