# QUARANTINED — medical-triage prototype (not part of AI Doctor)

**Status: quarantined, not deleted.** Retained for reference only. Nothing in the
AI Doctor product imports this package.

## What this is

`ai_doctor/` is an unrelated prototype: an LLM **medical-triage chat assistant**
(`assistant.py`, `guardrails.py`, `callback.py`, `web.py`,
`redteam_evaluation.py`, `cli.py`) with DeepTeam red-teaming configuration in
`deepteam_config.yaml` and `example_redteam.py`.

The product in this repository is **not** a medical device and performs **no**
medical reasoning. It is an autonomous troubleshooting and recovery agent for a
local Ollama runtime: it collects OS-level evidence (process table, TCP port,
HTTP `/api/tags`), applies a deterministic decision table, and executes one of
three allowlisted remediation actions. The name collision ("AI Doctor" the
recovery agent vs. `ai_doctor` the triage assistant) is the only relationship.

## Coupling audit (verified, not assumed)

`grep -rn "ai_doctor"` over `backend/`, `runner/`, `agent/`, `frontend/src/`
returns **zero imports**. The only references anywhere are:

| Reference | Nature |
|---|---|
| `tests/test_ai_doctor.py` | tests *of this package only* |
| `deepteam_config.yaml` | this package's own red-team config (`file: "ai_doctor/callback.py"`) |
| `example_redteam.py` | this package's own example |
| `pyproject.toml` / `requirements.txt` | declares it as an **optional extra**, excluded from `requirements-core.txt` |
| `README.md` / `SECURITY.md` | documents it as a separate optional component |

The production FastAPI application is `backend/main.py`. It never imports this
package, and the package is not installed by the core requirements.

## Known problems (do not treat these as coverage for AI Doctor)

1. **Its tests are not security tests of this product.** `tests/test_ai_doctor.py`
   exercises medical guardrails on a chat assistant that the product does not
   ship. They must never be counted as security validation of the recovery
   agent, and are excluded from the core suite (`npm run test:core`,
   `pytest tests/ --ignore=tests/test_ai_doctor.py`).
2. **They pass without any LLM present.** The guardrail evaluation falls back to
   an offline model that returns "safe" unconditionally, and `/api/redteam/run`
   returns a static six-item list. A green run here demonstrates nothing about
   real model behaviour.
3. **It binds port 8000**, which collides with the AI Doctor backend.
4. **CORS wildcard combined with credentials** in `web.py`.

## Disposition

Quarantined in place rather than deleted, per instruction. If this package is
ever revived it needs its own repository, its own port, a real LLM-backed
evaluation path, and a clinical-safety review that this project is not scoped
to provide. Until then: **do not import it, do not run its web app, and do not
cite its tests as evidence about AI Doctor.**
