# Phase 4 — real-runtime preflight

**Scope: prepare the project for a reproducible real-world run. No product
features were added and the architecture was not changed.**

Date: 2026-09-17 · Branch: `arena/01a0ae32-ai-doctor`

Operator documentation lives in the README under
[**Preparing a real-world run**](../README.md#preparing-a-real-world-run); the
security reasoning lives in [SECURITY.md §8](../SECURITY.md). This file is the
phase record.

---

## A. Files changed

| File | Change | Lines |
|---|---|---|
| `runner/preflight.py` | **new** — the product CLI: `preflight`, `bedrock-smoke-test`, `live-demo` | 1261 |
| `tests/test_preflight.py` | **new** — 96 tests | 1016 |
| `agent/strands_agent.py` | **modified** — one mapping entry (`SSLError` → `NETWORK_UNREACHABLE`) plus its comment | +7 |
| `README.md` | **modified** — "Preparing a real-world run" (prereqs, AWS setup, Ollama, env vars, the three commands, success and failure evidence, secret rules); corrected the stale test counts; added `preflight.py` to the directory listing | +230 |
| `SECURITY.md` | **modified** — new §8 (the preflight boundary, fabrication rules, secret handling, failure categories, defects P9–P12, limitations); corrected the subprocess inventory in §1 and the stale test table in §5 | +157 |

Nothing else changed. In particular: no fake Ollama, no fake Bedrock, no mocking
of Bedrock in the live path, no arbitrary shell, no new tool for the model, no
replacement of Strands with the deterministic engine, no Lambda deployment, no
history rewrite, no security control removed.

`ai_doctor/cli.py` was **not** touched: it belongs to the quarantined medical
prototype and imports nothing from the product. The recovery agent had no CLI, so
`python -m runner.preflight` is its first entry point — not a second application.

## B. Tests run

```bash
pytest tests/ -q -p no:randomly                                   # full suite
pytest tests/ -q -p no:randomly --ignore=tests/test_ai_doctor.py  # product only
pytest tests/test_preflight.py -q -p no:randomly                  # this phase
```

The redaction gate was also exercised for real, twice, as a subprocess from inside
`live-demo`:

```bash
pytest tests/test_agent_redaction.py tests/test_agent_prompt_injection.py -q -p no:randomly
```

## C. Test results

```
736 passed, 0 failed, 17 skipped, 1 warning      (753 items collected)
736 passed, 0 failed, 16 skipped, 1 warning      (product only)
 96 passed, 0 failed                             (tests/test_preflight.py)
 85 passed in 5.92s                              (redaction gate, run for real by live-demo)
```

The 17 skips are explicit and unchanged in kind: 13 need the real `ollama` binary,
3 make a real billable Bedrock call behind `AI_DOCTOR_RUN_LIVE_BEDROCK=1`, and 1 is
the quarantined medical component skipping at module level because
`deepeval`/`deepteam` are not installed. That last one is why the count moved from
647/16 in Phase 3 to 736/17 here: the environment was rebuilt without the optional
extra, so its 7 tests became 1 module-level skip (647 − 7 + 96 = 736). No product
test was lost, weakened or skipped.

What `tests/test_preflight.py` proves, among other things:

* an ordinary preflight attempts **no** AWS API call — asserted by patching
  `botocore.client.BaseClient._make_api_call`, the single funnel every AWS
  operation passes through, and requiring it never to be entered;
* when the identity check is allowed, the **only** service contacted is `sts`, and
  the only operation is `GetCallerIdentity`;
* a client whose endpoint is not `https://bedrock-runtime.<region>.amazonaws.com`
  is refused rather than accepted as real;
* the secret access key never appears in any rendered output, human or JSON, and
  the full access key ID never appears either — only `****` plus four characters;
  the mask is fixed-width so it cannot disclose the key's length;
* an ARN is reduced to a principal kind, never reproduced;
* both real commands are `BLOCKED` with exit code 1 and zero AWS calls when
  `AI_DOCTOR_RUN_LIVE_BEDROCK` is unset;
* the redaction gate runs **before** any request, and closes the run when the
  suites fail, when the files are missing, or when they hang;
* all eleven success criteria exist, are ordered, and pass on a complete proof;
* the deterministic fallback fails criterion 4, a `BEDROCK_SUCCESS` without a
  request ID fails criterion 5, a policy refusal fails criterion 7, and a retry
  returning anything other than 200 fails criterion 11 — and the **earliest**
  failure is the one reported;
* token counts are not required for success, and absent values are `None`, never 0;
* the module contains no `eval`/`exec`/`compile`/`os.system`/`popen`/`shell=True`,
  and its one subprocess call is a fixed argv list.

## D. Preflight result

Run in this environment, exactly as an operator would run it:

```
$ python -m runner.preflight          # exit code 1

PYTHON PACKAGES
  [ok  ] package:strands-agents                 1.56.0
  [ok  ] package:boto3                          1.43.96
  [ok  ] package:botocore                       1.43.96
  [ok  ] package:pydantic                       2.13.5
  [ok  ] package:fastapi                        0.141.1
  [ok  ] package:uvicorn                        0.53.0
  [ok  ] package:psutil                         7.2.2
  [ok  ] python-version                         3.11.2

CONFIGURATION AND ENVIRONMENT
  [warn] env:AI_DOCTOR_AGENT_MODE               not set — a default or deterministic mode applies
  [warn] env:AI_DOCTOR_AWS_REGION               not set — a default or deterministic mode applies
  [warn] env:AI_DOCTOR_BEDROCK_MODEL_ID         not set — a default or deterministic mode applies
  [ok  ] config:load                            mode=deterministic
  [warn] config:mode                            AI_DOCTOR_AGENT_MODE='deterministic': no model will be invoked.

AWS CREDENTIALS
  [warn] aws:credential-source-hint             no source detected by the local heuristic
  [BLOCK] aws:credentials                       AWS credentials unavailable — nothing was found in the
                                                default provider chain (environment, shared config, IAM role, IMDS)
  [BLOCK] aws:identity                          AWS credentials unavailable

BEDROCK RUNTIME CLIENT
  [skip] bedrock:client                         bedrock mode is not configured

OLLAMA RUNTIME
  [BLOCK] ollama:state                          NOT_INSTALLED — no ollama executable was found on PATH or
                                                in any standard location. Nothing was started and no
                                                stand-in server was substituted.

  BLOCKED   pass=9 warn=5 fail=0 blocked=3 skip=7
  Ollama state:      OLLAMA_NOT_INSTALLED
  Bedrock reachable: NOT TESTED (preflight never invokes the model)
```

With `AI_DOCTOR_AGENT_MODE=bedrock` and credentials present, the same run adds:

```
  [ok  ] aws:credentials    AVAILABLE (access key id ****Y123, secret access key present)
  [ok  ] bedrock:client     CONSTRUCTED (no Bedrock call was made)
         endpoint=https://bedrock-runtime.us-east-1.amazonaws.com  service=bedrock-runtime
         client_class=botocore.client.BedrockRuntime
         strands_model_class=strands.models.bedrock.BedrockModel
```

And with the opt-in set, `live-demo` runs the real gate chain and stops where this
machine cannot go further:

```
  [ok  ] gate:opt-in        AI_DOCTOR_RUN_LIVE_BEDROCK is set
  [ok  ] redaction:tests    85 passed in 5.92s (6455ms)
  [ok  ] aws:credentials    AVAILABLE (access key id ****Y123, secret access key present)
  [FAIL] aws:identity       the AWS SDK could not resolve an identity [NETWORK_UNREACHABLE]: SSLError
  [ok  ] bedrock:client     CONSTRUCTED (no Bedrock call was made)
  [BLOCK] ollama:state      NOT_INSTALLED — …
  BLOCKED: OLLAMA: NOT_INSTALLED
```

## E. Exact commands for a real run

On a machine with AWS credentials, Bedrock model access, and a real Ollama
installation:

```bash
# 0. install
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-core.txt -r requirements-aws.txt
curl -fsSL https://ollama.com/install.sh | sh   # or download from https://ollama.com/download
ollama --version && ollama pull llama3.2

# 1. free preflight - never calls a model
python -m runner.preflight

# 2. ONE real, billable Bedrock request
export AI_DOCTOR_RUN_LIVE_BEDROCK=1
export AI_DOCTOR_AGENT_MODE=bedrock
export AI_DOCTOR_AWS_REGION=us-east-1
export AI_DOCTOR_BEDROCK_MODEL_ID=anthropic.claude-3-5-haiku-20241022-v1:0
python -m runner.preflight bedrock-smoke-test

# 3. the complete real end-to-end demonstration
export AI_DOCTOR_AGENT_FALLBACK=fail            # refuse substitution during the demo
python -m runner.preflight live-demo --create-failure

# machine-readable variants
python -m runner.preflight --json --no-network
AI_DOCTOR_RUN_LIVE_BEDROCK=1 python -m runner.preflight bedrock-smoke-test --json
```

Exit code is `0` when ready and `1` when anything is `FAIL` or `BLOCKED`.

## F. Exact environment variables required

| Variable | Required by | Value |
|---|---|---|
| `AI_DOCTOR_RUN_LIVE_BEDROCK` | `bedrock-smoke-test`, `live-demo` | `1` (`true`/`yes`/`on` also accepted; anything else leaves the gate closed) |
| `AI_DOCTOR_AGENT_MODE` | `bedrock-smoke-test`, `live-demo` | `bedrock` |
| `AI_DOCTOR_AWS_REGION` | recommended | e.g. `us-east-1`; defaults to `us-east-1` in bedrock mode |
| `AI_DOCTOR_BEDROCK_MODEL_ID` | recommended | defaults to `anthropic.claude-3-5-haiku-20241022-v1:0` |
| `AI_DOCTOR_AGENT_FALLBACK` | recommended for a demo | `fail`, so a Bedrock failure cannot be masked by the offline rule engine |
| AWS credentials | `bedrock-smoke-test`, `live-demo` | via the standard boto3 chain only — never committed, never in a file in this repository |
| `OLLAMA_EXECUTABLE` | optional | absolute path, to override discovery |
| `OLLAMA_HOST_BIND` / `OLLAMA_PORT` | optional | default `127.0.0.1` / `11434` |

IAM permissions: `bedrock:InvokeModel` on the configured model (`bedrock:InvokeModel*`
for a cross-region inference profile), and `sts:GetCallerIdentity` for the identity
check.

## G. Blockers

These block a real run **from this environment only**. None of them is a defect in
the code:

| # | Blocker | Evidence |
|---|---|---|
| 1 | No AWS credentials of any kind | `aws:credentials` BLOCKED; `env \| grep -c '^AWS'` → 0; the provider chain finds nothing |
| 2 | No network route to AWS | a real STS `GetCallerIdentity` attempt failed with `SSLError`, classified `NETWORK_UNREACHABLE` |
| 3 | No real Ollama installation | `ollama:state` BLOCKED `NOT_INSTALLED`; nothing found on PATH or in any standard location |
| 4 | Therefore no Bedrock model access can be exercised | `bedrock:client` is only ever CONSTRUCTED here, never invoked |

Consequences: `bedrock-smoke-test` and `live-demo` are verified **up to their
gates** and are `BLOCKED` beyond them. The eleven success criteria are verified
against constructed proofs, not against a live run.

Also worth recording: the sandbox was reset mid-phase. The local clone came back
at the base commit with all Phase 2–3 work present but untracked, and the virtual
environment was gone. The branch pointer was restored from GitHub
(`git reset --mixed` onto the fetched `faae999`) without touching the working tree,
and the environment was rebuilt to the same pinned versions — strands-agents
1.56.0, boto3 1.43.96, botocore 1.43.96, pydantic 2.13.5, pytest 9.1.1. No work
was lost; `git diff` against the pushed commit was empty apart from this phase's
new files.

## H. Was Amazon Bedrock actually called?

**No.** Not once, in any command, during this phase.

* Ordinary preflight does not call it — asserted by a test that patches
  `botocore.client.BaseClient._make_api_call` and requires it never to be entered.
* `bedrock-smoke-test` was run only with the opt-in unset (BLOCKED at the gate) and
  with the opt-in set but no credentials (BLOCKED at `aws:credentials`). Both runs
  made zero AWS calls.
* `live-demo` reached the identity check, where the only service contacted was
  `sts`, and then stopped at `OLLAMA: NOT_INSTALLED` before any model call.
* The three live tests in `tests/test_bedrock_live.py` still skip.

There is therefore no `bedrock_request_id`, no latency measurement and no token
count from a real model in this phase, and none is claimed.

## I. Was a real Ollama actually used?

**No.** Ollama is `NOT_INSTALLED` on this machine: no executable on PATH, none in
`/usr/local/bin`, `/usr/bin`, `/opt/ollama/bin` or `~/.ollama/bin`. Preflight
reported that state, started nothing, fabricated no server and claimed no
recovery — which is the behaviour required of it, and which
`tests/test_preflight.py` asserts by turning any `start()`/`stop()` call into a
test failure.

---

## Defects found and fixed

| # | Defect | Fix |
|---|---|---|
| P9 | `botocore.exceptions.SSLError` was classified `UNKNOWN_AWS_ERROR`. `_BOTOCORE_KINDS` matches on the exact class name and `SSLError` is its own class (`SSLError → ConnectionError → BotoCoreError`), so one of the most common ways a real Bedrock call fails — a corporate proxy presenting its own CA — landed in the one category an operator cannot act on. | Mapped onto the existing `NETWORK_UNREACHABLE`. No new kind; the frozen 13-kind taxonomy is unchanged. Observed working in a real run: `[NETWORK_UNREACHABLE]: SSLError`. |
| P10 | `check_bedrock_client` reached `client.meta.service_model` through a chained `getattr` whose intermediate could be `None`, so a client missing `meta` raised `AttributeError` *out of* the preflight instead of reporting a failure. Found by a test, not by inspection. | Every attribute step is defensive; a malformed client yields `FAILED` naming the offending endpoint. |
| P11 | `--json` / `--no-network` worked only *after* the subcommand name, and argparse let a subparser's default silently overwrite a value already set on the top-level parser. | Defined on both parsers with `argparse.SUPPRESS` defaults on the subparsers. Regression-tested in both positions. |
| P12 | The live-demo path probed the Ollama API via `DoctorRunner.ollama_runtime`, an attribute that does not exist — `DoctorRunner` holds registries, not the runtime object. The `hasattr` fallback would have printed "probe unavailable" instead of the truth. | Uses the same `get_runtime()` singleton the rest of the product uses. |

## Honest statement

This phase made a real run **reproducible and verifiable**; it did not perform one.
The preflight CLI is real, its gates are real, its redaction gate really runs the
security suites, and its failure categories really come from the AWS SDK. But no
Amazon Bedrock request succeeded here and no real Ollama was used, so the
end-to-end demonstration is **not** complete. It is complete when someone runs
`AI_DOCTOR_RUN_LIVE_BEDROCK=1 python -m runner.preflight live-demo --create-failure`
on a machine with credentials and a real Ollama install, and the report shows a
service-issued `bedrock_request_id` with all eleven criteria `ok`.
