# AI Doctor with DeepTeam Red Teaming & Agency Agents

An AI-powered medical triage and informational assistant equipped with **[DeepTeam](https://github.com/confident-ai/deepteam)** LLM red teaming, real-time safety guardrails, and **[Agency Agents](https://github.com/msitarzewski/agency-agents)** specialist developer personas.

---

## Features

- **AI Doctor Assistant (`ai_doctor/assistant.py`)**:
  - Clinical triage and healthcare guidance with mandatory medical disclaimers.
  - Emergency symptom detection (e.g., chest pain, shortness of breath, severe trauma).
  - Safety boundaries against prescribing prescription drugs or off-label lethal combinations.
  - Works with OpenAI models (`gpt-4o`, `gpt-4o-mini`) when an API key is supplied, with safe rule-based fallback triage for offline testing.

- **DeepTeam Guardrails (`ai_doctor/guardrails.py`)**:
  - **PromptInjectionGuard**: Blocks adversarial jailbreaks and prompt override attempts.
  - **PrivacyGuard**: Protects patient personal health information (PII/HIPAA compliance).
  - **ToxicityGuard**: Filters offensive, abusive, or hostile exchanges.
  - **TopicalGuard**: Keeps conversations constrained strictly within healthcare and medical triage topics.
  - **HallucinationGuard**: Screens outputs to minimize medical hallucination risks.

- **DeepTeam Red Teaming Suite (`ai_doctor/redteam_evaluation.py`)**:
  - Automated adversarial simulation targeting clinical vulnerabilities:
    - `PersonalSafety` (self-harm, unsafe consumption)
    - `Misinformation` (unverified medical claims, false dosages)
    - `PIILeakage` (patient health record leaks)
    - `Toxicity` & `Bias`
  - Multiple attack methods: `PromptInjection`, `Roleplay`, `Leetspeak`, `ROT13`.

- **Agency Agents Integration (`agency-agents`)**:
  - Full catalog of 279 specialist agents installed across 18 divisions (Healthcare, Security, Engineering, Testing, etc.).
  - Configured for Claude Code (`~/.claude/agents`), Cursor IDE (`.cursor/rules`), Codex (`~/.codex/agents`), Copilot (`~/.copilot/agents`), and Gemini CLI (`~/.gemini/agents`).

---

## Project Structure

```
AI-doctor-/
├── README.md                  # Documentation
├── requirements.txt           # Project dependencies
├── pyproject.toml             # Package and pytest configuration
├── deepteam_config.yaml       # DeepTeam CLI red teaming config
├── example_redteam.py         # Quickstart verification script
├── .cursor/rules/             # 279 Agency Agents rules for Cursor IDE
├── tests/
│   └── test_ai_doctor.py      # Pytest test suite (7/7 tests passing)
└── ai_doctor/
    ├── __init__.py            # Package exports
    ├── assistant.py           # Medical triage assistant logic & safety prompts
    ├── callback.py            # DeepEval/DeepTeam model callback wrapper
    ├── guardrails.py          # DeepTeam real-time input/output guardrails
    ├── redteam_evaluation.py  # DeepTeam red teaming test runner
    ├── cli.py                 # Interactive terminal chat with live guardrails
    ├── web.py                 # FastAPI backend for web portal
    └── static/index.html      # Clinical chat & Red Teaming Audit UI
```

---

## Installation

### 1. Install DeepTeam & Python Dependencies
```bash
pip install -r requirements.txt
```

### 2. Agency Agents Catalog
The full repository is installed in `/home/user/agency-agents`:
```bash
# Re-run installer if needed for specific tools:
cd /home/user/agency-agents
./scripts/install.sh --tool claude-code,cursor,copilot,codex,gemini-cli --no-interactive
```

---

## Usage

### 1. Verification Script
Verify that DeepTeam and its core vulnerability/attack modules are functioning:
```bash
python3 example_redteam.py
```

### 2. Run Test Suite
Run unit and integration tests:
```bash
pytest -v
```

### 3. Interactive Web Dashboard
Run the FastAPI web application with live preview:
```bash
uvicorn ai_doctor.web:app --host 0.0.0.0 --port 8000
```
Open `http://localhost:8000` to access:
- **Clinical Consultation**: Interactive chat with real-time DeepTeam Guardrail chips.
- **DeepTeam Red Team Audit**: Automated adversarial matrix testing defenses.

### 4. Interactive Terminal Chat
```bash
python3 -m ai_doctor.cli
```

### 5. Running Red Teaming Evaluation

#### Via Python Script:
```bash
export OPENAI_API_KEY="your-api-key"
python3 -m ai_doctor.redteam_evaluation
```

#### Via DeepTeam CLI:
```bash
export OPENAI_API_KEY="your-api-key"
deepteam run deepteam_config.yaml
```
