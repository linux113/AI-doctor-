# AI Doctor with DeepTeam Red Teaming & Guardrails

An AI-powered medical triage and informational assistant equipped with **[DeepTeam](https://github.com/confident-ai/deepteam)** LLM red teaming and real-time safety guardrails.

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

- **DeepTeam CLI Integration (`deepteam_config.yaml`)**:
  - Standard YAML configuration allowing execution via `deepteam run deepteam_config.yaml`.

---

## Project Structure

```
AI-doctor-/
├── README.md                  # Documentation
├── requirements.txt           # Project dependencies
├── pyproject.toml             # Package and pytest configuration
├── deepteam_config.yaml       # DeepTeam CLI red teaming config
├── example_redteam.py         # Quickstart verification script
├── tests/
│   └── test_ai_doctor.py      # Pytest test suite
└── ai_doctor/
    ├── __init__.py            # Package exports
    ├── assistant.py           # Medical triage assistant logic & safety prompts
    ├── callback.py            # DeepEval/DeepTeam model callback wrapper
    ├── guardrails.py          # DeepTeam real-time input/output guardrails
    ├── redteam_evaluation.py  # DeepTeam red teaming test runner
    └── cli.py                 # Interactive terminal chat with live guardrails
```

---

## Installation

Install dependencies directly from GitHub and PyPI:

```bash
pip install -r requirements.txt
```

Or install `deepteam` directly via Git:

```bash
pip install git+https://github.com/confident-ai/deepteam.git sentry-sdk opentelemetry-exporter-otlp-proto-grpc
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

### 3. Interactive Chat with Guardrails
Launch the interactive AI Doctor CLI with active DeepTeam Guardrails:
```bash
python3 -m ai_doctor.cli
```
*Tip: You can type `guardrails` in the chat to toggle guardrail inspection on and off.*

### 4. Running Red Teaming Evaluation

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
Results and risk assessments will be output to the configured reports folder (`redteam_reports/`).
