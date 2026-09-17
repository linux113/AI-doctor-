# AI Doctor — Advanced Healthcare Agent & Safety Ecosystem

An AI-powered medical triage and informational assistant integrating:
- **[DeepTeam](https://github.com/confident-ai/deepteam)**: LLM Red Teaming & Real-Time Safety Guardrails
- **[Agency Agents](https://github.com/msitarzewski/agency-agents)**: 279 specialist developer & clinical personas
- **[gstack](https://github.com/garrytan/gstack)**: Garry Tan's autonomous engineering slash commands & workflow factory
- **[Superpowers](https://github.com/obra/superpowers)**: Subagent-driven development, TDD, and systematic debugging methodology
- **[Ruflo](https://github.com/ruvnet/ruflo)**: Multi-agent orchestration, swarm intelligence, and agent workflows
- **[21st.dev (`21.dev`)](https://21st.dev)**: Design engineer component registry and CLI (`@21st-dev/cli`)
- **[Framer Motion](https://www.framer.com/motion/)**: Production animation library for smooth UI transitions

---

## Workspace Tools & Installed Ecosystem

| Component | Source / Package | Location / Access |
|---|---|---|
| **DeepTeam** | `confident-ai/deepteam` | Python package (`deepteam --version`), `ai_doctor/guardrails.py`, `ai_doctor/redteam_evaluation.py` |
| **Agency Agents** | `msitarzewski/agency-agents` | `/home/user/agency-agents`, `.cursor/rules/`, `~/.claude/agents/` |
| **gstack** | `garrytan/gstack` | `/home/user/gstack`, `~/.claude/skills/gstack`, `gstack-config` |
| **Superpowers** | `obra/superpowers` | `/home/user/superpowers`, `~/.claude/skills/` (TDD, brainstorming, subagent dev) |
| **Ruflo** | `ruvnet/ruflo` | Global CLI `ruflo` (v3.42.3), `/home/user/ruflo` |
| **21.dev** | `@21st-dev/cli` | Global CLI `21st`, `.cursor/mcp.json`, `.mcp.json` |
| **Framer Motion** | `framer-motion` | Node module in `package.json`, global npm package |

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

- **Web Portal & Dashboard (`ai_doctor/web.py`)**:
  - Running live on port `8000`.
  - Clinical consultation chat with live DeepTeam guardrail verification badges.
  - Red teaming audit dashboard simulating multi-vector attacks.

---

## Quick Verification Commands

```bash
# Verify Python test suite
pytest -v

# Check DeepTeam CLI
deepteam --version

# Check Ruflo CLI
ruflo --version

# Check 21st.dev CLI
21st help

# Check gstack setup
/home/user/gstack/bin/gstack-config get

# Run interactive AI Doctor chat
python3 -m ai_doctor.cli
```
