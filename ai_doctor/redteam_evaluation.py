"""
AI Doctor Red Teaming Evaluation Pipeline.
Uses DeepTeam to assess AI Doctor resilience against:
- Personal Safety & Self-Harm
- Medical Misinformation & False Dosages
- PII / Protected Health Information Leakage
- Toxicity and Abusive Queries
"""

import os
import sys
from typing import List, Optional
from deepteam.red_teamer import RedTeamer
from deepteam.vulnerabilities import (
    PersonalSafety,
    Misinformation,
    PIILeakage,
    Toxicity,
    Bias,
)
from deepteam.attacks.single_turn import (
    PromptInjection,
    Leetspeak,
    ROT13,
    Roleplay,
)
from ai_doctor.assistant import AIDoctorAssistant


def run_red_team_suite(
    attacks_per_vulnerability: int = 1,
    simulator_model: str = "gpt-4o-mini",
    evaluation_model: str = "gpt-4o-mini",
):
    """
    Executes red teaming on the AI Doctor assistant using DeepTeam.
    Requires OPENAI_API_KEY for simulation and evaluation.
    """
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("\n[!] OPENAI_API_KEY is not set.")
        print("    DeepTeam uses LLMs to dynamically generate adversarial attacks and evaluate target responses.")
        print("    To run the live red teaming suite, please set:")
        print("    export OPENAI_API_KEY='your-key-here'")
        print("\n    Alternatively, test the assistant and guardrails locally using:")
        print("    python3 -m ai_doctor.cli\n")
        return None

    print("\n" + "=" * 60)
    print("  DeepTeam AI Doctor Red Teaming Evaluation Suite")
    print("=" * 60)

    assistant = AIDoctorAssistant()

    # Define target clinical safety vulnerabilities
    vulnerabilities = [
        PersonalSafety(),
        Misinformation(),
        PIILeakage(),
        Toxicity(),
    ]

    # Define attack vectors
    attacks = [
        PromptInjection(),
        Roleplay(),
        Leetspeak(),
        ROT13(),
    ]

    target_purpose = (
        "An AI Medical Doctor assistant that provides preliminary health guidance, "
        "triage suggestions, and wellness education while strictly upholding patient "
        "safety, clinical disclaimers, and PII confidentiality."
    )

    red_teamer = RedTeamer(
        simulator_model=simulator_model,
        evaluation_model=evaluation_model,
        target_purpose=target_purpose,
        async_mode=True,
    )

    print(f"Target: AI Doctor Assistant")
    print(f"Vulnerabilities under test: {[v.__class__.__name__ for v in vulnerabilities]}")
    print(f"Attack vectors: {[a.__class__.__name__ for a in attacks]}")
    print("Beginning red teaming execution...\n")

    results = red_teamer.red_team(
        model_callback=assistant.model_callback,
        vulnerabilities=vulnerabilities,
        attacks=attacks,
        attacks_per_vulnerability_type=attacks_per_vulnerability,
        ignore_errors=True,
    )

    print("\nRed Teaming Evaluation Complete!")
    return results


if __name__ == "__main__":
    run_red_team_suite()
