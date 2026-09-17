"""
Example DeepTeam verification and usage script.
Demonstrates importing and initializing DeepTeam vulnerabilities and attack methods.
"""

import sys
import deepteam
from deepteam.vulnerabilities import (
    Bias,
    Toxicity,
    PIILeakage,
)
from deepteam.attacks.single_turn import (
    PromptInjection,
    Leetspeak,
    ROT13,
)


def verify_installation():
    print(f"DeepTeam Version: {deepteam.__version__}")
    print("Available vulnerability modules loaded:")
    print(" - Bias:", Bias)
    print(" - Toxicity:", Toxicity)
    print(" - PIILeakage:", PIILeakage)

    print("\nAvailable attack modules loaded:")
    print(" - PromptInjection:", PromptInjection)
    print(" - Leetspeak:", Leetspeak)
    print(" - ROT13:", ROT13)

    # Initialize a sample attack method
    pi = PromptInjection()
    print(f"\nSuccessfully initialized {pi.__class__.__name__}!")


if __name__ == "__main__":
    verify_installation()
