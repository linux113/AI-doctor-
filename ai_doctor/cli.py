"""
Interactive CLI for AI Doctor with real-time DeepTeam Guardrails.
"""

import sys
import os
from ai_doctor.assistant import AIDoctorAssistant
from ai_doctor.guardrails import get_ai_doctor_guardrails


def main():
    print("=" * 60)
    print("   AI Doctor - Healthcare Assistant with DeepTeam Guardrails")
    print("=" * 60)
    print("Commands:")
    print("  'exit' or 'quit' : Exit the interactive session")
    print("  'guardrails'     : Toggle DeepTeam guardrails check (default: ON)")
    print("=" * 60)

    assistant = AIDoctorAssistant()
    guardrails = get_ai_doctor_guardrails()
    guardrails_enabled = True

    history = []

    while True:
        try:
            user_input = input("\n[Patient] > ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting session. Stay healthy!")
            break

        if not user_input:
            continue

        if user_input.lower() in ("exit", "quit"):
            print("Exiting session. Take care!")
            break

        if user_input.lower() == "guardrails":
            guardrails_enabled = not guardrails_enabled
            status = "ENABLED" if guardrails_enabled else "DISABLED"
            print(f"[System] DeepTeam Guardrails are now {status}.")
            continue

        # 1. Run Input Guardrails
        if guardrails_enabled:
            input_verdict = guardrails.guard_input(user_input)
            if input_verdict.breached:
                print("\n[DeepTeam Guardrails Alert] Input flagged as unsafe or out of scope:")
                for v in input_verdict.verdicts:
                    if v.safety_level in ("unsafe", "borderline"):
                        print(f"  - {v.name}: {v.safety_level} (Reason: {v.reason})")
                print("\n[AI Doctor] I cannot process this request because it violates healthcare safety policies.")
                continue

        # 2. Generate Assistant Response
        response = assistant.generate_response(user_input, conversation_history=history)

        # 3. Run Output Guardrails
        if guardrails_enabled:
            output_verdict = guardrails.guard_output(user_input, response)
            if output_verdict.breached:
                print("\n[DeepTeam Guardrails Alert] Generated response breached safety policies:")
                for v in output_verdict.verdicts:
                    if v.safety_level in ("unsafe", "borderline"):
                        print(f"  - {v.name}: {v.safety_level}")
                print("\n[AI Doctor] I apologize, but the response was withheld due to clinical safety guardrails.")
                continue

        print(f"\n[AI Doctor] {response}")
        history.append({"role": "user", "content": user_input})
        history.append({"role": "assistant", "content": response})


if __name__ == "__main__":
    main()
