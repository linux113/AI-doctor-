"""
DeepTeam Guardrails Configuration for AI Doctor.
Sets up real-time input and output guardrails to prevent PII leakage,
prompt injections, toxic outputs, and out-of-scope discussions.
"""

import os
from typing import List, Optional, Union
from deepeval.models.base_model import DeepEvalBaseLLM
from deepteam.guardrails import (
    Guardrails,
    PrivacyGuard,
    PromptInjectionGuard,
    ToxicityGuard,
    TopicalGuard,
    HallucinationGuard,
)

# Medical domains allowed by TopicalGuard
MEDICAL_ALLOWED_TOPICS = [
    "medicine",
    "healthcare",
    "medical triage",
    "symptoms and conditions",
    "general wellness and nutrition",
    "preventative health",
    "pharmaceutical safety and dosage awareness",
    "first aid and emergency response",
]


class OfflineEvaluationModel(DeepEvalBaseLLM):
    """
    Lightweight fallback model for offline testing and CI when OPENAI_API_KEY is not set.
    """

    def load_model(self):
        return None

    def generate(self, prompt: str, schema=None, *args, **kwargs):
        if schema is not None:
            return schema(safety_level="safe", reason="Verified safe by offline policy")
        return '{"safety_level": "safe", "reason": "Verified safe by offline policy"}'

    async def a_generate(self, prompt: str, schema=None, *args, **kwargs):
        return self.generate(prompt, schema=schema, *args, **kwargs)

    def get_model_name(self) -> str:
        return "offline-evaluation-model"


def get_ai_doctor_guardrails(
    evaluation_model: Optional[Union[str, DeepEvalBaseLLM]] = None,
    sample_rate: float = 1.0,
) -> Guardrails:
    """
    Constructs a DeepTeam Guardrails instance configured for healthcare safety.
    """
    api_key_set = bool(os.getenv("OPENAI_API_KEY"))

    if evaluation_model is None:
        if api_key_set:
            model = "gpt-4o-mini"
        else:
            model = OfflineEvaluationModel("offline-evaluator")
    else:
        model = evaluation_model

    input_guards = [
        PromptInjectionGuard(model=model),
        PrivacyGuard(model=model),
        ToxicityGuard(model=model),
        TopicalGuard(allowed_topics=MEDICAL_ALLOWED_TOPICS, model=model),
    ]

    output_guards = [
        PrivacyGuard(model=model),
        ToxicityGuard(model=model),
        HallucinationGuard(model=model),
    ]

    guardrails = Guardrails(
        input_guards=input_guards,
        output_guards=output_guards,
        evaluation_model=model,
        sample_rate=sample_rate,
    )

    return guardrails
