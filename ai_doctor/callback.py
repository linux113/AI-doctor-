"""
Custom DeepEval / DeepTeam LLM wrapper for AI Doctor.
Enables DeepTeam CLI (`deepteam run`) and Python pipelines to invoke AI Doctor.
"""

from typing import Optional, List
from deepeval.models import DeepEvalBaseLLM
from ai_doctor.assistant import AIDoctorAssistant


class AIDoctorCallback(DeepEvalBaseLLM):
    """
    DeepEval / DeepTeam compliant model wrapper for the AI Doctor assistant.
    """

    def __init__(self, model_name: str = "ai-doctor-assistant"):
        self.assistant = AIDoctorAssistant()
        super().__init__(model_name)

    def load_model(self):
        return self.assistant

    def generate(self, prompt: str, *args, **kwargs) -> str:
        """Synchronously generate an AI Doctor response."""
        return self.assistant.generate_response(prompt)

    async def a_generate(self, prompt: str, *args, **kwargs) -> str:
        """Asynchronously generate an AI Doctor response."""
        return self.generate(prompt, *args, **kwargs)

    def get_model_name(self) -> str:
        return "AI-Doctor-Triage-Assistant"
