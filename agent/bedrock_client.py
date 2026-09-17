"""
Amazon Bedrock Client Interface & Local Placeholder.
Keeps the contract clean for Phase 2 without fake AWS integration.
"""

from typing import Dict, Any, Optional
from .interfaces import BedrockClientInterface


class BedrockClientPlaceholder(BedrockClientInterface):
    """
    Placeholder client for Amazon Bedrock foundation models.
    Does not make fake AWS calls. Documents the Phase 2 AWS SDK (boto3) integration.
    """

    def __init__(self, region_name: str = "us-east-1"):
        self.region_name = region_name
        self.is_connected = False

    def invoke_model(
        self,
        prompt: str,
        model_id: str = "anthropic.claude-3-5-sonnet-20241022-v2:0",
        system_prompt: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.1,
    ) -> Dict[str, Any]:
        """
        Phase 2 Hook:
        client = boto3.client('bedrock-runtime', region_name=self.region_name)
        response = client.converse(...)
        """
        return {
            "status": "placeholder_mode",
            "model_id": model_id,
            "region": self.region_name,
            "note": "AWS Bedrock integration is scheduled for Phase 2. Local deterministic engine active.",
            "prompt_length": len(prompt),
        }
