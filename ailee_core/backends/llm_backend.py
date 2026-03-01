import json
import logging
import os
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

from ailee_core.interfaces import OSINTAnalyzer, AnalysisResult

logger = logging.getLogger(__name__)

# Environment variables for live API configuration:
#   LLM_API_URL  - Base URL of the OpenAI-compatible chat completions endpoint
#                  (e.g. "https://api.openai.com/v1/chat/completions")
#   LLM_API_KEY  - Bearer token / API key for the endpoint
# These are read at call time (not import time) so that runtime environment
# changes and test monkeypatching take effect without reloading the module.

_SYSTEM_PROMPT = (
    "You are a defensive threat-intelligence analyst specializing in mercenary spyware infrastructure. "
    "Given structured OSINT data, classify the risk and output ONLY valid JSON with keys: "
    "classification_label (str), confidence_score (float 0-1), risk_score (float 0-10), explanation (str). "
    "Use labels: HIGH_RISK_VENDOR, MODERATE_RISK_VENDOR, or BENIGN_ENTITY. "
    "Do not speculate beyond the provided data. Do not generate offensive content."
)


def _call_live_llm(input_data: Dict[str, Any]) -> Optional[AnalysisResult]:
    """
    Sends a prompt to the configured OpenAI-compatible LLM endpoint and
    parses the JSON response into an AnalysisResult.

    Returns None if the call fails or the response cannot be parsed, so
    the caller can fall back to deterministic logic.
    """
    llm_api_url = os.environ.get("LLM_API_URL", "")
    llm_api_key = os.environ.get("LLM_API_KEY", "")
    if not llm_api_url or not llm_api_key:
        return None

    user_content = (
        "Analyze the following OSINT data and respond with the JSON schema described:\n"
        + json.dumps(input_data, indent=2)
    )
    request_body = json.dumps(
        {
            "model": os.environ.get("LLM_MODEL", "gpt-4o-mini"),
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            "temperature": 0,
            "max_tokens": 256,
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        url=llm_api_url,
        data=request_body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {llm_api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = json.loads(response.read().decode("utf-8"))
            content = raw["choices"][0]["message"]["content"]
            parsed = json.loads(content)
            return AnalysisResult(
                classification_label=parsed["classification_label"],
                confidence_score=float(parsed["confidence_score"]),
                risk_score=float(parsed["risk_score"]),
                explanation=parsed["explanation"],
                metadata={"backend": "llm_backend_live", "model": raw.get("model", "unknown")},
            )
    except urllib.error.URLError as exc:
        logger.warning("LLM API unreachable (%s); falling back to stub logic.", exc)
    except (KeyError, ValueError, json.JSONDecodeError) as exc:
        logger.warning("LLM API returned unparsable response (%s); falling back to stub logic.", exc)
    return None


class LLMBackend(OSINTAnalyzer):
    """
    LLM Backend for OSINT Analysis.

    When ``LLM_API_URL`` and ``LLM_API_KEY`` environment variables are set,
    this backend sends the normalized OSINT data to a live Large Language
    Model (OpenAI-compatible API) to perform semantic analysis, extract
    relationships, and assess risk based on complex unstructured context.

    When the environment variables are not set, or when the live API call
    fails, the backend falls back to deterministic placeholder logic suitable
    for the defensive-only, synthetic testing environment of this framework.
    """

    def analyze(self, input_data: Dict[str, Any]) -> AnalysisResult:
        # Attempt live LLM call first (v3 enhancement)
        live_result = _call_live_llm(input_data)
        if live_result is not None:
            logger.info("LLM backend used live API for analysis.")
            return live_result

        # Fallback: deterministic stub logic
        is_suspicious = "example-spyware" in str(input_data).lower()

        if is_suspicious:
            return AnalysisResult(
                classification_label="HIGH_RISK_VENDOR",
                confidence_score=0.85,
                risk_score=8.5,
                explanation="LLM semantic analysis identified spyware-related terminology and patterns in the OSINT data.",
                metadata={"backend": "llm_backend_stub"}
            )
        else:
            return AnalysisResult(
                classification_label="BENIGN_ENTITY",
                confidence_score=0.9,
                risk_score=1.0,
                explanation="LLM semantic analysis found no indicators of mercenary spyware activity.",
                metadata={"backend": "llm_backend_stub"}
            )
