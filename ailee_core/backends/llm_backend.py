import json
import logging
import os
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

from ailee_core.interfaces import OSINTAnalyzer, AnalysisResult

logger = logging.getLogger(__name__)

# Environment variables for live API configuration:
#   LLM_API_URL          - Base URL of the OpenAI-compatible chat completions endpoint
#                          (e.g. "https://api.openai.com/v1/chat/completions")
#   LLM_API_KEY          - Bearer token / API key for the endpoint
#
# Cloudflare AI Gateway & Workers AI specific variables (v3 upgrade for Cloudflare):
#   CLOUDFLARE_API_TOKEN  - Cloudflare API Token with AI Gateway permissions
#   CLOUDFLARE_ACCOUNT_ID - Cloudflare Account ID
#   CLOUDFLARE_GATEWAY_ID - Cloudflare AI Gateway ID (optional, defaults to "default")
#   CF_AIG_GATEWAY_ID     - Alternative Cloudflare AI Gateway ID (optional)
#
# These are read at call time (not import time) so that runtime environment
# changes and test monkeypatching take effect without reloading the module.

_SYSTEM_PROMPT = (
    "You are a defensive threat-intelligence analyst specializing in mercenary spyware infrastructure. "
    "Given structured OSINT data, classify the risk and output ONLY valid JSON with keys: "
    "classification_label (str), confidence_score (float 0-1), risk_score (float 0-10), explanation (str). "
    "Use labels: HIGH_RISK_VENDOR, MODERATE_RISK_VENDOR, or BENIGN_ENTITY. "
    "Do not speculate beyond the provided data. Do not generate offensive content."
)


_MAX_LLM_INPUT_SIZE_BYTES = 102400  # 100KB
_VALID_LLM_LABELS = {"HIGH_RISK_VENDOR", "MODERATE_RISK_VENDOR", "BENIGN_ENTITY"}


def _call_live_llm(input_data: Dict[str, Any]) -> Optional[AnalysisResult]:
    """
    Sends a prompt to the configured OpenAI-compatible LLM endpoint and
    parses the JSON response into an AnalysisResult.

    Supports direct API endpoints as well as Cloudflare AI Gateway configurations.

    Returns None if the call fails or the response cannot be parsed, so
    the caller can fall back to deterministic logic.
    """
    # Check for Cloudflare AI Gateway native configurations
    cf_token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    cf_account_id = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
    cf_gateway_id = os.environ.get("CLOUDFLARE_GATEWAY_ID") or os.environ.get("CF_AIG_GATEWAY_ID")

    llm_api_url = os.environ.get("LLM_API_URL", "")
    llm_api_key = os.environ.get("LLM_API_KEY", "")

    headers = {"Content-Type": "application/json"}
    url = ""
    is_cloudflare = False

    if cf_token and cf_account_id:
        # Use Cloudflare AI Gateway REST API
        url = f"https://api.cloudflare.com/client/v4/accounts/{cf_account_id}/ai/v1/chat/completions"
        headers["Authorization"] = f"Bearer {cf_token}"
        if cf_gateway_id:
            headers["cf-aig-gateway-id"] = cf_gateway_id
        is_cloudflare = True
    elif llm_api_url:
        url = llm_api_url
        if llm_api_key:
            headers["Authorization"] = f"Bearer {llm_api_key}"
        # If the URL is explicitly a Cloudflare Gateway URL and we have a CF token, attach the CF-specific header
        if "gateway.ai.cloudflare.com" in llm_api_url and cf_token:
            headers["cf-aig-authorization"] = f"Bearer {cf_token}"
            is_cloudflare = True
    else:
        # No live configuration available
        return None

    serialized = json.dumps(input_data)
    if len(serialized) > _MAX_LLM_INPUT_SIZE_BYTES:
        logger.warning("Input data exceeds 100KB limit for LLM backend; falling back to stub.")
        return None

    user_content = (
        "Analyze the following OSINT data and respond with the JSON schema described:\n"
        + serialized
    )

    # Resolve default model name. Cloudflare REST API uses author/model (e.g. openai/gpt-4.1)
    if is_cloudflare:
        model_name = os.environ.get("LLM_MODEL", "openai/gpt-4o-mini")
    else:
        model_name = os.environ.get("LLM_MODEL", "gpt-4o-mini")

    request_body = json.dumps(
        {
            "model": model_name,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            "temperature": 0,
            "max_tokens": 256,
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        url=url,
        data=request_body,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = json.loads(response.read().decode("utf-8"))
            # In Cloudflare AI Gateway, the response structure is preserved from the upstream (choices[0].message.content)
            # or returned under "result" if utilizing specific Workers AI schemas.
            if "choices" in raw:
                content = raw["choices"][0]["message"]["content"]
            elif "result" in raw and "response" in raw["result"]:
                content = raw["result"]["response"]
            elif "result" in raw and "choices" in raw["result"]:
                content = raw["result"]["choices"][0]["message"]["content"]
            else:
                # Fallback to direct serialization check
                raise ValueError("Could not find completion content in response payload")

            parsed = json.loads(content)
            if parsed.get("classification_label") not in _VALID_LLM_LABELS:
                logger.warning(
                    "LLM returned unexpected label '%s'; falling back to stub.",
                    parsed.get("classification_label"),
                )
                return None
            return AnalysisResult(
                classification_label=parsed["classification_label"],
                confidence_score=float(parsed["confidence_score"]),
                risk_score=float(parsed["risk_score"]),
                explanation=parsed["explanation"],
                metadata={
                    "backend": "llm_backend_live",
                    "model": raw.get("model", model_name),
                    "gateway": "cloudflare_ai_gateway" if is_cloudflare else "direct",
                },
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
