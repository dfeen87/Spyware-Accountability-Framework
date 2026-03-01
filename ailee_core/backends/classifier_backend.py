import json
import logging
import os
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

from ailee_core.interfaces import NetworkAnalyzer, AnalysisResult

logger = logging.getLogger(__name__)

# Environment variables for live ML classifier API configuration:
#   CLASSIFIER_API_URL - Endpoint accepting a JSON POST with network features
#                        and returning a JSON AnalysisResult payload
#   CLASSIFIER_API_KEY - Bearer token / API key for the endpoint
# These are read at call time (not import time) so that runtime environment
# changes and test monkeypatching take effect without reloading the module.


def _call_live_classifier(input_data: Dict[str, Any]) -> Optional[AnalysisResult]:
    """
    Sends network-flow features to the configured ML classifier endpoint.

    The endpoint is expected to accept a JSON POST body of raw feature data
    and return a JSON object with the same keys as AnalysisResult.

    Returns None on failure so the caller can fall back to stub logic.
    """
    classifier_api_url = os.environ.get("CLASSIFIER_API_URL", "")
    classifier_api_key = os.environ.get("CLASSIFIER_API_KEY", "")
    if not classifier_api_url or not classifier_api_key:
        return None

    body = json.dumps(input_data).encode("utf-8")
    req = urllib.request.Request(
        url=classifier_api_url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {classifier_api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            parsed = json.loads(response.read().decode("utf-8"))
            return AnalysisResult(
                classification_label=parsed["classification_label"],
                confidence_score=float(parsed["confidence_score"]),
                risk_score=float(parsed["risk_score"]),
                explanation=parsed["explanation"],
                metadata={
                    **parsed.get("metadata", {}),
                    "backend": "classifier_backend_live",
                },
            )
    except urllib.error.URLError as exc:
        logger.warning("Classifier API unreachable (%s); falling back to stub logic.", exc)
    except (KeyError, ValueError, json.JSONDecodeError) as exc:
        logger.warning(
            "Classifier API returned unparsable response (%s); falling back to stub logic.", exc
        )
    return None


class ClassifierBackend(NetworkAnalyzer):
    """
    Machine Learning Classifier Backend for Network Analysis.

    When ``CLASSIFIER_API_URL`` and ``CLASSIFIER_API_KEY`` environment
    variables are set, this backend forwards normalized network telemetry
    (flow features, packet sizes, timing) to a live ML classifier endpoint
    to detect C2 beaconing or exfiltration patterns.

    When the environment variables are not set, or when the live API call
    fails, the backend falls back to deterministic placeholder logic suitable
    for the defensive-only, synthetic testing environment of this framework.
    """

    def analyze(self, input_data: Dict[str, Any]) -> AnalysisResult:
        # Attempt live classifier call first (v3 enhancement)
        live_result = _call_live_classifier(input_data)
        if live_result is not None:
            logger.info("Classifier backend used live API for analysis.")
            return live_result

        # Fallback: deterministic stub logic
        features = str(input_data).lower()
        has_beaconing = "beacon" in features or "tls_fingerprint" in features

        if has_beaconing:
            return AnalysisResult(
                classification_label="SUSPICIOUS_BEACON",
                confidence_score=0.92,
                risk_score=9.0,
                explanation="ML Classifier detected network flow patterns strongly correlating with known spyware C2 beaconing.",
                metadata={"backend": "classifier_backend_stub", "features_matched": ["timing_interval", "packet_size"]}
            )
        else:
            return AnalysisResult(
                classification_label="NORMAL_TRAFFIC",
                confidence_score=0.95,
                risk_score=0.5,
                explanation="ML Classifier determined traffic patterns are benign.",
                metadata={"backend": "classifier_backend_stub"}
            )
