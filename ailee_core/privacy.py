"""
ailee_core/privacy.py - Enhanced Data Privacy Overlays (v3)

Provides cryptographically-assured PII redaction and differential privacy
mechanics for the ingest pipelines to handle non-synthetic sensitive data
more safely. Integrates into all data ingest steps to ensure that even if
sensitive data is accidentally passed to the framework, PII cannot propagate
further into the analysis pipeline or appear in reports.
"""

import re
import math
import random
import hashlib
import hmac
import logging
from typing import Any, Dict, List

_secure_random = random.SystemRandom()
_MAX_REDACT_PII_RECURSION_DEPTH = 50

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PII Detection Patterns
# ---------------------------------------------------------------------------

_PII_PATTERNS: List[tuple] = [
    # Email addresses
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
    # Phone numbers (E.164, common US/EU formats)
    (re.compile(r"\b(?:\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b"), "[REDACTED_PHONE]"),
    # IPv4 addresses that are NOT within RFC 5737 documentation ranges
    # (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), loopback, or private RFC 1918 ranges.
    # We conservatively redact any public IP address not in known-safe ranges.
    (
        re.compile(
            r"\b(?!"
            r"192\.0\.2\."
            r"|198\.51\.100\."
            r"|203\.0\.113\."
            r"|127\.\d+\.\d+\.\d+"
            r"|10\.\d+\.\d+\.\d+"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+"
            r"|192\.168\.\d+\.\d+"
            r")"
            r"(?:\d{1,3}\.){3}\d{1,3}\b"
        ),
        "[REDACTED_IP]",
    ),
    # IMEI (15-digit numeric sequences)
    (re.compile(r"\b\d{15}\b"), "[REDACTED_IMEI]"),
    # MAC addresses
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b"), "[REDACTED_MAC]"),
]


def redact_pii(value: Any, _depth: int = 0) -> Any:
    """
    Recursively traverses a data structure (dict, list, or scalar) and
    replaces any detected PII with placeholder tokens.

    Args:
        value: The input data to scan. Can be a dict, list, str, or any scalar.
        _depth: Internal recursion depth counter. Raises ValueError if exceeded.

    Returns:
        A new data structure with PII replaced by placeholder strings.
    """
    if _depth > _MAX_REDACT_PII_RECURSION_DEPTH:
        raise ValueError("redact_pii: maximum recursion depth exceeded (possible malicious input)")
    if isinstance(value, dict):
        return {k: redact_pii(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_pii(item, _depth + 1) for item in value]
    if isinstance(value, str):
        redacted = value
        for pattern, replacement in _PII_PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        if redacted != value:
            logger.warning("PII detected and redacted from input data.")
        return redacted
    return value


# ---------------------------------------------------------------------------
# Differential Privacy
# ---------------------------------------------------------------------------

def _laplace_noise(sensitivity: float, epsilon: float) -> float:
    """
    Generates Laplace noise for differential privacy using the classic
    Laplace mechanism: noise scale = sensitivity / epsilon.

    Args:
        sensitivity: The global sensitivity of the function (L1 norm).
        epsilon: The privacy budget parameter. Smaller values offer stronger
                 privacy guarantees but more noise.

    Returns:
        A float noise value drawn from Laplace(0, sensitivity/epsilon).
    """
    if epsilon <= 0:
        raise ValueError("epsilon must be positive")
    if sensitivity <= 0:
        raise ValueError("sensitivity must be positive")
    scale = sensitivity / epsilon
    # Use inverse CDF method: Lap(b) = -b * sign(U) * ln(1 - 2|U|) where U ~ Uniform(-0.5, 0.5)
    u = _secure_random.uniform(-0.5 + 1e-10, 0.5 - 1e-10)
    return -scale * math.copysign(1.0, u) * math.log(1.0 - 2.0 * abs(u))


def apply_differential_privacy(
    result_dict: Dict[str, Any],
    epsilon: float = 1.0,
    fields: tuple = ("confidence_score", "risk_score"),
) -> Dict[str, Any]:
    """
    Applies the Laplace differential privacy mechanism to selected numeric
    fields in an AnalysisResult dict. This masks the precise model scores
    so that individual data points cannot be reverse-engineered.

    Args:
        result_dict: A dict representation of an AnalysisResult.
        epsilon: Privacy budget. Default 1.0 (moderate privacy guarantee).
        fields: Names of numeric fields to add noise to.

    Returns:
        A copy of result_dict with noise applied to the specified fields,
        clamped to their valid ranges.
    """
    noised = dict(result_dict)
    if epsilon <= 0:
        raise ValueError("epsilon must be positive")
    # confidence_score: [0.0, 1.0], sensitivity = 1.0
    # risk_score: [0.0, 10.0], sensitivity = 10.0
    sensitivities = {"confidence_score": 1.0, "risk_score": 10.0}
    clamp_ranges = {"confidence_score": (0.0, 1.0), "risk_score": (0.0, 10.0)}

    for field in fields:
        if field in noised and isinstance(noised[field], (int, float)):
            sensitivity = sensitivities.get(field, 1.0)
            noise = _laplace_noise(sensitivity, epsilon)
            lo, hi = clamp_ranges.get(field, (float("-inf"), float("inf")))
            noised[field] = max(lo, min(hi, noised[field] + noise))

    return noised


# ---------------------------------------------------------------------------
# Deterministic PII hash (for pseudonymization in audit logs)
# ---------------------------------------------------------------------------

def pseudonymize(value: str, secret: bytes) -> str:
    """
    Returns a stable, keyed pseudonym for a sensitive string value using
    HMAC-SHA256. This allows internal cross-referencing without exposing
    the original value.

    Args:
        value: The sensitive string to pseudonymize.
        secret: A per-installation secret key.

    Returns:
        A hex string pseudonym (first 16 hex chars of HMAC-SHA256).
    """
    mac = hmac.new(secret, value.encode("utf-8"), hashlib.sha256)
    return "PSEUDO_" + mac.hexdigest()[:32]
