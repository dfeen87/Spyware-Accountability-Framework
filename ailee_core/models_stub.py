from typing import Any, Dict
from ailee_core.interfaces import AnalysisResult, NetworkAnalyzer, OSINTAnalyzer

class SyntheticNetworkModelStub(NetworkAnalyzer):
    """
    A placeholder AI model implementation for network forensics that returns deterministic,
    hard-coded outputs based on simple heuristics in the input data.

    This represents the "raw AI output" before AILEE policy is applied.
    """

    def analyze(self, input_data: Dict[str, Any]) -> AnalysisResult:
        """
        Takes raw or pre-processed network telemetry, inspects it for known
        spyware-like patterns (e.g., beacon intervals, TLS fingerprinting), and
        returns an AnalysisResult.
        """
        # Look for simple synthetic indicators
        domains = input_data.get("domains", [])
        tls_fingerprints = input_data.get("tls_fingerprints", [])

        is_suspicious = False
        reasoning = []

        if any(d.endswith(".example-spyware.xyz") for d in domains):
            is_suspicious = True
            reasoning.append("Matched synthetic spyware domain.")

        if "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in tls_fingerprints:
            is_suspicious = True
            reasoning.append("Matched known malicious TLS fingerprint.")

        if is_suspicious:
            return AnalysisResult(
                classification_label="SUSPICIOUS_BEACON",
                confidence_score=0.92,
                risk_score=8.5,
                explanation=" | ".join(reasoning),
                metadata={"matched_domains": [d for d in domains if d.endswith(".example-spyware.xyz")]}
            )
        else:
            return AnalysisResult(
                classification_label="BENIGN_TRAFFIC",
                confidence_score=0.98,
                risk_score=1.0,
                explanation="No known indicators of compromise detected.",
                metadata={}
            )


class SyntheticOSINTModelStub(OSINTAnalyzer):
    """
    A placeholder AI model implementation for mapping OSINT data into risk scores,
    representing a model that flags mercenary vendor infrastructure.
    """

    def analyze(self, input_data: Dict[str, Any]) -> AnalysisResult:
        """
        Takes a list of OSINT entities (vendors, hosting providers, domains) and
        returns an AnalysisResult scoring the likelihood of mercenary activity.
        """
        vendors = input_data.get("vendors", [])
        hosting_providers = input_data.get("hosting_providers", [])

        is_mercenary = False
        reasoning = []

        if any(v.get("name") == "FakeSpywareCorp LLC" for v in vendors):
            is_mercenary = True
            reasoning.append("Vendor name matches known synthetic adversary profile.")

        if any(
            "suspicious_jurisdiction" in (j := str(v.get("jurisdiction", "")).lower())
            or "offshore" in j
            for v in vendors
        ):
            is_mercenary = True
            reasoning.append("Vendor registered in a known high-risk or offshore jurisdiction.")

        if any(h.get("name") == "BulletproofHosting Example" for h in hosting_providers):
            is_mercenary = True
            reasoning.append("Infrastructure hosted on known abusive ASN.")

        if any("bulletproof" in str(h.get("name", "")).lower() for h in hosting_providers):
            is_mercenary = True
            reasoning.append("Infrastructure hosted by a provider flagged as bulletproof hosting.")

        if is_mercenary:
            return AnalysisResult(
                classification_label="MERCENARY_INFRASTRUCTURE",
                confidence_score=0.88,
                risk_score=9.0,
                explanation=" | ".join(reasoning),
                metadata={"flagged_entities": [v.get("name") for v in vendors if v.get("name") == "FakeSpywareCorp LLC"]}
            )
        else:
            return AnalysisResult(
                classification_label="STANDARD_CORPORATE",
                confidence_score=0.95,
                risk_score=2.0,
                explanation="Infrastructure appears to be benign corporate hosting.",
                metadata={}
            )

def ailee_policy_gate(result: AnalysisResult, min_confidence: float = 0.85, min_risk: float = 7.0) -> bool:
    """
    Simulates the AILEE governance policy.

    Returns True if the analysis result can be trusted and acted upon
    (e.g., generating a rule or an alert), and False if it requires human review or rejection.
    """
    if result.classification_label in ("BENIGN_TRAFFIC", "STANDARD_CORPORATE"):
        return False # No action needed for benign traffic

    return result.confidence_score >= min_confidence and result.risk_score >= min_risk
