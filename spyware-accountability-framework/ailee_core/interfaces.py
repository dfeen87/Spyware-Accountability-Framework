from typing import Any, Dict, Protocol
from pydantic import BaseModel, Field

class AnalysisResult(BaseModel):
    """
    Standardized output from any AILEE-governed analysis module.

    This enforces the AILEE philosophy: every decision must carry
    a confidence score, a risk score, and an explainable reason,
    allowing the governance layer to decide whether to act on it.
    """
    classification_label: str = Field(
        ...,
        description="The resulting label (e.g., 'SUSPICIOUS_BEACON', 'MERCENARY_VENDOR')"
    )
    confidence_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="The AI model's confidence in this classification (0.0 to 1.0)"
    )
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=10.0,
        description="The assessed risk to human rights or network safety (0.0 to 10.0)"
    )
    explanation: str = Field(
        ...,
        description="A human-readable explanation of why this classification was made."
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Any additional structured context (e.g., matched IOCs, relevant jurisdictions)."
    )


class NetworkAnalyzer(Protocol):
    """
    Interface for analyzing network telemetry, packet captures, or flow data.
    Implementations should detect patterns indicative of spyware C2 or exfiltration.
    """
    def analyze(self, input_data: Dict[str, Any]) -> AnalysisResult:
        ...


class ForensicAnalyzer(Protocol):
    """
    Interface for analyzing forensic artifacts (e.g., files, process lists, memory dumps)
    recovered from potentially compromised devices.
    """
    def analyze(self, input_data: Dict[str, Any]) -> AnalysisResult:
        ...


class OSINTAnalyzer(Protocol):
    """
    Interface for analyzing Open Source Intelligence (e.g., corporate registries,
    WHOIS data, passive DNS) to map and score vendor infrastructure.
    """
    def analyze(self, input_data: Dict[str, Any]) -> AnalysisResult:
        ...
