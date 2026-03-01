# Active Prevention Integration Guidance

The Spyware Accountability Framework (SAF) is fundamentally an analytical and transparency-focused engine. Under our strict [Core Principles](../README.md#core-principles) and [Governance](../CONTRIBUTING.md) policies, the SAF **does not** and **must not** contain active offensive tooling, perform hack-backs, or interact directly with adversary infrastructure.

However, SAF produces high-fidelity, machine-readable artifacts (such as YARA/Sigma/Suricata rules, indicators of compromise, and structured `AnalysisResult` objects). These artifacts are intended to be consumed by **local defensive systems** to protect networks and individuals proactively.

This document outlines the architectural patterns and best practices for integrating SAF outputs with an external, active defense system (such as an Intrusion Prevention System (IPS), local DNS sinkhole, or a policy engine like the [AILEE Trust Layer](https://github.com/dfeen87/ailee-trust-layer)).

---

## 🛑 Strict Boundaries for Active Prevention

Before implementing any active blocking mechanism based on SAF outputs, you must adhere to the following boundaries:

1. **Local Network Controls Only:** Actions must be limited to modifying the state of systems you own or are explicitly authorized to defend (e.g., updating local firewall rules, dropping packets on a local IPS, or blocking DNS queries at a local resolver).
2. **No Outbound Interaction:** Systems consuming SAF data must not probe, scan, or send retaliatory payloads back to suspected spyware infrastructure.
3. **Fail-Open or Safe-Fail:** Automated blocking mechanisms should default to a state that prioritizes network availability and human safety, taking into account the potential for false positives.

---

## Architectural Handoff Pattern

The recommended integration pattern treats SAF strictly as a **passive intelligence provider** and the external system (e.g., AILEE Trust Layer) as the **enforcement point**.

### 1. SAF Output Generation (The Provider)

SAF pipelines (e.g., `pipelines/network_forensics_pipeline.py`) process telemetry and generate a structured JSON report. A critical component of this output is derived from the `AnalysisResult` object (defined in `ailee_core/interfaces.py`), which guarantees the presence of:

- `classification_label`: The categorized threat (e.g., `MERCENARY_C2_BEACON`).
- `confidence_score`: The AI/analysis engine's confidence in the finding (0.0 to 1.0).
- `risk_score`: The assessed severity or human rights risk (0.0 to 10.0).
- `metadata`: Contextual data containing actionable Extracted Indicators of Compromise (IOCs) like domains, IP addresses, or file hashes.
- `explanation`: A human-readable rationale for the classification.

*Example SAF Output Payload:*
```json
{
    "status": "ACTIONABLE",
    "findings": {
        "classification_label": "MERCENARY_C2_BEACON",
        "confidence_score": 0.95,
        "risk_score": 9.0,
        "explanation": "High frequency beaconing to known bulletproof hosting with self-signed TLS certificates.",
        "metadata": {
            "tls_fingerprint": "xyz123...",
            "associated_jurisdictions": ["Country X"]
        }
    },
    "extracted_iocs": [
        "c2.suspicious-domain.xyz",
        "192.0.2.55"
    ]
}
```

### 2. External Enforcement (The Consumer / AILEE Trust Layer)

The external system continuously monitors SAF output directories (e.g., `/tmp/reports/` or a configured webhook endpoint). When a new `ACTIONABLE` report is detected, the external Trust Layer should perform the following sequence:

#### A. Ingestion and Policy Evaluation
The external system parses the JSON payload and evaluates the `confidence_score` and `risk_score` against its own local defense policies.

*Example Logic:*
> *If `confidence_score` > 0.90 AND `risk_score` > 8.0, proceed to automated blocking. Otherwise, alert an analyst for manual review.*

#### B. Artifact Translation
The external system extracts the `extracted_iocs` or `metadata` elements and translates them into the specific syntax required by the local defensive controls.

- **Domains (`c2.suspicious-domain.xyz`):** Translated into RPZ (Response Policy Zone) records for a DNS sinkhole (e.g., Pi-hole, CoreDNS).
- **IP Addresses (`192.0.2.55`):** Translated into local `iptables`, `nftables`, or firewall appliance block rules.
- **Suricata/YARA rules:** Directly imported into the local IDS/IPS engine (e.g., Suricata, Zeek) and set to `drop` mode instead of `alert`.

#### C. State Modification (Enforcement)
The external system executes the commands to update the local network state (e.g., restarting the DNS service or committing firewall configurations).

#### D. Auditing and Telemetry
The external system must log the enforcement action, linking the newly created block rule directly to the SAF `explanation` and `classification_label` for auditability and transparency.

---

## Example Integration: Webhook Forwarder

While SAF does not build the blocking system, you can easily create a lightweight script alongside your SAF deployment that forwards actionable reports to an external Trust Layer API.

```python
# example_forwarder.py (Not part of core SAF, runs alongside it)
import json
import requests
import time
import os

WATCH_DIR = "/tmp/saf_reports/"
TRUST_LAYER_ENDPOINT = "https://local-ailee-trust-layer.internal/api/v1/enforce"

def process_report(filepath):
    with open(filepath, 'r') as f:
        report = json.load(f)

    if report.get("status") == "ACTIONABLE":
        # Forward only the necessary context to the external enforcement system
        payload = {
            "source": "saf_pipeline",
            "iocs": report.get("extracted_iocs", []),
            "confidence": report["findings"]["confidence_score"],
            "risk": report["findings"]["risk_score"],
            "reason": report["findings"]["explanation"]
        }

        # The Trust Layer receives this and makes the actual network state changes
        response = requests.post(TRUST_LAYER_ENDPOINT, json=payload)
        if response.status_code == 200:
            print(f"Successfully forwarded {filepath} for active prevention.")

# ... directory watching logic ...
```

## Summary

By maintaining a strict architectural separation between **passive intelligence generation** (SAF) and **active network enforcement** (External Trust Layer/IPS), you can effectively deter spyware activity on local networks without violating the framework's core defensive mandate or risking unintended outbound interactions.