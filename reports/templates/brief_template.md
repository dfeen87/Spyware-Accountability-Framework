# 🛡️ Defensive Intelligence Brief

**Status:** {{ status_msg }}

## 1. Executive Summary
This report aggregates findings from network telemetry and OSINT vendor mapping. The infrastructure profiled here exhibits characteristics of mercenary spyware operations.

## 2. Key Findings & Risk Scoring Summary

**Network Indicators:**
- **Confidence:** {{ network_confidence }}
- **Risk Score:** {{ network_risk }}
- **Classification:** {{ network_classification }}

**Vendor Attribution (OSINT):**
- **Confidence:** {{ osint_confidence }}
- **Risk Score:** {{ osint_risk }}
- **Classification:** {{ osint_classification }}

## 3. Infrastructure Details
The network forensic pipeline flagged the following domains or fingerprints as highly suspicious.

{{ iocs_list }}

## 4. Infrastructure Graph Overview
The following entities and relationships form the observed spyware ecosystem map.

{{ infrastructure_graph }}

## 5. Methodological Note, Limitations & Uncertainty
This brief is generated automatically by the Spyware Accountability Framework. It relies on synthetic examples or user-provided inputs evaluated by the AILEE layer.
- **Uncertainty:** The risk and confidence scores provided above reflect the current state of our models (stubs/LLMs/classifiers). They are probabilistic estimates.
- **Limitation:** The AI models may produce false positives. The `status` field indicates whether the models reached the required trust threshold for actionability.
- **Mandate:** Always confirm findings via human analysis before taking defensive action or attributing attacks. DO NOT use this tool for offensive purposes.