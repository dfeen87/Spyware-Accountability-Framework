# Architecture

The Spyware Accountability Framework is designed with a **layered, modular architecture** focused on data normalization, reproducible pipelines, and strict, policy-driven analysis powered by the AILEE (Adaptive Integrity Layer for AI Decision Systems) concept.

## High-Level Data Flow

1. **Ingest & Normalize**: Raw data (network flows, OSINT datasets, forensic artifacts) is ingested and mapped into strict schemas (e.g., via Pydantic models).
2. **Analysis (AILEE Layer)**: Normalized artifacts are passed to the `ailee_core` interfaces. Here, backend models (stubs for now, later LLMs or specialized classifiers) generate probabilistic scores (e.g., risk score, classification label). Crucially, the AILEE layer applies a *governance policy* to determine if the AI's output reaches the required trust threshold.
3. **Correlate**: The verified insights are mapped into broader ecosystem graphs (e.g., linking a malicious domain to a vendor to a jurisdiction).
4. **Output**: The system produces actionable, defensive intelligence—machine-readable IOCs and rules, and human-readable briefing documents.

## Core Components

### 1. `pipelines/` (The Automation Engine)
Pipelines are the primary execution units. They orchestrate the flow of data from ingestion to output. By enforcing a declarative configuration style, we ensure that the analysis of any given dataset is perfectly reproducible.

- `network_forensics_pipeline.py`: Ingests and processes network captures (or flow data) looking for spyware-like signatures (e.g., beaconing patterns, known bad TLS fingerprints).
- `osint_vendor_mapping_pipeline.py`: Ingests structured OSINT (corporate registrations, domain WHOIS, hosting providers) to build a relational graph of spyware vendor infrastructure.
- `reporting_pipeline.py`: A final aggregation step that builds the deliverables for researchers and defenders.

### 2. `ailee_core/` (The Trust Engine)
This is the heart of our integration with the AILEE philosophy. We do not trust AI blindly.

- **Interfaces**: We define clear `Analyzer` protocols (Network, OSINT, Forensics).
- **AnalysisResult**: Every result returned by the core must include not just a label, but a `confidence_score`, an overall `risk_score`, and an `explanation`.
- **Policy Enforcement**: (Future) Models are gated by strict policies. If a model detects a malicious artifact but its confidence is below 0.85, the AILEE layer flags it for human review rather than blindly generating an alert.

### 3. `rulesets/` (The Defensive Artifacts)
Our end goal is to output actionable defense. We maintain examples of YARA, Sigma, and Suricata rules. Currently, these contain *synthetic* examples to demonstrate structure without releasing live, usable indicators that could be misused or tip off adversaries.
