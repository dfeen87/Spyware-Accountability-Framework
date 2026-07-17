# Spyware Accountability Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/dfeen87/Spyware-Accountability-Framework/actions/workflows/ci.yml/badge.svg)](https://github.com/dfeen87/Spyware-Accountability-Framework/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-3.3.1-informational.svg)](CITATION.cff)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)

A **defensive, human-rights-aligned framework** that uses AILEE (Adaptive Integrity Layer for AI Decision Systems) as an analysis engine to:

- Detect and characterize mercenary/state-grade spyware infrastructure and activity.
- Map and document spyware ecosystems (infrastructure, vendors, and relationships).
- Produce machine-readable detection artifacts (rules, IOCs) and human-readable briefs.
- Provide reproducible pipelines for NGOs, journalists, researchers, and defenders.

---

## Core Principles

- **No Offensive Tooling:** This framework does not provide, analyze, or build exploits. It does not provide instructions for building or improving spyware.
- **No Targeting of Individuals:** The focus is exclusively on mapping infrastructure, vendor ecosystems, and systemic patterns.
- **No Real PII or Live Targets:** Any examples, datasets, or tutorials use synthetic or clearly anonymized data.
- **Defensive Alignment:** Everything is framed as transparency and accountability tooling, operating under strict human-rights alignment.

---

## Core Components

1. **AILEE Analysis Interfaces:** Interfaces for integrating AI/ML models to classify and risk-score forensic artifacts and OSINT, with live API backends configurable via environment variables (v3).
2. **Pipelines:** Configurable, reproducible pipelines for:
   - Network Forensics
   - OSINT Vendor Mapping (with NetworkX graph analytics in v3)
   - Reporting and Brief Generation
3. **Privacy Overlays:** `ailee_core/privacy` provides PII redaction, differential privacy, and pseudonymization integrated into all ingestion pipelines (v3).
4. **Reputation Network:** `ailee_core/reputation` provides a federated, HMAC-signed reputation query interface for sharing intelligence between trusted NGO partners (v3).
5. **Rulesets:** Example, synthetic rules (YARA, Sigma, Suricata) demonstrating how to construct defensive signatures safely.
6. **Governance:** Strict guidelines and checklists to ensure contributions remain aligned with human rights and defensive purposes.

---

## Quickstart

### Installation

Ensure you have Python 3.9+ installed.

```bash
git clone https://github.com/dfeen87/Spyware-Accountability-Framework.git
cd Spyware-Accountability-Framework
pip install -e .[dev]
```

### Running a Pipeline (Synthetic Data)

Run the Network Forensics Pipeline against a synthetic network capture:

```bash
python -m pipelines.network_forensics_pipeline \
  --input examples/synthetic_network_capture_description.md \
  --output /tmp/report.json
```

### Running Tests

```bash
pytest tests/
```

### Linting and Type Checking

```bash
ruff check .
mypy ailee_core pipelines
```

---

## AILEE Integration

The `ailee_core` module implements the AILEE architecture (Layering, Policy, and Trust Evaluation):

1. Ingest normalized data (with PII redaction applied at the boundary).
2. Consult AI models for risk/classification scores — using live API backends when configured, or deterministic stubs otherwise.
3. Apply rigorous policy and trust thresholds before acting on those scores.
4. Optionally enrich results with federated reputation data from trusted NGO peers.

---

## Live Backend Configuration

| Environment Variable    | Purpose                                     |
|-------------------------|---------------------------------------------|
| `LLM_API_URL`           | Endpoint for the live LLM backend           |
| `LLM_API_KEY`           | API key for the live LLM backend            |
| `CLASSIFIER_API_URL`    | Endpoint for the live classifier backend    |
| `CLASSIFIER_API_KEY`    | API key for the live classifier backend     |
| `SAF_REPUTATION_PEERS`  | JSON array of federated reputation peers    |

When these variables are unset, the framework falls back to deterministic stub logic.

---

## Intended Audience

- NGOs and civil society organizations
- Investigative journalists
- Security researchers
- Network defenders

---

## Roadmap

### v3 (Current)

1. **Live AI Model Integration:** Pluggable live API backends for `LLMBackend` and `ClassifierBackend`, configurable via environment variables. Falls back gracefully to deterministic stub logic when env vars are unset.
2. **Advanced Graph Analytics:** `OSINTSemanticBackend` and the OSINT pipeline now build real `networkx.DiGraph` objects and compute degree-centrality metrics to identify highly connected nodes in mercenary ecosystems.
3. **Enhanced Data Privacy Overlays:** `ailee_core/privacy` provides PII redaction (`redact_pii`), Laplace differential privacy (`apply_differential_privacy`), and HMAC-based pseudonymization. Both ingestion pipelines call `redact_pii` before any analysis.
4. **Decentralized Reputation Networks:** `ailee_core/reputation` implements HMAC-SHA256-signed federated queries to trusted NGO peers, with graceful degradation when no peers are configured.

### v2 (Completed)

1. **Pluggable AILEE Backends:** Implemented three stubbed backends (`llm_backend.py`, `classifier_backend.py`, `osint_semantic_backend.py`).
2. **Expanded Synthetic Datasets:** Created richer v2 datasets in `synthetic_data/`.
3. **Automated Threat Briefings:** Enhanced the reporting pipeline to generate Markdown briefs with graph visualization.
4. **CI/CD for Rulesets:** Automated YARA/Sigma/Suricata validation in CI.
5. **Community Governance Board:** Formalized review processes in `governance/v2/`.

---

## Acknowledgements

This project was developed with a combination of original ideas, hands‑on coding, and support from advanced AI systems. I would like to acknowledge **Microsoft Copilot**, **Anthropic Claude**, and **Google Jules** for their meaningful assistance in refining concepts, improving clarity, and strengthening the overall quality of this work.


---

## Citing this Work

If you use this framework in research or reports, please cite it using the metadata in [`CITATION.cff`](CITATION.cff):

```bibtex
@software{Feeney_Spyware_Accountability_Framework,
  author  = {Feeney Jr., Don Michael},
  title   = {Spyware Accountability Framework},
  version = {3.3.1},
  URL     = {https://github.com/dfeen87/Spyware-Accountability-Framework}
}
```

---

## Community & Code of Conduct

All contributors and users are expected to follow our [Code of Conduct](CODE_OF_CONDUCT.md). This project is governed by a strict defensive-only policy. For contribution guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md). For security disclosures, see [SECURITY.md](SECURITY.md).

---

## Enterprise Consulting & Integration
This architecture is fully open-source under the MIT License. If your organization requires custom scaling, proprietary integration, or dedicated technical consulting to deploy these models at an enterprise level, please reach out at: dfeen87@gmail.com

---

## License

This project is 100% open-source and released under the MIT License. See the [LICENSE](LICENSE) file for full terms.

