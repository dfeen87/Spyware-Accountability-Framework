# Ethics and Governance

The Spyware Accountability Framework operates under a strict, human-rights-aligned mandate. Our core purpose is **defensive transparency**: equipping journalists, researchers, NGOs, and defenders with the tools needed to investigate and map mercenary spyware infrastructure, vendors, and ecosystems.

This mandate requires explicit ethical boundaries and governance mechanisms.

## 🤝 Core Ethical Commitments

### 1. Absolute Defensive Alignment
Every line of code, documentation, rule, and pipeline must serve a purely defensive, analytical, or transparency-focused purpose. We build tools to *detect, map, and report* on abusive infrastructure.

**We categorically prohibit:**
- The creation, distribution, or analysis of offensive exploits, shellcode, or weaponized payloads.
- Any tooling designed to "hack back," disrupt, or interact with adversary infrastructure beyond standard, passive OSINT gathering.
- The use of this framework to improve, obfuscate, or test spyware capabilities.

### 2. No Targeting of Individuals
Our analysis focuses on macro-level entities: corporate structures, vendor relationships, hosting providers, IP spaces, and malware families.

**We categorically prohibit:**
- Tooling or analysis designed to identify, track, or dox specific individuals, whether they are targets of spyware, operators, or employees of vendor companies.
- The inclusion of real Personally Identifiable Information (PII) of victims in any dataset, rule, or documentation.

### 3. Protection of Vulnerable Communities
The existence of this framework must not inadvertently harm the communities we intend to protect. We must ensure that our tools do not expose investigative techniques prematurely, tip off adversaries to ongoing investigations, or provide blueprints for better spyware.

### 4. Transparency and Accountability
Our pipelines, models (even stubs), and rulesets must be open, reproducible, and auditable. When AI/ML (e.g., the AILEE layer) is used to score or classify risk, the reasoning and confidence levels must be transparently reported. We do not trust black-box decisions implicitly.

## 🏛️ Governance Mechanisms

To enforce these commitments, we maintain several governance structures:

1. **The Code of Conduct:** All contributors must adhere to our [Code of Conduct](../CODE_OF_CONDUCT.md), which emphasizes respect, empathy, and professional behavior.
2. **The Community Governance Board:** A specialized body established to oversee ethical compliance, review major architectural changes, and manage requests for sensitive, non-synthetic datasets. For details on its structure and policies, see the [Governance Board Structure](../governance/v2/governance_board_structure.md), the [Major Change Review Process](../governance/v2/major_change_review_process.md), and the [Sensitive Data Request Policy](../governance/v2/sensitive_data_request_policy.md).
3. **The Release Review Checklist:** Before any major release, PR merge, or publication of new rulesets, contributors and maintainers must complete the [Release Review Checklist](../governance/release-review-checklist.md). This ensures no PII, offensive content, or targeting capabilities have slipped in.
4. **The Abuse Handling Policy:** We recognize that even defensive tools can be misused. Our [Abuse Handling Policy](../governance/abuse-handling-policy.md) details how we respond to reports of our framework being used maliciously or in violation of our ethical commitments.
5. **Synthetic Data Mandate:** All examples, tests, and tutorials within this repository must use purely synthetic or heavily anonymized data. We provide examples in the `examples/` directory to demonstrate functionality without relying on real-world, sensitive indicators.
