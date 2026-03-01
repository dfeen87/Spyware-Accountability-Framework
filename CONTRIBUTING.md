# Contributing Guidelines

Thank you for your interest in contributing to the Spyware Accountability Framework! This project is dedicated to providing transparent, defensive, and human-rights-aligned tools for investigating and tracking mercenary spyware.

## 🛑 Hard Boundaries & Non-Goals
Before you contribute, please understand that this is a **DEFENSIVE ONLY** framework.

**We DO NOT accept:**
- Offensive tooling, exploit code, or proof-of-concept exploits.
- Instructions, techniques, or code that could be used to build or improve spyware.
- Commits that include real Personally Identifiable Information (PII) of victims or targets.
- Tooling aimed at targeting or investigating individuals (as opposed to corporate entities, vendors, or infrastructure).

**We DO accept:**
- Improvements to our defensive pipelines and analysis engines.
- Refinements to our AILEE integration stubs and interfaces.
- New **synthetic** datasets or rule examples (YARA, Sigma, etc.).
- Documentation improvements and bug fixes.

## 📝 Contribution Process

1. **Review the Governance Documents:** Read the [Ethics and Governance](docs/ethics-and-governance.md) documentation and the [Release Review Checklist](governance/release-review-checklist.md).
2. **Open an Issue:** Before writing code, open an issue to discuss your proposed changes. This helps ensure alignment with our strict defensive goals.
3. **Branch & Commit:** Create a branch for your work. Ensure your commits are descriptive.
4. **Use Synthetic Data:** Ensure any tests or examples you provide use purely synthetic data.
5. **Ruleset Submissions:** If you are contributing to `rulesets/`, your rules must pass automated CI validation.
    - Rules must contain explicit `synthetic` or `example` markers.
    - Real IP addresses outside of reserved example ranges (e.g., `192.0.2.x`) are prohibited.
    - Ensure your files are formatted correctly for their respective language (YARA, Sigma, Suricata).
6. **Open a PR:** Open a Pull Request referencing the issue. Ensure all CI checks (including `Ruleset CI`) and tests pass.
7. **Review:** Maintainers will review the PR not just for code quality, but for adherence to our human-rights and defensive-only policies.

## 🧑‍💻 Development Setup

```bash
git clone https://github.com/dfeen87/spyware-accountability-framework.git
cd spyware-accountability-framework
pip install -e .[dev]
pytest tests/
```
