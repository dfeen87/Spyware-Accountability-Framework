# Community Governance Board Structure

The Spyware Accountability Framework (SAF) is a powerful tool with significant potential impact on global security, journalism, and human rights. To ensure the framework remains strictly defensive, transparent, and aligned with its core mission, we establish the SAF Community Governance Board.

## 1. Purpose
The Governance Board exists to:
- Act as the final authority on ethical questions and edge-case policy decisions.
- Review major architectural changes (e.g., v3 upgrades to live LLM integrations).
- Evaluate requests from vetted partners (NGOs, researchers) for access to sensitive, non-synthetic datasets or models.
- Maintain and enforce the Abuse Handling Policy.

## 2. Structure & Composition
The Board consists of:
- **Core Maintainers (2)**: Representing the technical direction of the project.
- **Human Rights Experts (2)**: Representatives from civil society organizations specializing in digital rights.
- **Security Research Representative (1)**: An independent, vetted threat researcher focused on state-sponsored or mercenary threats.

## 3. Scope of Authority
The Governance Board *does not* manage day-to-day pull requests (e.g., bug fixes, UI tweaks). It convenes for:
- "Major Change" proposals (see `major_change_review_process.md`).
- Policy violations reported under the Code of Conduct.
- Approvals for the `Sensitive Data Request Policy`.

## 4. Escalation Path
If a contributor or maintainer encounters a PR, issue, or external request that blurs the line between defensive analysis and offensive capability, they must:
1. Halt the review process.
2. Tag the issue with `governance-review`.
3. The Governance Board will review and vote asynchronously within 72 hours.
4. A simple majority (3/5) is required to approve the action; a tie or failure to reach a majority results in rejection.