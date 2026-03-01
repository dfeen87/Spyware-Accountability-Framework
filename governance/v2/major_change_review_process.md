# Major Change Review Process

As the Spyware Accountability Framework evolves (e.g., moving from v2 to v3), significant technical changes may alter the risk profile of the project. A "Major Change" is defined as any modification that:

- Introduces live AI/ML model integration (replacing the current stubbed backends).
- Automates active network interactions (e.g., scanning, crawling).
- Modifies the AILEE trust layer or confidence thresholds.
- Introduces new data ingestion pipelines capable of handling raw PII.

## The Review Workflow

1. **Proposal Phase (RFC):**
   The technical lead or contributor submits a "Request for Comments" (RFC) detailing the proposed change, its defensive utility, and its potential risks.

2. **Public Comment Period (14 Days):**
   The RFC is opened for public comment from the community, allowing researchers and defenders to weigh in on potential unintended consequences.

3. **Governance Board Review:**
   Following the public comment period, the Governance Board evaluates the proposal against the core ethical commitments:
   - Does this remain strictly defensive?
   - Does it introduce targeting capabilities?
   - Does it comply with human-rights standards?

4. **Decision & Implementation:**
   - **Approved:** The implementation proceeds, with specific guardrails mandated by the Board.
   - **Revisions Required:** The Board requests specific technical or policy modifications before approval.
   - **Rejected:** The proposal is deemed too risky or out of scope and is closed.

All decisions by the Governance Board must be documented publicly in the repository.