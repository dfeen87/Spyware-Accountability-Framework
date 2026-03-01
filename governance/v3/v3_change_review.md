# V3 Major Change Review – Live AI Integration and Advanced Analytics

## Overview

This document records the V3 Major Change Review for the Spyware Accountability Framework,
covering the four principal enhancements introduced in version 3. All changes were reviewed
by the Governance Board prior to merge in accordance with the **Major Change Review Process**
(`governance/v2/major_change_review_process.md`).

---

## Change 1: Live AI Model Integration

**Scope:** `ailee_core/backends/llm_backend.py`, `ailee_core/backends/classifier_backend.py`

**Description:**
The v2 stubbed backends have been upgraded to support optional connections to live LLM and
ML classifier endpoints. When the environment variables `LLM_API_URL` / `LLM_API_KEY` (for the
LLM backend) or `CLASSIFIER_API_URL` / `CLASSIFIER_API_KEY` (for the classifier backend) are
set, the backends forward normalized data to the configured endpoint and parse the JSON
response into a standardized `AnalysisResult`.

**Safety Controls:**
- Live API calls are strictly optional; the framework falls back to deterministic stub logic
  when environment variables are unset or when the API call fails.
- All prompts sent to the LLM include an explicit system directive prohibiting offensive
  content generation and constraining the model to defensive analytical scope.
- The AILEE governance policy gate (`ailee_policy_gate`) continues to be applied to all
  results regardless of whether they originate from a live or stub backend.
- Non-determinism from LLMs is mitigated by using `temperature=0` and enforcing confidence
  thresholds via the existing policy gate.

**Risk Assessment:** Medium. Mitigated by mandatory fallback, strict prompt sandboxing, and
unchanged governance thresholds.

---

## Change 2: Advanced Graph Analytics (NetworkX)

**Scope:** `ailee_core/backends/osint_semantic_backend.py`,
`pipelines/osint_vendor_mapping_pipeline.py`

**Description:**
The OSINT semantic backend now constructs a real `networkx.DiGraph` from the input entities
and computes degree-centrality metrics to identify highly connected nodes. The OSINT pipeline
also builds a parallel NetworkX graph during the actionable-result path and appends
`analytics` metadata to the output JSON (node count, edge count, weakly-connected-component
sizes, top nodes by centrality).

**Safety Controls:**
- All graph computations are performed locally; no data is forwarded to external graph
  databases in this release.
- The output JSON schema is backward-compatible: existing `nodes` and `edges` arrays are
  preserved; the new `analytics` sub-object is additive.

**Risk Assessment:** Low.

---

## Change 3: Enhanced Data Privacy Overlays

**Scope:** `ailee_core/privacy.py` (new), `pipelines/network_forensics_pipeline.py`,
`pipelines/osint_vendor_mapping_pipeline.py`

**Description:**
A new `privacy` module provides:
1. **PII Redaction** (`redact_pii`): Recursively scans dict/list/str data structures for
   email addresses, phone numbers, non-RFC-5737 IPv4 addresses, MAC addresses, and IMEIs,
   replacing matches with typed placeholder tokens (e.g., `[REDACTED_EMAIL]`).
2. **Differential Privacy** (`apply_differential_privacy`): Applies the Laplace mechanism
   to numeric fields in `AnalysisResult` dicts, allowing operators to publish risk scores
   with tunable privacy guarantees.
3. **Pseudonymization** (`pseudonymize`): Produces HMAC-SHA256-keyed stable pseudonyms for
   sensitive strings, supporting cross-referencing without exposing original values.

Both pipelines now call `redact_pii(data)` immediately after ingestion, before any AI
analysis, ensuring that accidentally-included PII cannot propagate into reports or logs.

**Safety Controls:**
- RFC 5737 documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and all
  private/loopback ranges are explicitly excluded from IP redaction to avoid breaking
  synthetic test data.
- The Laplace noise implementation uses the inverse-CDF method with a numerically stable
  interior interval to avoid degenerate outputs.

**Risk Assessment:** Low. Privacy controls are additive and do not alter analytical logic.

---

## Change 4: Decentralized Reputation Networks

**Scope:** `ailee_core/reputation.py` (new)

**Description:**
A lightweight federated reputation query interface allows trusted NGOs to query shared
datasets of known mercenary infrastructure without centralizing the intelligence. Key features:
- **HMAC-SHA256 signed requests** using a shared secret exchanged out-of-band.
- **Constant-time signature verification** via `hmac.compare_digest` to resist timing attacks.
- **Graceful degradation**: if no peers are configured or all are unreachable, the pipeline
  continues with local-only analysis.
- Peer configuration loaded from the `SAF_REPUTATION_PEERS` environment variable (JSON array).

**Safety Controls:**
- No raw data is forwarded between peers; only the queried entity identifier and type are
  transmitted.
- Source peer names on response entries are always set by the querying node from its own
  configuration (not from self-reported peer data) to prevent spoofing.
- All HTTP requests use short timeouts (default: 5 s) and are wrapped in broad exception
  handlers to prevent peer failures from crashing the pipeline.

**Risk Assessment:** Low for the current release (no peers configured by default). Operators
who enable peer connections should conduct bilateral security reviews with each partner.

---

## Governance Board Sign-off

| Role | Name | Date |
|------|------|------|
| Technical Lead | *pending review* | *TBD* |
| Privacy Officer | *pending review* | *TBD* |
| Ethics Reviewer | *pending review* | *TBD* |
