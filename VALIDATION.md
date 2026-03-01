# VALIDATION — Spyware Accountability Framework v3

This document records the deep code review performed on the SAF v3 codebase and the results of a full end-to-end simulation using the included synthetic datasets. All findings, fixes, and simulation outputs are documented here for auditability and reproducibility.

---

## 1. Deep Code Review

### 1.1 Review Scope

All Python source files were reviewed:

| File | Description |
|------|-------------|
| `ailee_core/interfaces.py` | Pydantic models & Protocol interfaces |
| `ailee_core/models_stub.py` | Deterministic stub AI models |
| `ailee_core/privacy.py` | PII redaction & differential privacy |
| `ailee_core/reputation.py` | Federated reputation network |
| `ailee_core/backends/classifier_backend.py` | Live ML classifier backend |
| `ailee_core/backends/llm_backend.py` | Live LLM backend |
| `ailee_core/backends/osint_semantic_backend.py` | Graph analytics backend |
| `pipelines/network_forensics_pipeline.py` | Network forensics pipeline |
| `pipelines/osint_vendor_mapping_pipeline.py` | OSINT vendor mapping pipeline |
| `pipelines/reporting_pipeline.py` | Report generation pipeline |

### 1.2 Bugs Found & Fixed

#### Bug 1 — `SyntheticOSINTModelStub` pattern mismatch (misclassification)

**File:** `ailee_core/models_stub.py`  
**Severity:** High — caused the OSINT pipeline to always return `STANDARD_CORPORATE` for the provided synthetic dataset.

**Root cause:** `SyntheticOSINTModelStub.analyze()` only matched two exact hard-coded strings (`"FakeSpywareCorp LLC"`, `"BulletproofHosting Example"`). The actual synthetic dataset `synthetic_osint_entities_v2.json` uses different names (`"Apex Security Holdings"` registered in `"suspicious_jurisdiction"`, `"Bulletproof Hosting Inc."`), so the model stub never triggered its mercenary detection path.

**Fix:** Extended the detection heuristics to also match:
- Vendors registered in a jurisdiction containing `"suspicious_jurisdiction"` or `"offshore"` (case-insensitive)
- Hosting providers whose name contains `"bulletproof"` (case-insensitive)

This makes the stub properly general while fully preserving existing test coverage (all 54 tests continue to pass).

#### Bug 2 — `KeyError` risk on `vendor["id"]` and `host["id"]`

**File:** `pipelines/osint_vendor_mapping_pipeline.py` (graph construction block)  
**Severity:** Medium — would raise `KeyError` at runtime if any vendor or hosting-provider dict lacked an `"id"` key.

**Root cause:** The graph construction loop used `vendor["id"]` and `host["id"]` with bare key access. The equivalent logic in `osint_semantic_backend.py` already uses `.get("id", .get("name", "unknown_..."))` safely.

**Fix:** Replaced all bare key accesses with `.get()` chains, consistent with the defensive pattern already used in `osint_semantic_backend.py`:
```python
vid = vendor.get("id", vendor.get("name", "unknown_vendor"))
hid = host.get("id", host.get("name", "unknown_host"))
```
Also replaced `vendor["name"]` and `host["name"]` in the same block with `.get()` for the same reason.

#### Bug 3 — Hardcoded relative path for the report template

**File:** `pipelines/reporting_pipeline.py`  
**Severity:** Low — the pipeline failed with a `FileNotFoundError` when invoked from any working directory other than the repository root.

**Root cause:** `template_path = "reports/templates/brief_template.md"` is a bare relative path resolved against the current working directory (CWD) at runtime.

**Fix:** Replaced with a path resolved relative to the module's own location, making it CWD-independent:
```python
template_path = Path(__file__).resolve().parent.parent / "reports" / "templates" / "brief_template.md"
```

### 1.3 No-action Observations

The following points were noted during review but required no code change:

| Observation | Decision |
|-------------|----------|
| `hmac.new(key, msg, digestmod)` used in `privacy.py` and `reputation.py` | Correct Python 3 API; not deprecated. |
| `logging.info(f"...")` f-string style throughout pipelines | Functionally correct; lazy evaluation is not required here. |
| `SyntheticNetworkModelStub` / `SyntheticOSINTModelStub` inherit directly from `Protocol` classes | Accepted Python pattern for explicit protocol registration; mypy handles it correctly. |
| IMEI regex `\b\d{15}\b` may over-match non-IMEI 15-digit strings | Accepted conservative design decision for a safety-oriented tool. |
| `extract_features_from_markdown` domain extraction is simple (split+endswith) | Intentional stub — documented in comments; sufficient for synthetic testing. |
| `apply_differential_privacy` Laplace inverse-CDF implementation | Mathematically verified correct: `X = −b·sign(u)·ln(1−2|u|)`, `u ~ Uniform(−0.5, 0.5)`. |
| `generate_brief` returns `None` silently on missing template | Intentional graceful degradation; error is logged. |

---

## 2. Test Suite Results

The repository ships with 54 automated tests. All pass on Python 3.12.3 after the fixes above.

```
tests/test_graph_analytics.py             10 passed
tests/test_live_backends.py               8  passed
tests/test_network_forensics_pipeline.py  2  passed
tests/test_osint_vendor_mapping_pipeline.py 2 passed
tests/test_privacy.py                     17 passed
tests/test_reporting_pipeline.py          2  passed
tests/test_reputation.py                  13 passed
─────────────────────────────────────────────────────
TOTAL                                     54 passed
```

---

## 3. End-to-End Simulation

The full three-stage pipeline was executed against the synthetic datasets included in `synthetic_data/`.

### 3.1 Stage 1 — Network Forensics Pipeline

**Command:**
```bash
python -m pipelines.network_forensics_pipeline \
  --input  synthetic_data/synthetic_network_flows_v2.json \
  --output /tmp/saf_sim/network_report.json
```

**Input highlights** (`synthetic_network_flows_v2.json`):
- 3 synthetic network flows
- Flow 1: domain `api.auth.example-spyware.xyz`, TLS fingerprint `1f8e134b...`, 300 s beacon interval → matches `.example-spyware.xyz` indicator
- Flow 2: domain `update.sys.example-vendor.com`, TLS fingerprint `8b5f3a1e...`
- Flow 3: HTTP to `legitimate-example-service.org` (benign)

**Output:**
```json
{
  "status": "ACTIONABLE",
  "findings": {
    "classification_label": "SUSPICIOUS_BEACON",
    "confidence_score": 0.92,
    "risk_score": 8.5,
    "explanation": "Matched synthetic spyware domain.",
    "metadata": { "matched_domains": ["api.auth.example-spyware.xyz"] }
  },
  "extracted_iocs": [
    "api.auth.example-spyware.xyz",
    "update.sys.example-vendor.com",
    "1f8e134b2c019d675317767425ba12f32a2455f52a8a5b6c738e412e12891d4e",
    "8b5f3a1e2f3d4c5b6a79889706152433445566778899aabbccddeeff00112233"
  ]
}
```

**AILEE policy gate:** ✅ PASSED — confidence 0.92 ≥ 0.85, risk 8.5 ≥ 7.0 → `ACTIONABLE`

---

### 3.2 Stage 2 — OSINT Vendor Mapping Pipeline

**Command:**
```bash
python -m pipelines.osint_vendor_mapping_pipeline \
  --input  synthetic_data/synthetic_osint_entities_v2.json \
  --output /tmp/saf_sim/osint_report.json
```

**Input highlights** (`synthetic_osint_entities_v2.json`):
- 2 vendors: `Apex Security Holdings` (jurisdiction: `suspicious_jurisdiction`), `Global Surveillance Technologies`
- 2 hosting providers: `Bulletproof Hosting Inc.`, `Cloud Infra LLC`
- 2 domains: `api.auth.example-spyware.xyz`, `update.sys.example-vendor.com`

**Output (abridged):**
```json
{
  "status": "ACTIONABLE",
  "findings": {
    "classification_label": "MERCENARY_INFRASTRUCTURE",
    "confidence_score": 0.88,
    "risk_score": 9.0,
    "explanation": "Vendor registered in a known high-risk or offshore jurisdiction. | Infrastructure hosted by a provider flagged as bulletproof hosting."
  },
  "graph": {
    "analytics": {
      "node_count": 8,
      "edge_count": 10,
      "num_weakly_connected_components": 1,
      "largest_component_size": 8,
      "top_nodes_by_centrality": ["v-001", "v-002", "h-001"]
    }
  }
}
```

**AILEE policy gate:** ✅ PASSED — confidence 0.88 ≥ 0.85, risk 9.0 ≥ 7.0 → `ACTIONABLE`

**Graph topology:** 8 nodes (2 vendors, 2 jurisdictions, 2 hosting providers, 2 domains), 10 directed edges forming a single weakly-connected component. Both vendors (`v-001`, `v-002`) and `h-001` are the highest-centrality nodes.

---

### 3.3 Stage 3 — Reporting Pipeline

**Command:**
```bash
python -m pipelines.reporting_pipeline \
  --network-report /tmp/saf_sim/network_report.json \
  --osint-graph    /tmp/saf_sim/osint_report.json \
  --output-dir     /tmp/saf_sim/report
```

**Outputs generated:**
- `defensive_brief.md` — human-readable Markdown intelligence brief
- `actionable_iocs.json` — machine-readable IOC list

**Brief status line:** `Critical Alert: Spyware Ecosystem Mapped`  
**IOCs verified:** 4 (2 domains, 2 TLS fingerprints)

**Infrastructure graph (visual summary from brief):**
```
[Apex Security Holdings]             --(REGISTERED_IN)--> [suspicious_jurisdiction]
[Global Surveillance Technologies]   --(REGISTERED_IN)--> [example_jurisdiction_b]
[Apex Security Holdings]             --(HOSTS_WITH)-----> [Bulletproof Hosting Inc.]
[Global Surveillance Technologies]   --(HOSTS_WITH)-----> [Bulletproof Hosting Inc.]
[Apex Security Holdings]             --(HOSTS_WITH)-----> [Cloud Infra LLC]
[Global Surveillance Technologies]   --(HOSTS_WITH)-----> [Cloud Infra LLC]
[Apex Security Holdings]             --(OWNS_DOMAIN)----> [api.auth.example-spyware.xyz]
[api.auth.example-spyware.xyz]       --(RESOLVES_TO)----> [Bulletproof Hosting Inc.]
[Global Surveillance Technologies]   --(OWNS_DOMAIN)----> [update.sys.example-vendor.com]
[update.sys.example-vendor.com]      --(RESOLVES_TO)----> [Cloud Infra LLC]
```

---

## 4. Summary

| Item | Result |
|------|--------|
| Bugs found | 3 |
| Bugs fixed | 3 |
| Tests before fixes | 54 passed / 0 failed |
| Tests after fixes | 54 passed / 0 failed |
| End-to-end simulation | ✅ All three pipeline stages complete successfully |
| Network pipeline verdict | `SUSPICIOUS_BEACON` — ACTIONABLE (confidence 0.92, risk 8.5) |
| OSINT pipeline verdict | `MERCENARY_INFRASTRUCTURE` — ACTIONABLE (confidence 0.88, risk 9.0) |
| Report generated | Defensive brief + IOC list produced without errors |

> **Ethical note:** All data processed above is fully synthetic (`"is_synthetic": true` in every dataset). No real personal data, real IP addresses, or real infrastructure is referenced. The framework is designed exclusively for defensive research and human-rights accountability work.
