# VALIDATION — Spyware Accountability Framework v3

This document records the results of a full end-to-end simulation of the SAF v3 pipelines using the realistic synthetic datasets included in `synthetic_data/`. All simulation commands, inputs, outputs, and analysis findings are documented here for auditability and reproducibility.

**Simulation date:** 2026-03-01  
**Python version:** 3.12.3  
**Platform:** Linux x86-64

---

## 1. Synthetic Datasets Used

Two realistic synthetic datasets were prepared for this simulation. They model a multi-vendor mercenary spyware ecosystem with layered C2 infrastructure. All entities, domains, IP addresses, and corporate details are completely fabricated.

### 1.1 Network Telemetry — `synthetic_data/synthetic_network_flows_v3.json`

Eight network flows captured across four synthetic devices. The flows exhibit patterns characteristic of a commercial spyware implant: periodic low-volume heartbeat beacons, bulk data exfiltration sessions, implant update pulls, and command-and-control polling — all using encrypted HTTPS on standard and non-standard ports.

| Flow ID | Source Device | Destination Domain | Port | Pattern | Notes |
|---------|--------------|-------------------|------|---------|-------|
| f-001 | `10.0.1.42` (mobile) | `api.auth.example-spyware.xyz` | 443 | Beacon (300 s interval) | 256 B sent / 1 KB recv — heartbeat |
| f-002 | `10.0.1.42` (mobile) | `ingest.telemetry.example-spyware.xyz` | 443 | Exfil (1800 s interval) | 85 KB sent / 512 B recv — data upload |
| f-003 | `10.0.2.11` (laptop) | `update.sys.example-vendor.com` | 443 | Update pull (4 h interval) | 5 KB sent / 200 KB recv — payload download |
| f-004 | `10.0.3.77` (mobile) | `api.auth.example-spyware.xyz` | 443 | Beacon (300 s interval) | Second device, same C2 — cluster indicator |
| f-005 | `10.0.3.77` (mobile) | `cmd.c2.example-spyware.xyz` | 8443 | C2 poll (600 s interval) | Non-standard port; 1 KB sent / 44 KB recv |
| f-006 | `10.0.1.42` (mobile) | `relay.proxy.example-spyware.xyz` | 443 | Relay burst (one-shot) | Symmetric 4 KB traffic; single burst session |
| f-007 | `10.0.4.22` (laptop) | `legitimate-cdn-example.org` | 80 | Normal web browsing | Baseline control flow — no indicators |
| f-008 | `10.0.5.103` (mobile) | `update.sys.example-vendor.com` | 443 | Update pull (4 h interval) | Third device pulling from same update endpoint |

**TLS fingerprints observed:**

| Fingerprint (SHA-256) | Seen in flows | Interpretation |
|-----------------------|--------------|----------------|
| `1f8e134b2c019d675317767425ba12f32a2455f52a8a5b6c738e412e12891d4e` | f-001, f-004 | Beacon C2 certificate |
| `2a9f04711c3e56a1847a33c1228e4c9f9e5372116a3d2c5b7413e524f99012ab` | f-002 | Exfil endpoint certificate |
| `8b5f3a1e2f3d4c5b6a79889706152433445566778899aabbccddeeff00112233` | f-003, f-008 | Update server certificate |
| `3c7d92a0f451e8b31229dfee5c04a7b8d6f3291e0a5c48f7b9d012e673ac4501` | f-005 | C2 command channel certificate |
| `5e8a1c0374d2fa96b154728e3f0a5c92d7481b0623d569c18427e0ab1f9d8200` | f-006 | Relay proxy certificate |

### 1.2 OSINT Entities — `synthetic_data/synthetic_osint_entities_v3.json`

Three synthetic vendor entities, three hosting providers, and five domains form the OSINT picture of the spyware ecosystem. Corporate ownership links connect the vendors in a parent/subsidiary/shell-company structure.

**Vendors:**

| ID | Name | Jurisdiction | Status | Notes |
|----|------|-------------|--------|-------|
| v-001 | Apex Security Holdings | `suspicious_jurisdiction` | Active | Parent entity; offshore registration; minimal disclosure |
| v-002 | Global Surveillance Technologies | `example_jurisdiction_b` | Dormant | Subsidiary; historically operated delivery infrastructure |
| v-003 | SecureOps Intelligence LLC | `offshore_jurisdiction_c` | Active | Shell company; shares registered agent with v-001 |

**Corporate links:** v-001 owns v-003 (`OWNS_SUBSIDIARY`); v-001 controls v-002 via directorship (`CONTROLS_VIA_DIRECTOR`); v-003 shares registered agent with v-002 (`SHARES_REGISTERED_AGENT`).

**Hosting providers:**

| ID | Name | ASN | Country | Abuse handling |
|----|------|-----|---------|---------------|
| h-001 | Bulletproof Hosting Inc. | AS64496 | `example_country_1` | None — ignores takedown notices |
| h-002 | Cloud Infra LLC | AS64511 | `example_country_2` | Minimal — `abuse@cloudinfra.example` |
| h-003 | ShieldNet Datacenter | AS65000 | `example_country_3` | None — no-log datacenter; advertises anonymity |

**Domains:**

| Domain | Registered by | Hosted on | Registration date |
|--------|--------------|-----------|------------------|
| `api.auth.example-spyware.xyz` | v-001 | h-001 | 2022-01-10 |
| `ingest.telemetry.example-spyware.xyz` | v-001 | h-001 | 2022-01-10 |
| `cmd.c2.example-spyware.xyz` | v-003 | h-001 | 2022-04-18 |
| `relay.proxy.example-spyware.xyz` | v-003 | h-003 | 2022-06-02 |
| `update.sys.example-vendor.com` | v-002 | h-002 | 2021-09-15 |

**PII in dataset:** The v3 OSINT dataset includes a synthetic contact email (`info@apexsecholdings.example`) on vendor v-001. The privacy overlay (`ailee_core/privacy.py`) automatically redacted this value before it reached the analysis stage — confirmed by the `WARNING - PII detected and redacted` log entries during Stage 2 execution below.

---

## 2. Simulation — Stage 1: Network Forensics Pipeline

### 2.1 Command

```bash
python -m pipelines.network_forensics_pipeline \
  --input  synthetic_data/synthetic_network_flows_v3.json \
  --output /tmp/saf_sim_v3/network_report.json
```

### 2.2 Runtime Log

```
INFO  - Starting Network Forensics Pipeline with input: synthetic_data/synthetic_network_flows_v3.json
INFO  - AI Classification: SUSPICIOUS_BEACON
INFO  - Confidence: 0.92, Risk: 8.5
INFO  - Analysis passed AILEE policy gate. Generating actionable report.
INFO  - Pipeline complete. Report written to /tmp/saf_sim_v3/network_report.json
```

### 2.3 Full Output — `network_report.json`

```json
{
    "status": "ACTIONABLE",
    "findings": {
        "classification_label": "SUSPICIOUS_BEACON",
        "confidence_score": 0.92,
        "risk_score": 8.5,
        "explanation": "Matched synthetic spyware domain.",
        "metadata": {
            "matched_domains": [
                "api.auth.example-spyware.xyz",
                "ingest.telemetry.example-spyware.xyz",
                "api.auth.example-spyware.xyz",
                "cmd.c2.example-spyware.xyz",
                "relay.proxy.example-spyware.xyz"
            ]
        }
    },
    "extracted_iocs": [
        "api.auth.example-spyware.xyz",
        "ingest.telemetry.example-spyware.xyz",
        "update.sys.example-vendor.com",
        "api.auth.example-spyware.xyz",
        "cmd.c2.example-spyware.xyz",
        "relay.proxy.example-spyware.xyz",
        "update.sys.example-vendor.com",
        "1f8e134b2c019d675317767425ba12f32a2455f52a8a5b6c738e412e12891d4e",
        "2a9f04711c3e56a1847a33c1228e4c9f9e5372116a3d2c5b7413e524f99012ab",
        "8b5f3a1e2f3d4c5b6a79889706152433445566778899aabbccddeeff00112233",
        "1f8e134b2c019d675317767425ba12f32a2455f52a8a5b6c738e412e12891d4e",
        "3c7d92a0f451e8b31229dfee5c04a7b8d6f3291e0a5c48f7b9d012e673ac4501",
        "5e8a1c0374d2fa96b154728e3f0a5c92d7481b0623d569c18427e0ab1f9d8200",
        "8b5f3a1e2f3d4c5b6a79889706152433445566778899aabbccddeeff00112233"
    ]
}
```

### 2.4 Analysis

**AILEE policy gate:** PASSED — confidence 0.92 >= 0.85, risk 8.5 >= 7.0 -> `ACTIONABLE`

The `SyntheticNetworkModelStub` matched **five** distinct `.example-spyware.xyz` flows across the eight total flows in the dataset. The two update flows (f-003, f-008 to `update.sys.example-vendor.com`) are included in the IOC list as network indicators but did not contribute to the `SUSPICIOUS_BEACON` classification since the stub classifies on `.example-spyware.xyz` suffix matches. Flow f-007 (`legitimate-cdn-example.org`) was correctly excluded from the IOC list.

**IOC observations:**
- Several domains and TLS fingerprints appear more than once in the raw IOC list because they were observed in multiple distinct flows (e.g., `api.auth.example-spyware.xyz` in both f-001 and f-004; TLS fingerprint `1f8e134b...` in both f-001 and f-004). This is expected behavior: the pipeline extracts one entry per flow, and deduplication is left to downstream consumers.
- A total of 5 unique `.xyz` C2 domains and 5 unique TLS fingerprints were extracted from the 8 input flows.
- The beacon cluster (two separate devices, f-001 and f-004, hitting the same `api.auth.example-spyware.xyz` C2 at the same 5-minute interval with the same TLS certificate) is a strong spyware deployment indicator.

---

## 3. Simulation — Stage 2: OSINT Vendor Mapping Pipeline

### 3.1 Command

```bash
python -m pipelines.osint_vendor_mapping_pipeline \
  --input  synthetic_data/synthetic_osint_entities_v3.json \
  --output /tmp/saf_sim_v3/osint_report.json
```

### 3.2 Runtime Log

```
INFO    - Starting OSINT Vendor Mapping Pipeline with input: synthetic_data/synthetic_osint_entities_v3.json
INFO    - Loaded OSINT dataset: 3 vendors.
WARNING - PII detected and redacted from input data.
WARNING - PII detected and redacted from input data.
INFO    - AI Classification: MERCENARY_INFRASTRUCTURE
INFO    - Confidence: 0.88, Risk: 9.0
INFO    - Analysis passed AILEE policy gate. Creating relationship graph representation.
INFO    - Graph analytics: {'node_count': 14, 'edge_count': 22, 'num_weakly_connected_components': 1, 'largest_component_size': 14, 'top_nodes_by_centrality': ['v-001', 'v-003', 'h-001']}
INFO    - Pipeline complete. Graph report written to /tmp/saf_sim_v3/osint_report.json
```

The two `WARNING - PII detected and redacted` lines confirm that the privacy overlay correctly identified and removed the synthetic email address present in vendor v-001's record before any AI analysis took place.

### 3.3 Full Output — `osint_report.json`

```json
{
    "status": "ACTIONABLE",
    "findings": {
        "classification_label": "MERCENARY_INFRASTRUCTURE",
        "confidence_score": 0.88,
        "risk_score": 9.0,
        "explanation": "Vendor registered in a known high-risk or offshore jurisdiction. | Infrastructure hosted by a provider flagged as bulletproof hosting.",
        "metadata": {
            "flagged_entities": []
        }
    },
    "graph": {
        "nodes": [
            {"id": "v-001", "label": "Apex Security Holdings",            "type": "Vendor"},
            {"id": "j-suspicious_jurisdiction",  "label": "suspicious_jurisdiction",  "type": "Jurisdiction"},
            {"id": "v-002", "label": "Global Surveillance Technologies",   "type": "Vendor"},
            {"id": "j-example_jurisdiction_b",   "label": "example_jurisdiction_b",   "type": "Jurisdiction"},
            {"id": "v-003", "label": "SecureOps Intelligence LLC",         "type": "Vendor"},
            {"id": "j-offshore_jurisdiction_c",  "label": "offshore_jurisdiction_c",  "type": "Jurisdiction"},
            {"id": "h-001", "label": "Bulletproof Hosting Inc.",           "type": "Infrastructure"},
            {"id": "h-002", "label": "Cloud Infra LLC",                    "type": "Infrastructure"},
            {"id": "h-003", "label": "ShieldNet Datacenter",               "type": "Infrastructure"},
            {"id": "d-api.auth.example-spyware.xyz",
             "label": "api.auth.example-spyware.xyz",               "type": "Domain"},
            {"id": "d-ingest.telemetry.example-spyware.xyz",
             "label": "ingest.telemetry.example-spyware.xyz",       "type": "Domain"},
            {"id": "d-cmd.c2.example-spyware.xyz",
             "label": "cmd.c2.example-spyware.xyz",                 "type": "Domain"},
            {"id": "d-relay.proxy.example-spyware.xyz",
             "label": "relay.proxy.example-spyware.xyz",            "type": "Domain"},
            {"id": "d-update.sys.example-vendor.com",
             "label": "update.sys.example-vendor.com",              "type": "Domain"}
        ],
        "edges": [
            {"source": "v-001", "target": "j-suspicious_jurisdiction",               "label": "REGISTERED_IN"},
            {"source": "v-002", "target": "j-example_jurisdiction_b",                "label": "REGISTERED_IN"},
            {"source": "v-003", "target": "j-offshore_jurisdiction_c",               "label": "REGISTERED_IN"},
            {"source": "v-001", "target": "h-001",                                   "label": "HOSTS_WITH"},
            {"source": "v-002", "target": "h-001",                                   "label": "HOSTS_WITH"},
            {"source": "v-003", "target": "h-001",                                   "label": "HOSTS_WITH"},
            {"source": "v-001", "target": "h-002",                                   "label": "HOSTS_WITH"},
            {"source": "v-002", "target": "h-002",                                   "label": "HOSTS_WITH"},
            {"source": "v-003", "target": "h-002",                                   "label": "HOSTS_WITH"},
            {"source": "v-001", "target": "h-003",                                   "label": "HOSTS_WITH"},
            {"source": "v-002", "target": "h-003",                                   "label": "HOSTS_WITH"},
            {"source": "v-003", "target": "h-003",                                   "label": "HOSTS_WITH"},
            {"source": "v-001", "target": "d-api.auth.example-spyware.xyz",          "label": "OWNS_DOMAIN"},
            {"source": "d-api.auth.example-spyware.xyz", "target": "h-001",          "label": "RESOLVES_TO"},
            {"source": "v-001", "target": "d-ingest.telemetry.example-spyware.xyz",  "label": "OWNS_DOMAIN"},
            {"source": "d-ingest.telemetry.example-spyware.xyz", "target": "h-001",  "label": "RESOLVES_TO"},
            {"source": "v-003", "target": "d-cmd.c2.example-spyware.xyz",            "label": "OWNS_DOMAIN"},
            {"source": "d-cmd.c2.example-spyware.xyz", "target": "h-001",            "label": "RESOLVES_TO"},
            {"source": "v-003", "target": "d-relay.proxy.example-spyware.xyz",       "label": "OWNS_DOMAIN"},
            {"source": "d-relay.proxy.example-spyware.xyz", "target": "h-003",       "label": "RESOLVES_TO"},
            {"source": "v-002", "target": "d-update.sys.example-vendor.com",         "label": "OWNS_DOMAIN"},
            {"source": "d-update.sys.example-vendor.com", "target": "h-002",         "label": "RESOLVES_TO"}
        ],
        "analytics": {
            "node_count": 14,
            "edge_count": 22,
            "num_weakly_connected_components": 1,
            "largest_component_size": 14,
            "top_nodes_by_centrality": ["v-001", "v-003", "h-001"]
        }
    }
}
```

### 3.4 Analysis

**AILEE policy gate:** PASSED — confidence 0.88 >= 0.85, risk 9.0 >= 7.0 -> `ACTIONABLE`

**Graph topology:**

The resulting graph has **14 nodes** and **22 directed edges** forming a **single weakly-connected component** — meaning the entire observed infrastructure is reachable from any single entry point. This is a strong indicator of a tightly coordinated operation rather than unrelated independent actors.

Node breakdown:
- 3 vendor nodes (v-001, v-002, v-003)
- 3 jurisdiction nodes
- 3 hosting provider nodes (h-001, h-002, h-003)
- 5 domain nodes

**Top nodes by degree centrality:** `v-001` (Apex Security Holdings), `v-003` (SecureOps Intelligence LLC), `h-001` (Bulletproof Hosting Inc.).

- `v-001` has the highest centrality because it is the parent entity linked to the offshore jurisdiction, two hosting providers, and two directly-owned domains.
- `h-001` (Bulletproof Hosting Inc.) is a critical hub: it hosts domains registered by all three vendor entities and has no abuse-contact handling.
- `v-003` (SecureOps Intelligence LLC, the offshore shell) controls the C2 (`cmd.c2.example-spyware.xyz`) and relay proxy infrastructure, acting as operational insulation for the parent entity.

**Classification triggers (dual):**
1. `v-001` registered in `suspicious_jurisdiction` — jurisdiction heuristic fired
2. `h-001` name contains `"bulletproof"` — bulletproof hosting heuristic fired

Both heuristics are implemented as case-insensitive substring checks in `SyntheticOSINTModelStub.analyze()`.

---

## 4. Simulation — Stage 3: Reporting Pipeline

### 4.1 Command

```bash
python -m pipelines.reporting_pipeline \
  --network-report /tmp/saf_sim_v3/network_report.json \
  --osint-graph    /tmp/saf_sim_v3/osint_report.json \
  --output-dir     /tmp/saf_sim_v3/report
```

### 4.2 Runtime Log

```
INFO - Starting Reporting Pipeline...
INFO - Generating defensive intelligence brief...
INFO - Brief successfully written to /tmp/saf_sim_v3/report/defensive_brief.md
INFO - Machine-readable IOCs written to /tmp/saf_sim_v3/report/actionable_iocs.json
```

### 4.3 Outputs Generated

Two artifacts were produced in `/tmp/saf_sim_v3/report/`:

**`defensive_brief.md`** — Human-readable Markdown intelligence brief. Key fields:

| Field | Value |
|-------|-------|
| Status line | `Critical Alert: Spyware Ecosystem Mapped` |
| Network confidence | 0.92 |
| Network risk score | 8.5 |
| Network classification | `SUSPICIOUS_BEACON` |
| OSINT confidence | 0.88 |
| OSINT risk score | 9.0 |
| OSINT classification | `MERCENARY_INFRASTRUCTURE` |

**`actionable_iocs.json`** — Machine-readable IOC list (raw, pre-deduplication):

```json
{
    "verified_iocs": [
        "api.auth.example-spyware.xyz",
        "ingest.telemetry.example-spyware.xyz",
        "update.sys.example-vendor.com",
        "api.auth.example-spyware.xyz",
        "cmd.c2.example-spyware.xyz",
        "relay.proxy.example-spyware.xyz",
        "update.sys.example-vendor.com",
        "1f8e134b2c019d675317767425ba12f32a2455f52a8a5b6c738e412e12891d4e",
        "2a9f04711c3e56a1847a33c1228e4c9f9e5372116a3d2c5b7413e524f99012ab",
        "8b5f3a1e2f3d4c5b6a79889706152433445566778899aabbccddeeff00112233",
        "1f8e134b2c019d675317767425ba12f32a2455f52a8a5b6c738e412e12891d4e",
        "3c7d92a0f451e8b31229dfee5c04a7b8d6f3291e0a5c48f7b9d012e673ac4501",
        "5e8a1c0374d2fa96b154728e3f0a5c92d7481b0623d569c18427e0ab1f9d8200",
        "8b5f3a1e2f3d4c5b6a79889706152433445566778899aabbccddeeff00112233"
    ]
}
```

**Unique IOCs (after deduplication):**

| Type | Value |
|------|-------|
| Domain | `api.auth.example-spyware.xyz` |
| Domain | `ingest.telemetry.example-spyware.xyz` |
| Domain | `cmd.c2.example-spyware.xyz` |
| Domain | `relay.proxy.example-spyware.xyz` |
| Domain | `update.sys.example-vendor.com` |
| TLS fingerprint | `1f8e134b2c019d675317767425ba12f32a2455f52a8a5b6c738e412e12891d4e` |
| TLS fingerprint | `2a9f04711c3e56a1847a33c1228e4c9f9e5372116a3d2c5b7413e524f99012ab` |
| TLS fingerprint | `8b5f3a1e2f3d4c5b6a79889706152433445566778899aabbccddeeff00112233` |
| TLS fingerprint | `3c7d92a0f451e8b31229dfee5c04a7b8d6f3291e0a5c48f7b9d012e673ac4501` |
| TLS fingerprint | `5e8a1c0374d2fa96b154728e3f0a5c92d7481b0623d569c18427e0ab1f9d8200` |

**Total unique IOCs: 10** (5 domains, 5 TLS fingerprints).

### 4.4 Infrastructure Graph — Visual Summary (from defensive brief)

```
[Apex Security Holdings]               --(REGISTERED_IN)--> [suspicious_jurisdiction]
[Global Surveillance Technologies]     --(REGISTERED_IN)--> [example_jurisdiction_b]
[SecureOps Intelligence LLC]           --(REGISTERED_IN)--> [offshore_jurisdiction_c]
[Apex Security Holdings]               --(HOSTS_WITH)-----> [Bulletproof Hosting Inc.]
[Global Surveillance Technologies]     --(HOSTS_WITH)-----> [Bulletproof Hosting Inc.]
[SecureOps Intelligence LLC]           --(HOSTS_WITH)-----> [Bulletproof Hosting Inc.]
[Apex Security Holdings]               --(HOSTS_WITH)-----> [Cloud Infra LLC]
[Global Surveillance Technologies]     --(HOSTS_WITH)-----> [Cloud Infra LLC]
[SecureOps Intelligence LLC]           --(HOSTS_WITH)-----> [Cloud Infra LLC]
[Apex Security Holdings]               --(HOSTS_WITH)-----> [ShieldNet Datacenter]
[Global Surveillance Technologies]     --(HOSTS_WITH)-----> [ShieldNet Datacenter]
[SecureOps Intelligence LLC]           --(HOSTS_WITH)-----> [ShieldNet Datacenter]
[Apex Security Holdings]               --(OWNS_DOMAIN)----> [api.auth.example-spyware.xyz]
[api.auth.example-spyware.xyz]         --(RESOLVES_TO)----> [Bulletproof Hosting Inc.]
[Apex Security Holdings]               --(OWNS_DOMAIN)----> [ingest.telemetry.example-spyware.xyz]
[ingest.telemetry.example-spyware.xyz] --(RESOLVES_TO)----> [Bulletproof Hosting Inc.]
[SecureOps Intelligence LLC]           --(OWNS_DOMAIN)----> [cmd.c2.example-spyware.xyz]
[cmd.c2.example-spyware.xyz]           --(RESOLVES_TO)----> [Bulletproof Hosting Inc.]
[SecureOps Intelligence LLC]           --(OWNS_DOMAIN)----> [relay.proxy.example-spyware.xyz]
[relay.proxy.example-spyware.xyz]      --(RESOLVES_TO)----> [ShieldNet Datacenter]
[Global Surveillance Technologies]     --(OWNS_DOMAIN)----> [update.sys.example-vendor.com]
[update.sys.example-vendor.com]        --(RESOLVES_TO)----> [Cloud Infra LLC]
```

---

## 5. Test Suite Results

All 54 automated tests pass without modification on Python 3.12.3.

```
tests/test_graph_analytics.py               10 passed
tests/test_live_backends.py                  8 passed
tests/test_network_forensics_pipeline.py     2 passed
tests/test_osint_vendor_mapping_pipeline.py  2 passed
tests/test_privacy.py                       17 passed
tests/test_reporting_pipeline.py             2 passed
tests/test_reputation.py                    13 passed
------------------------------------------------------
TOTAL                                       54 passed
```

---

## 6. Privacy Overlay Verification

The privacy module (`ailee_core/privacy.py`) applies automatic PII redaction before any data reaches the AI analysis stage. During the Stage 2 run above, two `WARNING - PII detected and redacted` log entries were emitted because the v3 OSINT dataset includes a synthetic contact email address (`info@apexsecholdings.example`) on vendor v-001. The email was matched by the `_PII_PATTERNS` email regex and replaced with `[REDACTED_EMAIL]` before the dict was passed to `SyntheticOSINTModelStub.analyze()`.

This confirms that even if a real analyst accidentally includes personally identifiable contact details in an OSINT record, the framework's privacy overlay prevents that data from appearing in AI inputs, pipeline outputs, or generated reports.

---

## 7. Simulation Summary

| Item | Result |
|------|--------|
| Input dataset — network flows | 8 flows across 4 devices; 7 flows with TLS/domain indicators |
| Input dataset — OSINT entities | 3 vendors, 3 hosting providers, 5 domains, 3 corporate links |
| Test suite | 54 passed / 0 failed |
| Network pipeline status | `SUSPICIOUS_BEACON` — **ACTIONABLE** |
| Network pipeline confidence | 0.92 (threshold: 0.85) PASSED |
| Network pipeline risk score | 8.5 (threshold: 7.0) PASSED |
| OSINT pipeline status | `MERCENARY_INFRASTRUCTURE` — **ACTIONABLE** |
| OSINT pipeline confidence | 0.88 (threshold: 0.85) PASSED |
| OSINT pipeline risk score | 9.0 (threshold: 7.0) PASSED |
| Graph: nodes / edges | 14 / 22 |
| Graph: connected components | 1 (fully connected — single ecosystem) |
| Graph: highest-centrality nodes | v-001 (Apex Security Holdings), v-003 (SecureOps Intelligence LLC), h-001 (Bulletproof Hosting Inc.) |
| Unique IOCs extracted | 10 (5 domains + 5 TLS fingerprints) |
| PII redaction triggered | Yes — 2 values redacted before AI analysis |
| Report artifacts generated | `defensive_brief.md` + `actionable_iocs.json` |
| End-to-end pipeline | All three stages completed without errors |

> **Ethical note:** All data processed in this simulation is fully synthetic (`"is_synthetic": true` in every record). No real personal data, real IP addresses, real domain names, or real infrastructure is referenced anywhere in these datasets or outputs. The Spyware Accountability Framework is designed exclusively for defensive research and human-rights accountability work. Do not use it for offensive purposes.
