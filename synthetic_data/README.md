# Synthetic Datasets v2

This directory contains expanded synthetic datasets designed for testing and demonstrating the Spyware Accountability Framework's analytical pipelines.

## ⚠️ STRICT WARNING: SYNTHETIC DATA ONLY ⚠️

All files in this directory contain **fake, synthetic, and mocked data**. They use reserved IP spaces (e.g., `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and example domains (e.g., `*.example-spyware.xyz`).

**No real targets, vendors, or infrastructure are represented here.**

## Datasets

- `synthetic_network_flows_v2.json`: A simulated collection of network flow records, demonstrating patterns indicative of C2 beaconing and obfuscated communication channels, suitable for `pipelines/network_forensics_pipeline.py`.
- `synthetic_osint_entities_v2.json`: A mock OSINT database modeling shell companies, bulletproof hosting providers, and their associated infrastructure, suitable for `pipelines/osint_vendor_mapping_pipeline.py`.
- `synthetic_infrastructure_graph_v2.json`: A pre-computed relationship graph connecting the synthetic vendors, jurisdictions, domains, and hosting infrastructure.

These datasets provide a structurally rich environment for testing the AILEE-governed backend logic without touching live intelligence.