# Synthetic Network Capture Analyst Notes

**Incident ID:** SYN-2024-001
**Date:** 2024-03-01
**Analyst:** Demo User

## Context
During routine monitoring of a secure research environment (VLAN 50), anomalous outbound connections were detected originating from an isolated testing VM.

## Extracted Features

We extracted the following features from the PCAP. Note that these are purely synthetic domains and mock hashes, designed for testing the pipeline.

### Suspicious Domains Queried
- `update.example-spyware.xyz`
- `c2.example-spyware.xyz`
- `benign-looking-domain.com`

### Observed TLS Fingerprints (JA3)
- `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- `ab98765432101234567890abcdef1234567890abcdef1234567890abcdef1234`

### Analyst Notes
The beacon interval appears to be highly randomized, with jitter between 45s and 180s. The TLS fingerprint matches a signature previously associated (synthetically) with a known adversary infrastructure builder.
