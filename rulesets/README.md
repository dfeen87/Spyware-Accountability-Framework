# Defensive Rulesets

This directory contains examples of machine-readable defensive artifacts (YARA, Sigma, Suricata).

## ⚠️ STRICT WARNING: SYNTHETIC DATA ONLY ⚠️

The rules provided in this repository are **strictly synthetic examples**. They are designed to demonstrate the structure, syntax, and logic required to build defensive signatures against mercenary spyware infrastructure.

**Do not deploy these rules into production environments expecting them to catch real threats.** They use fake domains (`*.example-spyware.xyz`), fake IP spaces (`192.0.2.0/24`), and mock strings.

### Why Synthetic?

To maintain our human-rights alignment and defensive mandate, we do not publish live, actionable indicators of compromise (IOCs) or real exploit signatures in this public repository. Doing so could:
1. Tip off adversaries that their infrastructure has been burned.
2. Provide blueprints or "clean" code snippets for others to build upon.
3. Inadvertently expose the investigative methods of partner NGOs.

### How to use these examples

Defenders should use these files as templates. When your internal instance of the `spyware-accountability-framework` generates a verified IOC report (via the Reporting Pipeline), you can programmatically inject those real IOCs into these templates for your own private, local use.
