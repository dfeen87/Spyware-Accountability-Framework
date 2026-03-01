# Threat Model

The Spyware Accountability Framework operates within a highly sensitive and adversarial environment. Understanding our adversaries and defining explicit boundaries on our capabilities is critical to ensuring our work remains defensive and human-rights-aligned.

## 👥 Adversaries
We explicitly model defense against:
1. **Mercenary Spyware Vendors:** Organizations that develop, sell, and sometimes operate advanced offensive capabilities against civil society.
2. **Abusive Operators/Client States:** Entities that deploy spyware to target journalists, activists, political dissidents, and NGOs.
3. **Infrastructure Providers:** Entities knowingly or unknowingly hosting spyware command-and-control (C2) or delivery infrastructure.

## 🛡️ Assets to Protect
1. **Target Privacy and Safety:** The identity, location, and communications of targeted individuals.
2. **Integrity of Investigations:** The analytical findings, attribution links, and forensic artifacts gathered by researchers.
3. **Safety of Defenders:** The security of the researchers, NGOs, and journalists using this framework.
4. **The Framework Itself:** Ensuring the tools provided herein cannot be repurposed for offensive ends.

## ⚔️ Defended Attacks (Our Purpose)
We provide tooling to detect and document:
- **Undetected Spyware Infrastructure:** Identifying hidden C2 servers, exploit delivery domains, and network beaconing patterns.
- **Lack of Attribution/Visibility:** Mapping opaque corporate structures, vendor relationships, and jurisdictional havens used by mercenary companies.
- **Obfuscation Tactics:** Detecting TLS fingerprint anomalies, irregular DNS resolution patterns, and characteristic network flows.

## 🚫 Out-of-Scope Activities (Strictly Forbidden)
To maintain our defensive and human-rights-aligned posture, the following are explicitly out of scope and forbidden within this framework:
1. **Counter-Offensive Hacking:** We do not build tools to "hack back," exploit, or disrupt adversary infrastructure.
2. **Targeting Individuals:** Our analysis focuses on *systems, vendors, and infrastructure*. We do not build tools to identify, track, or analyze specific individuals (targets or operators).
3. **Exploit Development:** We do not host, build, or analyze exploit code (e.g., zero-days, 1-days) beyond the necessary signatures required to build defensive rules (YARA/Suricata).
4. **Live PII Storage:** We do not store or process real Personally Identifiable Information (PII) of victims within this repository. All examples and tests use synthetic data.
