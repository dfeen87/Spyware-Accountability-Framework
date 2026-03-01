# Release Review Checklist

Before merging a Pull Request, creating a new tagged release, or publishing new rules/datasets to this repository, a maintainer must complete the following checklist.

This process ensures that our framework remains strictly aligned with our defensive, human-rights-focused mandate.

## 1. Defensive Alignment Verification
- [ ] Are all new features strictly related to detection, mapping, transparency, or accountability?
- [ ] Does the change introduce any capability to execute arbitrary code on a remote system? (If yes, REJECT)
- [ ] Does the change introduce any capability to actively probe or attack adversary infrastructure? (If yes, REJECT)
- [ ] Are new rules (YARA, Sigma, etc.) formatted safely, providing defensive capability without acting as a "how-to" guide for attackers?

## 2. Privacy & PII Verification
- [ ] Has the submitted code, dataset, or PCAP been reviewed for Personally Identifiable Information (PII)?
- [ ] Are we confident that NO real target identities, email addresses, phone numbers, or unredacted victim URLs are included?
- [ ] If real data is included (rather than synthetic), has it been properly anonymized and stripped of any data that could deanonymize victims or researchers?

## 3. Threat Intelligence Safety
- [ ] If real IOCs or behavioral descriptions are included, has their publication been coordinated with relevant researchers to ensure we are not burning an active, sensitive investigation?
- [ ] Does the release provide actionable value to defenders (NGOs, journalists, SOCs) without unnecessarily providing threat actors with a free "QA check" of their malware?

## 4. Documentation & Clarity
- [ ] Are new synthetic examples clearly marked as "SYNTHETIC / EXAMPLE" so that users do not deploy them expecting real detections?
- [ ] Is the AILEE trust layer and policy configuration clearly explained for new modules?

---
*Signed off by Maintainer: ___________________ Date: __________*
