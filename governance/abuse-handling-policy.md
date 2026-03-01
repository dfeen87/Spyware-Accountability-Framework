# Abuse Handling Policy

The Spyware Accountability Framework exists to foster transparency, defense, and human-rights protection.

However, we recognize the inherent dual-use potential of any threat intelligence and infrastructure mapping tooling. Tools designed to unmask spyware operators can theoretically be repurposed by those operators, or by other threat actors, to map networks or refine their obfuscation.

This policy outlines how we handle reports of abuse.

## What Constitutes Abuse?

For the purposes of this repository, abuse occurs when the framework or its provided datasets/rules are used in ways that violate our core ethical commitments:

1. **Targeting Individuals:** Using the framework to track, dox, or identify victims or human rights defenders.
2. **Offensive Repurposing:** Extending the pipelines to enable active exploitation or disruption.
3. **PII Exposure:** Submitting datasets, PCAPs, or logs that contain unredacted Personally Identifiable Information of victims.
4. **Spyware Enhancement:** Submitting code, tutorials, or rule bypasses explicitly intended to help threat actors avoid detection.

## Reporting Misuse or PII Exposure

If you identify abuse, or discover real victim PII in this repository:

1. **DO NOT CREATE A PUBLIC ISSUE.**
2. Open a **private** vulnerability report at:
   <https://github.com/dfeen87/Spyware-Accountability-Framework/security/advisories/new>

Include:
- The URL of the specific file, commit, or PR in question.
- A description of how it violates the ethical guidelines.
- If it is PII, what type of data it is (e.g., "phone number located in line 42 of dummy_data.json").

## Action Taken on Reports

1. **Immediate Quarantine:** If a report involves victim PII or a clear, dangerous offensive tool, maintainers will immediately hide the PR or issue and force-push to remove the offending commit from the public history.
2. **Review:** The maintainers (and potentially the community governance board) will review the report.
3. **Resolution:** We will communicate the resolution back to the reporter. This may include rewriting git history to purge sensitive data, permanently banning an abusive contributor, or updating our rule templates to be safer.

## Safe Harbor for Defenders

This policy is not intended to discourage security research. We actively support researchers probing the limits of our detection rules—provided those probes are done synthetically, defensively, and without exposing live targets or teaching threat actors how to improve their tools.
