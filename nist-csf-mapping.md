# NIST CSF & SSDF Control Mapping

This POC demonstrates automated security scanning aligned to the **NIST
Cybersecurity Framework (CSF) v1.1** and **NIST SP 800-218 (Secure Software
Development Framework, SSDF)**. This mapping is what elevates the pipeline
from "we run some scanners" to "we have a governed, auditable control set."

## Why NIST CSF for this POC

| Consideration | NIST CSF | ISO 27001 | SOC 2 |
|---|---|---|---|
| Freely available | Yes | No (paid standard) | N/A (audit process, not a control catalog) |
| Maps directly to CI/CD tooling | Yes | Partially | Indirectly |
| Recognized by US enterprise / public sector | Widely | Internationally | US-centric, audit-only |
| Has a dev-lifecycle companion (SSDF) | Yes | No direct equivalent | No |

## Control Mapping

| Tool | Control Area | CSF Function | CSF Category / Subcategory | SSDF Practice |
|---|---|---|---|---|
| CodeQL | Static Application Security Testing | Identify / Detect | ID.RA-1, DE.CM-4 | PW.7 |
| Trivy + Dependency Review | Software Composition Analysis | Identify | ID.RA-1, ID.SC-2 | PW.4 |
| Gitleaks | Secrets Detection | Protect | PR.AC-1, PR.DS-5 | PW.6 |
| Syft | SBOM Generation | Identify | ID.AM-2, ID.SC-2 | PS.3, PW.4 |
| Compliance report job | Governance Reporting | Identify / Detect | ID.GV-1, DE.DP-4 | — |

## Retention & Evidence Policy

- **Scan artifacts (SARIF/JSON):** 90 days — supports incident investigation windows.
- **SBOMs:** 180 days — supports supply-chain review and EO 14028 alignment.
- **Compliance reports:** 365 days — aligns with a typical annual audit cycle.

## Extending This Mapping

If your organization is required to report against a different framework,
only `NIST_CSF_MAPPING` in `scripts/generate_compliance_report.py` needs to
change — the scanning workflow itself is framework-agnostic. Common
substitutions:

- **ISO 27001 Annex A:** A.12.6 (vulnerability management), A.14.2 (secure
  development), A.8.1 (asset inventory for SBOM).
- **SOC 2 Trust Services Criteria:** CC7.1 (vulnerability detection), CC6.1
  (logical access / secrets), CC7.2 (monitoring).
