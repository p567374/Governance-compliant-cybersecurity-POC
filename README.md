# Automated Security Scanning POC (NIST CSF Aligned)

A proof-of-concept CI/CD pipeline that runs SAST, dependency/vulnerability
scanning, secrets detection, and SBOM generation on every push and pull
request — then aggregates the results into a governance report mapped to
the **NIST Cybersecurity Framework** and **NIST SP 800-218 (SSDF)**.

The goal: every CI run produces not just scan output, but audit-ready
evidence of a governed security process.

## What's in this POC

```
.github/workflows/security-scan.yml   # the pipeline itself
scripts/generate_compliance_report.py # aggregates scan results into a NIST CSF report
docs/nist-csf-mapping.md              # control-to-framework mapping and rationale
SECURITY.md                           # vulnerability reporting policy
```

## Pipeline stages

1. **SAST** — CodeQL analyzes source code for vulnerable patterns.
2. **SCA / Dependency scan** — Trivy scans dependencies for known CVEs;
   GitHub's Dependency Review action blocks PRs introducing critical
   vulnerabilities.
3. **Secrets scan** — Gitleaks checks the full git history for committed
   credentials.
4. **SBOM generation** — Syft produces a CycloneDX SBOM for supply-chain
   transparency.
5. **Compliance report** — a Python script pulls all of the above together
   into a single markdown report mapped to NIST CSF functions/categories,
   posted directly to the GitHub Actions job summary and retained as an
   artifact for 365 days.

## Setting it up in your repo

1. Copy `.github/workflows/security-scan.yml` and `scripts/` into your repo.
2. Edit the `matrix.language` list in the CodeQL job to match your repo's
   languages.
3. Start with `exit-code: '0'` on Trivy (report-only) while you tune
   severity thresholds, then flip to `'1'` to hard-fail builds on
   critical/high findings once noise is under control.
4. No secrets or API keys are required — everything here runs on the
   default `GITHUB_TOKEN` and public GitHub Actions.

## Why this counts as "governance," not just scanning

Anyone can bolt a scanner onto CI. What makes this a governance artifact is:

- **Traceability** — every control is explicitly mapped to a named
  framework requirement (see `docs/nist-csf-mapping.md`), not just "we run
  a tool."
- **Retention policy** — artifacts are retained on a schedule that matches
  audit needs (SBOMs 180 days, compliance reports 365 days), not GitHub's
  default 90-day expiry.
- **Continuous evidence** — the compliance report regenerates on every
  scheduled run, so you always have current evidence rather than a
  point-in-time assessment.
- **Framework portability** — swapping to ISO 27001 or SOC 2 only requires
  editing one dictionary in `generate_compliance_report.py`; the scanning
  logic doesn't change.

## Extending this POC

- Swap the framework mapping for ISO 27001 or SOC 2 (see
  `docs/nist-csf-mapping.md` for a starter mapping).
- Add container image scanning (Trivy supports `image` mode as well as `fs`).
- Push the compliance report to an external GRC tool via its API instead
  of (or alongside) the GitHub Actions job summary.
- Add branch protection rules requiring the `compliance-report` job to
  pass before merge.
