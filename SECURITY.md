# Security Policy

## Automated Scanning

This repository runs automated security scanning on every push, pull
request, and weekly on a schedule. See
[`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml)
for details. Scan types:

- Static Application Security Testing (CodeQL)
- Dependency / vulnerability scanning (Trivy, GitHub Dependency Review)
- Secrets detection (Gitleaks)
- SBOM generation (Syft, CycloneDX format)

Results are aggregated into a governance report mapped to the NIST
Cybersecurity Framework — see [`docs/nist-csf-mapping.md`](docs/nist-csf-mapping.md).

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it
privately rather than opening a public issue:

1. Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) feature on this repo, or
2. Email the maintainer directly (replace with your contact address).

Please include steps to reproduce, affected versions, and potential impact.
We aim to acknowledge reports within 5 business days.

## Supported Versions

| Version | Supported |
|---|---|
| main / latest | ✅ |
| older releases | ❌ |
