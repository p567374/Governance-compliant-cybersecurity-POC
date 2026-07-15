#!/usr/bin/env python3
"""
generate_compliance_report.py

Aggregates CI/CD security scan outputs (SAST, SCA, secrets, SBOM) into a
single governance report mapped to the NIST Cybersecurity Framework (CSF)
and NIST SP 800-218 (Secure Software Development Framework).

This is the piece that turns "we ran some scanners" into "here is our
evidence of governance," which is what makes this POC meet a compliance
bar rather than just a technical one.

Usage:
    python generate_compliance_report.py --input all-scan-results --output compliance-report.md
"""

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

# Maps each control area to its NIST CSF Function / Category and SSDF practice.
# Edit this mapping if you target a different framework (ISO 27001 Annex A,
# SOC 2 Trust Services Criteria, etc.) — the aggregation logic below stays the same.
NIST_CSF_MAPPING = {
    "sast": {
        "name": "Static Application Security Testing",
        "csf_function": "Identify / Detect",
        "csf_category": "ID.RA-1, DE.CM-4",
        "ssdf_practice": "PW.7 — Review and/or analyze human-readable code",
    },
    "dependency": {
        "name": "Software Composition Analysis",
        "csf_function": "Identify",
        "csf_category": "ID.RA-1, ID.SC-2",
        "ssdf_practice": "PW.4 — Reuse existing, well-secured software",
    },
    "secrets": {
        "name": "Secrets Detection",
        "csf_function": "Protect",
        "csf_category": "PR.AC-1, PR.DS-5",
        "ssdf_practice": "PW.6 — Configure the compilation/build process to improve executable security",
    },
    "sbom": {
        "name": "Software Bill of Materials",
        "csf_function": "Identify",
        "csf_category": "ID.AM-2, ID.SC-2",
        "ssdf_practice": "PS.3 / PW.4 — Archive and protect each software release; supply chain transparency",
    },
}


def find_artifact_dirs(root: Path) -> dict:
    """Locate downloaded artifact directories by their known name prefixes."""
    found = {"sast": [], "dependency": [], "secrets": [], "sbom": []}
    if not root.exists():
        return found

    for entry in root.iterdir():
        name = entry.name.lower()
        if "sast" in name:
            found["sast"].append(entry)
        elif "dependency" in name:
            found["dependency"].append(entry)
        elif "gitleaks" in name or "secret" in name:
            found["secrets"].append(entry)
        elif "sbom" in name:
            found["sbom"].append(entry)
    return found


def summarize_dependency_findings(dirs: list) -> dict:
    """Pull a rough severity count out of a Trivy SARIF file if present."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for d in dirs:
        for f in d.glob("*.sarif"):
            try:
                data = json.loads(f.read_text())
                for run in data.get("runs", []):
                    for result in run.get("results", []):
                        level = result.get("level", "note")
                        if level == "error":
                            counts["high"] += 1
                        elif level == "warning":
                            counts["medium"] += 1
                        else:
                            counts["low"] += 1
            except (json.JSONDecodeError, OSError):
                continue
    return counts


def build_report(input_dir: Path) -> str:
    artifacts = find_artifact_dirs(input_dir)
    dep_counts = summarize_dependency_findings(artifacts["dependency"])
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = []
    lines.append("# Security & Governance Compliance Report")
    lines.append(f"\n**Generated:** {generated_at}")
    lines.append("**Framework:** NIST Cybersecurity Framework (CSF) v1.1 + NIST SP 800-218 (SSDF)\n")
    lines.append("| Control Area | Status | CSF Function | CSF Category | SSDF Practice |")
    lines.append("|---|---|---|---|---|")

    for key, meta in NIST_CSF_MAPPING.items():
        ran = len(artifacts.get(key, [])) > 0
        status = "✅ Executed" if ran else "⚠️ Not found in this run"
        lines.append(
            f"| {meta['name']} | {status} | {meta['csf_function']} | "
            f"{meta['csf_category']} | {meta['ssdf_practice']} |"
        )

    lines.append("\n## Dependency Scan Findings Summary\n")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in ("critical", "high", "medium", "low"):
        lines.append(f"| {sev.title()} | {dep_counts[sev]} |")

    lines.append("\n## Governance Notes\n")
    lines.append(
        "- This report is generated automatically on every scheduled and "
        "pull-request-triggered scan, providing a continuous evidence trail "
        "for audits (NIST CSF DE.DP-4 — detection results communicated).\n"
        "- SBOM artifacts are retained for 180 days to support software supply "
        "chain review requirements (Executive Order 14028, NIST SP 800-218).\n"
        "- Compliance reports are retained for 365 days to align with typical "
        "annual audit cycles.\n"
        "- Severity thresholds and fail-build conditions should be tuned per "
        "repository risk tolerance before enforcing hard CI gates."
    )

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Generate a NIST CSF-aligned security compliance report.")
    parser.add_argument("--input", required=True, help="Directory containing downloaded scan artifacts")
    parser.add_argument("--output", required=True, help="Path to write the markdown report")
    args = parser.parse_args()

    report = build_report(Path(args.input))
    Path(args.output).write_text(report)
    print(f"Compliance report written to {args.output}")


if __name__ == "__main__":
    main()
