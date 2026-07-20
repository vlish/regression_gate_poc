#!/usr/bin/env python3
"""Compare Trivy SARIF reports (PR vs base) and emit a PR comment for new findings."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


COMMENT_MARKER = "<!-- trivy-regression-gate -->"

MESSAGE_PATTERNS = {
    "package": re.compile(r"^Package:\s*(.+)$", re.MULTILINE),
    "installed": re.compile(r"^Installed Version:\s*(.+)$", re.MULTILINE),
    "severity": re.compile(r"^Severity:\s*(.+)$", re.MULTILINE),
    "fixed": re.compile(r"^Fixed Version:\s*(.+)$", re.MULTILINE),
    "link": re.compile(r"^Link:\s*\[([^\]]+)\]\(([^)]+)\)", re.MULTILINE),
}


@dataclass(frozen=True)
class Finding:
    vuln_id: str
    package: str
    installed_version: str
    severity: str
    fixed_version: str
    advisory: str
    target: str

    @property
    def key(self) -> str:
        # Identity for regression: same CVE on same package/version/target is "known".
        return "|".join(
            [
                self.vuln_id,
                self.package,
                self.installed_version,
                self.target,
            ]
        )


def _first(pattern: re.Pattern[str], text: str, default: str = "N/A") -> str:
    match = pattern.search(text)
    if not match:
        return default
    return match.group(1).strip() or default


def _location_target(result: dict) -> str:
    locations = result.get("locations") or []
    if not locations:
        return ""
    physical = (locations[0] or {}).get("physicalLocation") or {}
    artifact = physical.get("artifactLocation") or {}
    uri = artifact.get("uri") or ""
    message = ((locations[0] or {}).get("message") or {}).get("text") or ""
    return message or uri


def parse_sarif(path: Path) -> dict[str, Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    findings: dict[str, Finding] = {}

    for run in data.get("runs") or []:
        for result in run.get("results") or []:
            message = ((result.get("message") or {}).get("text")) or ""
            vuln_id = (result.get("ruleId") or "").strip()
            if not vuln_id:
                continue

            package = _first(MESSAGE_PATTERNS["package"], message)
            installed = _first(MESSAGE_PATTERNS["installed"], message)
            severity = _first(MESSAGE_PATTERNS["severity"], message)
            fixed = _first(MESSAGE_PATTERNS["fixed"], message)
            link_match = MESSAGE_PATTERNS["link"].search(message)
            advisory = link_match.group(1).strip() if link_match else vuln_id
            target = _location_target(result)

            finding = Finding(
                vuln_id=vuln_id,
                package=package,
                installed_version=installed,
                severity=severity.title() if severity != "N/A" else severity,
                fixed_version=fixed if fixed else "N/A",
                advisory=advisory,
                target=target,
            )
            findings[finding.key] = finding

    return findings


def _md_cell(value: str) -> str:
    """Escape values so they don't break markdown table cells."""
    return (value or "N/A").replace("|", "\\|").replace("\n", " ").strip()


def format_comment(new_findings: Iterable[Finding], base_ref: str) -> str:
    findings = sorted(
        new_findings,
        key=lambda f: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}.get(
                f.severity.upper(), 5
            ),
            f.vuln_id,
            f.package,
        ),
    )

    lines = [
        COMMENT_MARKER,
        "## New vulnerabilities introduced compared with the base branch",
        "",
        "This PR introduces vulnerabilities that are not present in the base branch.",
        "The security regression check will remain red until they are remediated by "
        "upgrading the dependency, reverting the dependency change, or following the "
        "approved exception process (for example by adding an entry to `.trivyignore`).",
        "",
        f"_Compared against base ref `{base_ref}`._",
        "",
        "| CVE | Package | Installed version | Severity | Fixed version | Advisory |",
        "| --- | --- | --- | --- | --- | --- |",
    ]

    for finding in findings:
        lines.append(
            "| "
            + " | ".join(
                [
                    _md_cell(finding.vuln_id),
                    _md_cell(finding.package),
                    _md_cell(finding.installed_version),
                    _md_cell(finding.severity),
                    _md_cell(finding.fixed_version),
                    _md_cell(finding.advisory),
                ]
            )
            + " |"
        )

    lines.append("")
    return "\n".join(lines)



def format_pass_comment(base_ref: str, pr_count: int, base_count: int) -> str:
    return "\n".join(
        [
            COMMENT_MARKER,
            "## Trivy regression gate: passed",
            "",
            "No new vulnerabilities were introduced compared with the base branch.",
            f"- Base (`{base_ref}`): {base_count} finding(s)",
            f"- PR branch: {pr_count} finding(s)",
            "",
            "Known findings may remain; this check only fails on **new** issues. "
            "Approved exceptions can be recorded in `.trivyignore`.",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-sarif", required=True, type=Path)
    parser.add_argument("--pr-sarif", required=True, type=Path)
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--comment-out", required=True, type=Path)
    parser.add_argument("--summary-out", type=Path, default=None)
    args = parser.parse_args()

    base_findings = parse_sarif(args.base_sarif)
    pr_findings = parse_sarif(args.pr_sarif)

    new_keys = set(pr_findings) - set(base_findings)
    new_findings = [pr_findings[k] for k in new_keys]

    if new_findings:
        comment = format_comment(new_findings, args.base_ref)
        exit_code = 1
        status = "failed"
    else:
        comment = format_pass_comment(args.base_ref, len(pr_findings), len(base_findings))
        exit_code = 0
        status = "passed"

    args.comment_out.write_text(comment, encoding="utf-8")

    summary = {
        "status": status,
        "base_ref": args.base_ref,
        "base_count": len(base_findings),
        "pr_count": len(pr_findings),
        "new_count": len(new_findings),
        "new_vuln_ids": sorted({f.vuln_id for f in new_findings}),
    }
    if args.summary_out:
        args.summary_out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    print(json.dumps(summary))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
