"""
Report Generator
Produces a professional Markdown remediation report from a completed investigation.
"""
from datetime import datetime, timezone
from typing import Optional
from app.models import Investigation, RemediationStatus


def generate_markdown_report(inv: Investigation) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    severity = inv.severity.value.upper() if inv.severity else "UNKNOWN"
    status_label = "VERIFIED" if (
        inv.remediation and inv.remediation.status == RemediationStatus.VERIFIED
    ) else "PENDING"

    lines = [
        "# SECUREFIX — Remediation Report",
        "",
        f"**Investigation ID:** `{inv.id}`  ",
        f"**Generated:** {now}  ",
        f"**Status:** {status_label}  ",
        f"**Severity:** {severity}  ",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
    ]

    if inv.correlation:
        lines += [
            f"SECUREFIX identified a **{inv.correlation.primary_finding}** vulnerability "
            f"in the repository with **{int(inv.correlation.confidence * 100)}% confidence**.",
            "",
            f"The finding was investigated by 7 specialized AI agents, evidence was correlated "
            f"across source code, configuration, dependencies, and test coverage.",
            "",
        ]

    if inv.verification:
        v = inv.verification
        if v.overall_status == "verified":
            lines += [
                "✅ The vulnerability has been **patched, tested, and verified**. "
                "The original exploit is blocked.",
                "",
            ]
        else:
            lines += [
                f"⚠️ Verification status: **{v.overall_status.upper()}**. Manual review required.",
                "",
            ]

    lines += [
        "---",
        "",
        "## Finding",
        "",
        f"**Title:** {inv.title}  ",
        f"**Reported Issue:** {inv.issue_description}  ",
        "",
    ]

    if inv.severity:
        lines += [f"**Severity:** `{severity}`  ", ""]

    if inv.root_cause:
        rc = inv.root_cause
        lines += [
            "## Root Cause Analysis",
            "",
            "### Symptom",
            rc.symptom,
            "",
            "### Root Cause",
            rc.root_cause,
            "",
            "### Why It Happens",
            rc.why_it_happens,
            "",
            "### Impact",
            rc.impact,
            "",
        ]
        if rc.cwe_id or rc.cvss_score:
            lines.append("### Classification")
            if rc.cwe_id:
                lines.append(f"- **CWE:** `{rc.cwe_id}`")
            if rc.cvss_score:
                lines.append(f"- **CVSS Score:** `{rc.cvss_score}`")
            lines.append("")

    if inv.correlation and inv.correlation.attack_path:
        lines += ["## Attack / Failure Path", ""]
        for i, step in enumerate(inv.correlation.attack_path, 1):
            lines.append(f"{i}. {step}")
        lines.append("")

    if inv.correlation and inv.correlation.affected_files:
        lines += [
            "## Affected Components",
            "",
        ]
        for f in inv.correlation.affected_files:
            # Strip absolute paths — show only relative
            display = f.replace("\\", "/")
            if "/" in display:
                # Keep last 3 path components at most
                parts = display.split("/")
                display = "/".join(parts[-3:]) if len(parts) > 3 else display
            lines.append(f"- `{display}`")
        lines.append("")

    # Agent findings summary
    lines += ["## Agent Findings Summary", ""]
    for agent_name, result in inv.agent_results.items():
        label = agent_name.replace("_", " ").title()
        status_sym = "✅" if result.status.value == "completed" else "⚠️"
        lines.append(f"### {status_sym} {label}")
        lines.append(f"*{result.summary}*")
        for finding in result.findings:
            conf_pct = int(finding.confidence * 100)
            lines.append(
                f"\n**{finding.title}** — `{finding.severity.upper()}` ({conf_pct}% confidence)"
            )
            for ev in finding.evidence[:3]:
                lines.append(f"- {ev}")
            if finding.recommendation:
                lines.append(f"\n> 💡 {finding.recommendation}")
        lines.append("")

    if inv.correlation and inv.correlation.corroborating_evidence:
        lines += ["## Evidence Correlation", "", "| Source | Type | Description |", "|--------|------|-------------|"]
        for ev in inv.correlation.corroborating_evidence[:15]:
            src = ev.source.replace("_agent", "")
            desc = ev.description.replace("|", "–")[:80]
            lines.append(f"| {src} | {ev.type} | {desc} |")
        lines.append("")

    if inv.remediation:
        r = inv.remediation
        lines += [
            "## Remediation",
            "",
            f"**Summary:** {r.summary}  ",
            f"**Risk Level:** `{r.risk_level.upper()}`  ",
            f"**Files Changed:** {', '.join(f'`{f}`' for f in r.files_changed)}  ",
            "",
            r.risk_explanation,
            "",
        ]
        for patch in r.patches:
            lines += [
                f"### Patch: `{patch.file_path}`",
                "",
                patch.explanation,
                "",
                "```diff",
                patch.diff,
                "```",
                "",
            ]

    if inv.remediation and inv.remediation.regression_test:
        test_file = inv.remediation.regression_test_file or "tests/test_securefix_regression.py"
        lines += [
            "## Regression Test",
            "",
            f"Auto-generated regression test written to `{test_file}`.",
            "",
            "```python",
            inv.remediation.regression_test[:1500],
            "```",
            "",
        ]

    if inv.verification:
        v = inv.verification
        lines += [
            "## Verification Results",
            "",
            f"**Overall Status:** `{v.overall_status.upper()}`  ",
            f"**Exploit Blocked:** {'Yes' if v.exploit_blocked else 'No'}  ",
            f"**Regression Test Passed:** {'Yes' if v.regression_passed else 'No'}  ",
            "",
        ]
        for check in v.checks:
            sym = "✅" if check.status == "passed" else ("⏭️" if check.status == "skipped" else "❌")
            lines.append(f"{sym} **{check.name}** — {check.detail}")
        lines += ["", v.summary, ""]

    if inv.timeline:
        lines += ["## Investigation Timeline", ""]
        for ev in inv.timeline:
            ts = ev.timestamp.strftime("%H:%M:%S") if hasattr(ev.timestamp, "strftime") else str(ev.timestamp)[:19]
            lines.append(f"- `{ts}` — **{ev.event}**" + (f": {ev.detail}" if ev.detail else ""))
        lines.append("")

    lines += [
        "---",
        "",
        "*Generated by SECUREFIX — Detect. Understand. Fix. Verify.*  ",
        "*IBM Bob 2.0 Hackathon 2026*",
    ]

    return "\n".join(lines)
