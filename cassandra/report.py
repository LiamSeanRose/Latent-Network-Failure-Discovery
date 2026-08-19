"""Findings -> text a person reads.

Severity first, then device, so the top of the output is the thing to look at.
Every finding shows how it was established (`tier`) because a deterministic
assertion and a model prediction deserve different amounts of trust.
"""

from __future__ import annotations

import json

from cassandra.findings import Finding, Severity, Tier, rank

_LABEL = {
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MED ",
    Severity.LOW: "LOW ",
    Severity.INFO: "INFO",
}


def render(findings: list[Finding], *, explain: bool = False) -> str:
    if not findings:
        return "no findings"

    lines: list[str] = []
    for finding in rank(findings):
        lines.append(f"{_LABEL[finding.severity]}  {finding.device}  {finding.title}")
        lines.append(f"        {finding.detail}")
        if finding.trigger:
            lines.append(f"        trigger: {finding.trigger}")
        if explain:
            for item in finding.evidence:
                lines.append(f"        evidence: {item}")
            if finding.remedy:
                lines.append(f"        fix: {finding.remedy}")
            lines.append(f"        rule: {finding.rule} ({finding.tier.value})")
        lines.append("")

    counts = {severity: 0 for severity in Severity}
    tiers = {tier: 0 for tier in Tier}
    for finding in findings:
        counts[finding.severity] += 1
        tiers[finding.tier] += 1
    lines.append(
        "  ".join(
            f"{severity.value}={count}" for severity, count in counts.items() if count
        )
        + "   ("
        + ", ".join(f"{tier.value}={count}" for tier, count in tiers.items() if count)
        + ")"
    )
    if not explain:
        lines.append("run with --explain for evidence, fixes and rule ids")
    return "\n".join(lines)


def as_json(findings: list[Finding], *, pack_id: str = "", digest: str = "") -> str:
    """Machine-readable output for a pipeline.

    Carries the fact-pack identity alongside the findings, because a result
    without the digest of the configs that produced it cannot be tied back to a
    revision, which is what a pipeline needs it for.
    """
    return json.dumps(
        {
            "fact_pack_id": pack_id,
            "config_digest": digest,
            "counts": {
                severity.value: sum(1 for f in findings if f.severity is severity)
                for severity in Severity
                if any(f.severity is severity for f in findings)
            },
            "findings": [
                {
                    "rule": finding.rule,
                    "tier": finding.tier.value,
                    "severity": finding.severity.value,
                    "device": finding.device,
                    "title": finding.title,
                    "detail": finding.detail,
                    "trigger": finding.trigger,
                    "remedy": finding.remedy,
                    "evidence": list(finding.evidence),
                }
                for finding in rank(findings)
            ],
        },
        indent=2,
    )
