"""Findings -> text a person reads.

Severity first, then device, so the top of the output is the thing to look at.
Every finding shows how it was established (`tier`) because a deterministic
assertion and a model prediction deserve different amounts of trust.

The citation a finding carries is shown under `--explain` rather than in the
default view: a reader scanning for what is wrong does not need a path on every
line, and a reader who has decided to fix one needs it immediately. The JSON
carries it unconditionally, because nothing reading that is scanning.
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
            # Before the evidence: the first thing someone does with a finding
            # they believe is open the configuration it is about, and the last
            # thing they want is to search six files for it (PROJECT.md §5.4).
            if finding.source:
                lines.append(f"        source: {finding.source}")
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
                    "source": _source_json(finding),
                }
                for finding in rank(findings)
            ],
        },
        indent=2,
    )


def _source_json(finding: Finding) -> dict[str, str | int | None] | None:
    """The citation as an object rather than `file:line`.

    A pipeline that turns a finding into an annotation on a diff needs the path
    and the line apart; splitting `file:line` back up is guesswork on a path
    containing a colon.
    """
    if finding.source is None:
        return None
    return {"file": finding.source.file, "line": finding.source.line}
