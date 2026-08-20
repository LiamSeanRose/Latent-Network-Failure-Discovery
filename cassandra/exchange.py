"""Findings in the two formats a CI system already knows how to read.

`--format json` is this tool's own shape, and something has to be taught to read
it. SARIF and JUnit are shapes the machinery is already wired for: GitHub code
scanning ingests SARIF and turns each result into an annotation on the exact
configuration line, and every CI runner in existence renders a JUnit file as a
test report. Neither adds a capability — both remove the integration work
between "the check found something" and "the person who can fix it sees it".

The two carry different halves of the answer on purpose.

SARIF carries the findings, one result each, located at the configuration
responsible for them (PROJECT.md §5.4). JUnit carries the *rule set*: one test
case per catalogued rule, so a rule that fired, a rule that ran and found
nothing, and a rule that never had a fact to reason over are three visibly
different outcomes rather than one silence. That distinction is the whole
argument of `cassandra.coverage`, and a CI report is where it matters most — a
green build with thirty of forty-five checks inert is not the result it looks
like.

Determinism
-----------

Both are byte-identical for the same configs. No timestamp, no run id, no
duration, no random anything: the value of these files is that two of them can
be diffed, and a field that moves on every run destroys that for the sake of
information nobody reads. This is why SARIF's `invocations` carries no
`startTimeUtc` and why the JUnit test cases carry no `time` — a duration is a
measurement of the machine, not of the network.

What is deliberately not attempted
----------------------------------

**No SARIF `fix`.** `Finding.change` is the edit, and a `fix` with an
`artifactChange` is the obvious home for it — but a SARIF fix is a *text
replacement at a location*, and `change` is not that. It is a sequence of lines
typed in configuration mode, frequently on a different device than the one the
finding is located on: `bgp-session-one-sided` is reported against the device
that has the neighbor statement and its change is typed on the device that does
not. Applying that as a patch to the located file would corrupt it. So `change`
travels as text a human types, in the message and in `properties`, and the
autofix that would be wrong is not offered.

**No line number in the fingerprint.** `partialFingerprints` exists so a
finding that has not changed is not re-reported as new after unrelated lines
shift above it, which rules out the location outright. It is derived instead
from `baseline.identity` — the rule, the device, and the network objects the
finding names — which is the same identity `cassandra check --since` compares
by, so the two answers to "is this the same finding?" cannot drift apart.
"""

from __future__ import annotations

import hashlib
import json
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from dataclasses import dataclass
from importlib import metadata
from pathlib import PurePath
from typing import Final

from cassandra import baseline
from cassandra.catalogue import RuleDoc, catalogue
from cassandra.coverage import RuleCoverage
from cassandra.findings import Finding, Severity, Tier, rank

type JsonObject = dict[str, object]

TOOL_NAME: Final = "cassandra"
SARIF_VERSION: Final = "2.1.0"
SARIF_SCHEMA: Final = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
    "sarif-schema-2.1.0.json"
)

# LOW and INFO both land on `note` because SARIF has three levels below `error`
# and one of them (`none`) means "this is not a problem". Collapsing two
# severities is a loss; reporting an INFO finding as not-a-problem is a lie.
_LEVEL: Final[dict[Severity, str]] = {
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# Versioned because the identity it hashes is a heuristic that may be improved.
# A reader that starts seeing a different key knows the fingerprints under the
# old one are not comparable, instead of silently comparing two schemes.
_FINGERPRINT_KEY: Final = "cassandraFindingIdentity/v1"
_FINGERPRINT_BITS: Final = 16

# Written rather than left to ElementTree, which emits no declaration at all
# for a unicode string. A JUnit file without one is read as ASCII by some
# parsers, and a device description with an em dash in it then fails to load.
_XML_DECLARATION: Final = '<?xml version="1.0" encoding="UTF-8"?>'


# --------------------------------------------------------------------------
# SARIF
# --------------------------------------------------------------------------


def sarif(
    findings: Sequence[Finding],
    *,
    base: str = "",
    pack_id: str = "",
    digest: str = "",
) -> str:
    """A SARIF 2.1.0 log: the rule set as descriptors, the findings as results.

    `base` is the directory that was checked, as it was named on the command
    line, and every result URI is written under it. This is what makes the
    output usable by code scanning: a finding's `source.file` is relative to the
    directory checked, and an annotation has to be relative to the repository,
    so the two only agree once the directory the user typed is put back in
    front. A directory named absolutely produces absolute URIs, which is the
    right answer for a reader outside CI and the wrong one inside it — the
    invocation records the directory so it can be seen either way.

    The whole catalogue is emitted as descriptors, not only the rules that
    fired, so `driver.rules` describes the tool rather than the run: a reader
    can see what was looked for. Results index into it by position.
    """
    docs = catalogue()
    index_of = {doc.id: position for position, doc in enumerate(docs)}
    directory = _directory_uri(base)
    run: JsonObject = {
        "tool": {"driver": _driver(docs)},
        # No start or end time. See the module docstring: a diffable artifact is
        # worth more than a precise one.
        "invocations": [
            {
                "executionSuccessful": True,
                "workingDirectory": {"uri": directory},
            }
        ],
        "results": [
            _result(finding, index_of, directory) for finding in rank(list(findings))
        ],
        # The identity of the configs these results describe, carried for the
        # same reason `report.as_json` carries it: a result that cannot be tied
        # back to a revision is not evidence about anything. The rule set is
        # here for the other half: two uploads that differ mean nothing until a
        # reader knows whether the configs moved, the checks moved, or both.
        "properties": {
            "factPackId": pack_id,
            "configDigest": digest,
            "rulesDigest": baseline.rules_digest(),
        },
    }
    return json.dumps(
        {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}, indent=2
    )


def _driver(docs: Sequence[RuleDoc]) -> JsonObject:
    driver: JsonObject = {"name": TOOL_NAME}
    version = _version()
    if version is not None:
        driver["semanticVersion"] = version
    driver["rules"] = [_descriptor(doc) for doc in docs]
    return driver


def _version() -> str | None:
    """The installed version, or nothing when running from an uninstalled tree.

    Nothing rather than a placeholder: a SARIF log that names a version the tool
    does not have is worse than one that declines to name a version at all.
    """
    try:
        return metadata.version(TOOL_NAME)
    except metadata.PackageNotFoundError:
        return None


def _descriptor(doc: RuleDoc) -> JsonObject:
    """One rule, described entirely out of `cassandra.catalogue`.

    Nothing here is written twice. The catalogue derives every field from the
    rule's own source — the identifier from the `Finding` it constructs, the
    prose from its docstring, the silence notes from the tests that assert it
    stays quiet — so a rule that is reworded or added changes this output
    without anyone editing it, which is the property a hand-maintained copy
    loses on its first edit.
    """
    return {
        "id": doc.id,
        "name": doc.function,
        "shortDescription": {"text": _short(doc)},
        "fullDescription": {"text": _full(doc)},
        "help": {"text": _help(doc)},
        "defaultConfiguration": {"level": _LEVEL[doc.severity]},
        "properties": {
            "tier": doc.tier.value,
            "severity": doc.severity.value,
            "tags": [doc.tier.value, doc.severity.value],
        },
    }


def _short(doc: RuleDoc) -> str:
    if doc.summary is not None:
        return doc.summary
    # The catalogue reports an undocumented rule as a visible defect rather than
    # inventing prose for it, and this does the same. A descriptor that reads
    # like a rule with nothing to say is a bug report anyone can file.
    return f"{doc.id} carries no docstring, so there is nothing to describe it with."


def _full(doc: RuleDoc) -> str:
    """Summary plus the paragraphs that say when the rule deliberately stays quiet.

    The second half is the part that decides whether silence is reassuring, and
    it is the reason `fullDescription` is not just a longer `shortDescription`.
    """
    return "\n\n".join(part for part in (_short(doc), *doc.checks) if part)


def _help(doc: RuleDoc) -> str:
    """What a reader needs once an annotation has told them a rule fired.

    The message templates and the tested silence, which the descriptions do not
    carry: what this rule says when it fires, what it advises, and which tests
    hold it quiet — the last one being how a reader judges an absence of
    findings from this rule elsewhere in their configs.
    """
    lines = [
        _full(doc),
        "",
        f"Tier: {doc.tier.value}.  Severity: {doc.severity.value}.",
    ]
    if doc.reports:
        lines.append(f"Reports: {doc.reports}")
    if doc.remedy:
        lines.append(f"Remedy: {doc.remedy}")
    lines += ["", "Stays silent when:"]
    if doc.silence:
        lines += [f"  - {note.note}  ({note.source})" for note in doc.silence]
    else:
        lines.append(
            "  - nothing asserts this rule staying quiet, so read its silence "
            "as an absence of evidence."
        )
    return "\n".join(lines)


def _result(finding: Finding, index_of: dict[str, int], directory: str) -> JsonObject:
    result: JsonObject = {
        "ruleId": finding.rule,
        "level": _LEVEL[finding.severity],
        "message": {"text": _message(finding)},
        "locations": [_location(finding, directory)],
        "partialFingerprints": {_FINGERPRINT_KEY: _fingerprint(finding)},
        # Everything the message says, back apart. A reader turning a result
        # into something else needs the fields separately, and splitting them
        # back out of prose is guesswork — the same reason `report._source_json`
        # hands out the file and the line rather than `file:line`.
        "properties": {
            "tier": finding.tier.value,
            "severity": finding.severity.value,
            "device": finding.device,
            "title": finding.title,
            "detail": finding.detail,
            "trigger": finding.trigger,
            "remedy": finding.remedy,
            "evidence": list(finding.evidence),
            "change": list(finding.change),
        },
    }
    position = index_of.get(finding.rule)
    if position is not None:
        result["ruleIndex"] = position
    return result


def _message(finding: Finding) -> str:
    """The whole finding as prose, because the annotation is all a reader gets.

    A code scanning annotation shows the message and nothing else — not the
    properties, not the rule help until someone clicks through. So the trigger,
    the evidence, the remedy and the change all appear here, in the vocabulary
    the text report uses, and the message is long rather than the finding being
    unusable where it is read.
    """
    lines = [finding.title, finding.detail]
    if finding.trigger:
        lines.append(f"trigger: {finding.trigger}")
    lines += [f"evidence: {item}" for item in finding.evidence]
    if finding.remedy:
        lines.append(f"fix: {finding.remedy}")
    # Indented under the prose that describes it, as the text report does. These
    # are lines to type, never a patch to apply — see the module docstring.
    lines += [f"  {line}" for line in finding.change]
    return "\n".join(line for line in lines if line)


def _location(finding: Finding, directory: str) -> JsonObject:
    """Where the result is reported, with as much precision as is honest.

    Three cases, and the second two are why this is not one line. A finding with
    a file and a line is annotated on that line. A finding whose rule could not
    narrow past the device gets the file with no region, because SARIF's region
    is optional and an invented line points a reader at configuration that has
    nothing to do with the finding. A finding the fact pack could not place at
    all is reported against the directory the tool was pointed at — the same URI
    the invocation records — rather than a path made up to satisfy the schema.
    """
    source = finding.source
    if source is None:
        return {"physicalLocation": {"artifactLocation": {"uri": directory}}}
    artifact: JsonObject = {"uri": _join(directory, source.file)}
    physical: JsonObject = {"artifactLocation": artifact}
    if source.line is not None:
        physical["region"] = {"startLine": source.line}
    return {"physicalLocation": physical}


def _fingerprint(finding: Finding) -> str:
    """A stable identity for the finding, computed from what it is about.

    `baseline.identity` is the rule, the device and the network objects named —
    no line number, no measured quantity, no wording of the sentence around
    them. A timer moving from 150ms to 100ms while the defect stands does not
    produce a new fingerprint, and neither does an edit ten lines above it.
    """
    rule, device, references = baseline.identity(finding)
    material = "\0".join((rule, device, *references))
    return hashlib.sha256(material.encode()).hexdigest()[:_FINGERPRINT_BITS]


def _directory_uri(base: str) -> str:
    """The checked directory as a URI, always ending in a separator.

    A trailing slash is what says "directory" in a URI, and it is what keeps
    joining a relative file onto it from producing `configsnorth/agg1.cfg`.
    """
    if not base:
        return "./"
    posix = PurePath(base).as_posix().rstrip("/")
    return f"{posix}/" if posix else "/"


def _join(directory: str, file: str) -> str:
    if directory == "./":
        return file
    return f"{directory}{file}"


# --------------------------------------------------------------------------
# JUnit
# --------------------------------------------------------------------------


def junit(findings: Sequence[Finding], coverage: Sequence[RuleCoverage]) -> str:
    """The rule set as a test report: fired, ran and clean, or never ran.

    One test case per catalogued rule, keyed on the rule rather than on the
    finding, because a test report is a report about *checks* — a rule that
    found nothing has to appear, or the file says only what went wrong and a CI
    dashboard shows a suite that shrinks as the network improves.

    `<skipped>` is the point of the exercise. `cassandra.coverage` distinguishes
    a rule that ran and was satisfied from a rule that never had a fact to
    reason over, and every CI test report already draws that distinction on
    screen; mapping inert to skipped puts it in front of someone without their
    having to know this tool has a `--coverage` flag at all.
    """
    root = ET.Element("testsuites", {"name": TOOL_NAME})
    grouped = _cases(findings, coverage)
    for tier in Tier:
        cases = grouped[tier]
        if not cases:
            continue
        suite = ET.SubElement(root, "testsuite", {"name": f"{TOOL_NAME}.{tier.value}"})
        for case in cases:
            _testcase(suite, case)
        _write_counts(suite, cases)
    _write_counts(root, [case for cases in grouped.values() for case in cases])

    ET.indent(root)
    body = ET.tostring(root, encoding="unicode")
    return f"{_XML_DECLARATION}\n{body}\n"


@dataclass(frozen=True, slots=True, kw_only=True)
class _Case:
    """One rule as a test case: what it found, or why it was never asked."""

    rule: str
    classname: str
    findings: tuple[Finding, ...]
    skip_reason: str = ""

    @property
    def failed(self) -> bool:
        return bool(self.findings)

    @property
    def skipped(self) -> bool:
        return not self.findings and bool(self.skip_reason)


def _cases(
    findings: Sequence[Finding], coverage: Sequence[RuleCoverage]
) -> dict[Tier, list[_Case]]:
    """Every rule as a case, in coverage order, grouped by tier.

    A rule that produced findings but has no coverage entry still gets a case,
    appended after the assessed ones in its tier. That combination should not
    happen — the coverage module assesses every catalogued rule — and if it ever
    does, the failure mode has to be a visible extra test rather than a finding
    that quietly vanished on its way to the report.
    """
    by_rule: dict[str, list[Finding]] = {}
    for finding in rank(list(findings)):
        by_rule.setdefault(finding.rule, []).append(finding)

    grouped: dict[Tier, list[_Case]] = {tier: [] for tier in Tier}
    for entry in coverage:
        grouped[entry.tier].append(
            _Case(
                rule=entry.rule,
                classname=entry.module,
                findings=tuple(by_rule.pop(entry.rule, ())),
                skip_reason="" if entry.applicable else (entry.reason or "inert"),
            )
        )
    for rule_id, unassessed in by_rule.items():
        tier = unassessed[0].tier
        grouped[tier].append(
            _Case(
                rule=rule_id,
                classname=f"{TOOL_NAME}.{tier.value}",
                findings=tuple(unassessed),
            )
        )
    return grouped


def _write_counts(element: ET.Element, cases: Sequence[_Case]) -> None:
    """Counts last, so every element reads name first and numbers after.

    `errors` is always zero and is written anyway: a parser that treats a
    missing attribute as unknown rather than as zero should not have to guess,
    and a check that had nothing to look at is a skip here, never an error.
    """
    element.set("tests", str(len(cases)))
    element.set("failures", str(sum(1 for case in cases if case.failed)))
    element.set("skipped", str(sum(1 for case in cases if case.skipped)))
    element.set("errors", "0")


def _testcase(suite: ET.Element, case: _Case) -> None:
    element = ET.SubElement(
        suite,
        "testcase",
        # No `time`. The format allows one and every runner shows it, but it
        # would be the only thing in this file that changes between two runs on
        # the same configs.
        {"name": case.rule, "classname": case.classname},
    )
    if case.failed:
        failure = ET.SubElement(
            element,
            "failure",
            {
                "message": _failure_message(case.findings),
                "type": case.findings[0].severity.value,
            },
        )
        failure.text = "\n\n".join(_finding_text(f) for f in case.findings)
    elif case.skipped:
        ET.SubElement(element, "skipped", {"message": case.skip_reason})


def _failure_message(findings: Sequence[Finding]) -> str:
    """The one line a CI summary shows, which is why the count is in it.

    Several findings from one rule collapse into a single failing case, and a
    summary naming only the first would understate the problem to exactly the
    reader who is not going to open the detail.
    """
    first = f"{findings[0].device}: {findings[0].title}"
    if len(findings) == 1:
        return first
    return f"{first} (and {len(findings) - 1} more)"


def _finding_text(finding: Finding) -> str:
    """One finding in full, including where it is written.

    The location is prose here rather than a structured field: JUnit has nowhere
    to put a file and a line, and a reader who has to open the configuration
    still needs to be told which one (PROJECT.md §5.4).
    """
    lines = [
        f"{finding.severity.value} {finding.device}  {finding.title}",
        f"  {finding.detail}",
    ]
    if finding.source:
        lines.append(f"  source: {finding.source}")
    if finding.trigger:
        lines.append(f"  trigger: {finding.trigger}")
    lines += [f"  evidence: {item}" for item in finding.evidence]
    if finding.remedy:
        lines.append(f"  fix: {finding.remedy}")
    lines += [f"    {line}" for line in finding.change]
    lines.append(f"  rule: {finding.rule} ({finding.tier.value})")
    return "\n".join(lines)
