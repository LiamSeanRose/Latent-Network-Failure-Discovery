"""The rule catalogue, derived from the rules themselves.

A user who reads `rule: bgp-peer-off-subnet` in the output needs three things the
finding cannot carry: what the rule checks, why that matters, and — the part that
decides whether silence is reassuring — when it deliberately does not fire.

A hand-written catalogue answers those until the first rule someone forgets to
add to it, after which it answers them wrongly, which is worse. So nothing here
is hand-written. The rule set is read from the registries at runtime, the
identifiers, tiers, severities and message templates come from the code that
constructs each `Finding`, the prose comes from the rule docstrings, and the
silence notes come from the tests that assert a rule stays quiet. Where a rule
has no docstring the catalogue says so rather than inventing one — an entry that
reads "undocumented" is a defect anyone can see, which is the point.

Regenerate the committed copy with:

    python -m cassandra.catalogue --write

`tests/test_catalogue.py` fails when it is stale, so the file cannot rot quietly.
"""

from __future__ import annotations

import argparse
import ast
import inspect
import re
import sys
import textwrap
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Final

from cassandra.facts import rules as facts_rules
from cassandra.findings import Severity, Tier
from cassandra.timing import sequences, timer_rules

# The three modules that produce findings. `facts.rules` and `timing.timer_rules`
# each keep a `RULES` registry filled by their `@rule` decorator;
# `timing.sequences` has no registry because its findings are emitted by the
# enumeration itself, so every function in it is a candidate. Discovery covers
# both shapes rather than assuming one.
SOURCES: Final[tuple[ModuleType, ...]] = (facts_rules, timer_rules, sequences)

# Where the repository lives when running from a checkout. The tests and the
# docs are not installed with the package, so both lookups degrade to "absent"
# rather than failing when they are not there.
REPO: Final = Path(__file__).resolve().parents[1]
DOCS_PATH: Final = REPO / "docs" / "RULES.md"

SEVERITY_ORDER: Final[tuple[Severity, ...]] = (
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)
TIER_ORDER: Final[tuple[Tier, ...]] = (Tier.FACTS, Tier.TIMING)

TIER_BLURB: Final[dict[Tier, str]] = {
    Tier.FACTS: (
        "Decidable from the configuration text alone (PROJECT.md §2.1). A finding "
        "here is either true of the text or a bug in the rule — no model stands "
        "between the config and the claim."
    ),
    Tier.TIMING: (
        "Derived from the discrete-event timer model (PROJECT.md §2.2). These are "
        "candidates: they say a sequence your configs permit produces the "
        "behaviour, and they carry that sequence so a human can judge it."
    ),
}

_PLACEHOLDER: Final = "{…}"


@dataclass(frozen=True, slots=True, kw_only=True)
class SilenceNote:
    """One test that asserts a rule stays quiet, and what it establishes."""

    note: str
    source: str


@dataclass(frozen=True, slots=True, kw_only=True)
class RuleDoc:
    """Everything the catalogue knows about one rule identifier."""

    id: str
    tier: Tier
    severity: Severity
    module: str
    function: str
    summary: str | None
    checks: tuple[str, ...] = ()
    reports: str = ""
    detail: str = ""
    remedy: str | None = None
    silence: tuple[SilenceNote, ...] = ()

    @property
    def documented(self) -> bool:
        """False when the rule ships with no docstring to explain itself."""
        return self.summary is not None

    @property
    def sort_key(self) -> tuple[int, int, str]:
        return (
            TIER_ORDER.index(self.tier),
            SEVERITY_ORDER.index(self.severity),
            self.id,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class Registry:
    """A module that produces findings, and the silence its tests assert wholesale."""

    module: str
    rules: tuple[RuleDoc, ...]
    silence: tuple[SilenceNote, ...] = ()


# --------------------------------------------------------------------------
# Reading the code
# --------------------------------------------------------------------------


def _tree(module: ModuleType) -> ast.Module:
    return ast.parse(textwrap.dedent(inspect.getsource(module)))


def _registered(module: ModuleType) -> tuple[str, ...] | None:
    """The names the module's registry holds, or None when it keeps no registry."""
    registry: Sequence[Callable[..., object]] | None = getattr(module, "RULES", None)
    if registry is None:
        return None
    return tuple(fn.__name__ for fn in registry)


def _functions(module: ModuleType) -> Iterator[ast.FunctionDef]:
    """Rule functions, in registry order where the module has a registry."""
    tree = _tree(module)
    defined = {
        node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
    }
    names = _registered(module)
    if names is None:
        yield from defined.values()
        return
    for name in names:
        node = defined.get(name)
        if node is not None:
            yield node


def _callee(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _findings(node: ast.AST) -> Iterator[ast.Call]:
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and _callee(child.func) == "Finding":
            yield child


def _keyword(call: ast.Call, name: str) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _literal(call: ast.Call, name: str) -> str | None:
    node = _keyword(call, name)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _enum(call: ast.Call, name: str) -> str | None:
    """The member name of an enum written as `Tier.FACTS` or `Severity.HIGH`."""
    node = _keyword(call, name)
    return node.attr if isinstance(node, ast.Attribute) else None


def _template(node: ast.expr | None) -> str:
    """A message written back with its interpolations replaced by a placeholder.

    The titles and details are f-strings over the facts that tripped the rule, so
    the literal text is the only part that is the same on every finding. Showing
    it with `{…}` where a value goes describes the message honestly without
    pretending to know what any particular device is called.
    """
    if node is None:
        return ""
    if isinstance(node, ast.Constant):
        return str(node.value) if isinstance(node.value, str) else _PLACEHOLDER
    if isinstance(node, ast.JoinedStr):
        return "".join(_template(part) for part in node.values)
    if isinstance(node, ast.FormattedValue):
        return _PLACEHOLDER
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _template(node.left) + _template(node.right)
    return _PLACEHOLDER


def _collapse(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _paragraphs(docstring: str | None) -> tuple[str, ...]:
    if not docstring:
        return ()
    blocks = re.split(r"\n\s*\n", textwrap.dedent(docstring).strip())
    return tuple(_collapse(block) for block in blocks if _collapse(block))


# --------------------------------------------------------------------------
# Reading the tests
# --------------------------------------------------------------------------

_SILENCE_HELPERS: Final = frozenset({"set", "frozenset", "tuple", "dict", "list"})


def _is_empty(node: ast.expr) -> bool:
    """`[]`, `()`, `set()` and friends — the shapes 'nothing was reported' takes."""
    if isinstance(node, ast.List | ast.Tuple | ast.Set) and not node.elts:
        return True
    if isinstance(node, ast.Dict) and not node.keys:
        return True
    return (
        isinstance(node, ast.Call)
        and not node.args
        and _callee(node.func) in _SILENCE_HELPERS
    )


def _quoted(node: ast.AST, known: frozenset[str]) -> set[str]:
    return {
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant)
        and isinstance(child.value, str)
        and child.value in known
    }


def _assignments(fn: ast.FunctionDef) -> dict[str, ast.expr]:
    """Local names bound exactly once, so an assertion can be read through them."""
    bound: dict[str, ast.expr] = {}
    rebound: set[str] = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            if target.id in bound:
                rebound.add(target.id)
            bound[target.id] = node.value
    return {name: value for name, value in bound.items() if name not in rebound}


def _asserted_silent(fn: ast.FunctionDef, known: frozenset[str]) -> set[str] | None:
    """Which rules this test asserts stay quiet — empty set meaning 'all of them'.

    Two shapes carry the claim. `assert "rule-id" not in fired` names the rule
    directly. `assert [f for f in analyse(pack) if f.rule == "rule-id"] == []`
    names it inside the expression that produced nothing; when no identifier
    appears at all the test is asserting the whole rule set is quiet, which is a
    statement about the registry rather than about any one rule.

    None means the test asserts no silence and is not a source at all.
    """
    named: set[str] = set()
    wholesale = False
    bound = _assignments(fn)
    for node in ast.walk(fn):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1:
            continue
        operator, right = node.ops[0], node.comparators[0]
        if isinstance(operator, ast.NotIn):
            named |= _quoted(node.left, known)
            continue
        if not isinstance(operator, ast.Eq | ast.Is) or not _is_empty(right):
            continue
        # `isolated = [...]` then `assert isolated == []` is the same claim
        # written over two lines, so a local name resolves to what it was bound
        # to before the shape is judged.
        left = (
            bound.get(node.left.id, node.left)
            if isinstance(node.left, ast.Name)
            else node.left
        )
        # Only a call or a comprehension can be the *result* of running rules.
        # An empty tuple compared against an attribute is a finding's evidence,
        # not a silent rule set.
        if not isinstance(left, ast.Call | ast.ListComp | ast.SetComp):
            continue
        found = _quoted(left, known)
        named |= found
        wholesale = wholesale or not found
    if named:
        return named
    return set() if wholesale else None


def _humanise(name: str) -> str:
    words = name.removeprefix("test_").replace("_", " ")
    return words[:1].upper() + words[1:]


def _rule_modules(tree: ast.Module) -> set[str]:
    """Which finding-producing modules a test file imports from."""
    names = {module.__name__ for module in SOURCES}
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in names:
            found.add(node.module)
        elif isinstance(node, ast.Import):
            found |= {alias.name for alias in node.names} & names
    return found


def _test_files(tests_dir: Path | None) -> list[Path]:
    directory = tests_dir if tests_dir is not None else REPO / "tests"
    if not directory.is_dir():
        return []
    return sorted(directory.glob("test_*.py"))


def _silence(
    known: frozenset[str], tests_dir: Path | None
) -> tuple[dict[str, list[SilenceNote]], dict[str, list[SilenceNote]]]:
    """Silence notes per rule, and per module for the tests that name no rule."""
    per_rule: dict[str, list[SilenceNote]] = {}
    per_module: dict[str, list[SilenceNote]] = {}
    for path in _test_files(tests_dir):
        tree = ast.parse(path.read_text())
        modules = _rule_modules(tree)
        if not modules:
            # A test that never imports a rule set is not making a claim about
            # one. The web view's filter tests assert a rule id is absent from a
            # page, which is a statement about the filter, not about the rule.
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            if not node.name.startswith("test_"):
                continue
            silent = _asserted_silent(node, known)
            if silent is None:
                continue
            # The whole docstring, because the reasoning for a deliberate
            # silence is usually in the sentences after the first one. A test
            # that never explained itself falls back to its own name, which the
            # convention in this repository makes a readable sentence.
            explanation = " ".join(_paragraphs(ast.get_docstring(node)))
            note = SilenceNote(
                note=explanation or _humanise(node.name),
                source=f"{path.name}::{node.name}",
            )
            if silent:
                for rule_id in sorted(silent):
                    per_rule.setdefault(rule_id, []).append(note)
            elif len(modules) == 1:
                # A whole-set assertion only says something about a rule set it
                # can be attributed to. A test file that touches two of them is
                # ambiguous, so it is dropped rather than guessed at.
                per_module.setdefault(next(iter(modules)), []).append(note)
    return per_rule, per_module


# --------------------------------------------------------------------------
# The catalogue
# --------------------------------------------------------------------------


def _docs_for(
    module: ModuleType, silence: dict[str, list[SilenceNote]]
) -> list[RuleDoc]:
    docs: dict[str, RuleDoc] = {}
    for function in _functions(module):
        paragraphs = _paragraphs(ast.get_docstring(function))
        for call in _findings(function):
            rule_id = _literal(call, "rule")
            tier = _enum(call, "tier")
            severity = _enum(call, "severity")
            if rule_id is None or tier is None or severity is None:
                continue
            if rule_id in docs:
                continue
            docs[rule_id] = RuleDoc(
                id=rule_id,
                tier=Tier[tier],
                severity=Severity[severity],
                module=module.__name__,
                function=function.name,
                summary=paragraphs[0] if paragraphs else None,
                checks=paragraphs[1:],
                reports=_collapse(_template(_keyword(call, "title"))),
                detail=_collapse(_template(_keyword(call, "detail"))),
                remedy=_collapse(_template(_keyword(call, "remedy"))) or None,
                silence=tuple(silence.get(rule_id, ())),
            )
    return list(docs.values())


def registries(tests_dir: Path | None = None) -> tuple[Registry, ...]:
    """Every finding-producing module, its rules, and its rule-set-wide silence."""
    identifiers = frozenset(_rule_ids())
    per_rule, per_module = _silence(identifiers, tests_dir)
    return tuple(
        Registry(
            module=module.__name__,
            rules=tuple(_docs_for(module, per_rule)),
            silence=tuple(per_module.get(module.__name__, ())),
        )
        for module in SOURCES
    )


def _rule_ids() -> set[str]:
    """The identifiers alone, needed before the tests can be read for silence."""
    return {
        rule_id
        for module in SOURCES
        for function in _functions(module)
        for call in _findings(function)
        if (rule_id := _literal(call, "rule")) is not None
    }


def catalogue(tests_dir: Path | None = None) -> tuple[RuleDoc, ...]:
    """Every rule the tool can emit, ranked by tier and then by severity.

    This is the structured form: a `cassandra rules` command and the web view
    both read it, so neither has to know where rules live or how they register.
    """
    docs = [doc for registry in registries(tests_dir) for doc in registry.rules]
    return tuple(sorted(docs, key=lambda doc: doc.sort_key))


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

_PREAMBLE: Final = """# Rule catalogue

Every check this tool can report, what trips it, and — the part a clean run
depends on — when it deliberately stays quiet.

Generated from the rules themselves by `python -m cassandra.catalogue --write`.
Do not edit by hand: `tests/test_catalogue.py` regenerates it and fails on any
difference, so an edit here is lost and a new rule that is not documented here
breaks the build.
"""


def _anchor(rule_id: str) -> str:
    return rule_id.replace(" ", "-")


def _index(docs: Sequence[RuleDoc]) -> list[str]:
    lines = [
        "## Index",
        "",
        "| Rule | Tier | Severity | Summary |",
        "| --- | --- | --- | --- |",
    ]
    for doc in docs:
        summary = doc.summary or "_undocumented_"
        lines.append(
            f"| [`{doc.id}`](#{_anchor(doc.id)}) | {doc.tier.value} "
            f"| {doc.severity.value} | {summary} |"
        )
    lines.append("")
    return lines


def _entry(doc: RuleDoc) -> list[str]:
    lines = [
        f"### `{doc.id}`",
        "",
        f"**{doc.severity.value}** · `{doc.module}.{doc.function}`",
        "",
    ]
    if doc.summary is None:
        lines += [
            f"> Undocumented: `{doc.function}` carries no docstring, so the "
            "catalogue has nothing to report beyond the message it emits. "
            "Adding a docstring to the rule fills this in.",
            "",
        ]
    else:
        lines += [doc.summary, ""]
    for paragraph in doc.checks:
        lines += [paragraph, ""]
    if doc.reports:
        lines += [f"**Reports:** {doc.reports}", ""]
    if doc.detail:
        lines += [f"**Detail:** {doc.detail}", ""]
    if doc.remedy:
        lines += [f"**Remedy:** {doc.remedy}", ""]
    lines.append("**Stays silent when:**")
    lines.append("")
    if doc.silence:
        lines += [f"- {note.note}  \n  `{note.source}`" for note in doc.silence]
    else:
        lines.append(
            "- _No test asserts this rule staying quiet. Its silence is "
            "untested, so read it as an absence of evidence._"
        )
    lines.append("")
    return lines


def render_markdown(tests_dir: Path | None = None) -> str:
    """The committed catalogue, grouped by tier, with an index."""
    docs = catalogue(tests_dir)
    lines = [_PREAMBLE, *_index(docs)]

    for tier in TIER_ORDER:
        in_tier = [doc for doc in docs if doc.tier is tier]
        if not in_tier:
            continue
        lines += [f"## {tier.value.upper()} tier", "", TIER_BLURB[tier], ""]
        for doc in in_tier:
            lines += _entry(doc)

    wholesale = [
        (registry, note)
        for registry in registries(tests_dir)
        for note in registry.silence
    ]
    if wholesale:
        lines += [
            "## Silence across a whole rule set",
            "",
            "These tests assert that a rule set reports nothing at all on a given "
            "input. They constrain every rule in the module rather than one of "
            "them, which is what makes a clean run mean something.",
            "",
        ]
        for registry, note in wholesale:
            lines.append(
                f"- **`{registry.module}`** — {note.note}  \n  `{note.source}`"
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_text(rule_id: str | None = None) -> str:
    """The terminal form: one line per rule, or one rule in full.

    Lives here rather than in the CLI so that `cassandra rules` is a few lines of
    wiring over the same structured data the web view reads, and neither has to
    learn where rules are kept.
    """
    docs = catalogue()
    if rule_id is None:
        width = max((len(doc.id) for doc in docs), default=0)
        return "\n".join(
            f"{doc.severity.value:<6} {doc.tier.value:<6} {doc.id:<{width}}  "
            f"{doc.summary or 'undocumented'}"
            for doc in docs
        )

    doc = next((d for d in docs if d.id == rule_id), None)
    if doc is None:
        known = ", ".join(sorted(d.id for d in docs))
        return f"no such rule: {rule_id}\nknown rules: {known}"

    lines = [
        f"{doc.id}  [{doc.tier.value} / {doc.severity.value}]",
        f"  {doc.module}.{doc.function}",
        "",
    ]
    if doc.summary is None:
        lines += ["  (undocumented: the rule carries no docstring)", ""]
    for paragraph in (doc.summary, *doc.checks):
        if paragraph:
            lines += [
                textwrap.fill(
                    paragraph, width=78, initial_indent="  ", subsequent_indent="  "
                ),
                "",
            ]
    if doc.reports:
        lines += [f"  reports: {doc.reports}"]
    if doc.remedy:
        lines += [f"  remedy:  {doc.remedy}"]
    lines += ["", "  stays silent when:"]
    if doc.silence:
        for note in doc.silence:
            lines.append(
                textwrap.fill(
                    note.note,
                    width=78,
                    initial_indent="    - ",
                    subsequent_indent="      ",
                )
            )
            # Never wrapped: a test identifier broken across two lines cannot be
            # pasted back into pytest, which is the only thing it is good for.
            lines.append(f"      {note.source}")
    else:
        lines.append("    - nothing asserts this rule staying quiet")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m cassandra.catalogue",
        description="Render the rule catalogue read out of the rules themselves.",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="write docs/RULES.md instead of printing it",
    )
    args = parser.parse_args(argv)
    markdown = render_markdown()
    if args.write:
        DOCS_PATH.parent.mkdir(parents=True, exist_ok=True)
        DOCS_PATH.write_text(markdown)
        print(f"wrote {DOCS_PATH}", file=sys.stderr)
        return 0
    print(markdown, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
