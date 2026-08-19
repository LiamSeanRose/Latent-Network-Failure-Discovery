"""Which checks had something to look at, and which had nothing.

"No findings" is two claims wearing one face. Either every rule ran and none of
them found anything, or most of the rule set never had a fact to reason over: no
BGP was parsed, no BFD session exists, one device was handed to a rule that
compares two. The first is reassuring. The second is a measurement that was never
taken, and printing it as silence is the most expensive lie this tool can tell.

Separating them is done by watching the rules run, not by keeping a list of what
each one needs. A list is a second copy of the rule set, written by hand, correct
until the first rule someone edits — the failure `catalogue.py` exists to avoid.
So the fact pack is wrapped in a recorder that notes every field each rule reads
and what came back, the real rule functions are run against it, and the verdict
is read off what the rule was actually handed.

Three observations decide it, and a rule is called inert only when all three
agree:

1. **It produced nothing.** A rule that fired is applicable, and no inference is
   allowed to contradict that.
2. **It never reached its decision.** Every rule ends at a comparison — the `if`
   that guards its `Finding`, or the statement immediately before it. Whether
   that point executed is read from line counts, so a rule that got all the way
   to its comparison and judged the network fine is never called inert.
3. **Something it read was absent.** Either a collection it read held nothing on
   every read, or a guard that threw away every candidate it was offered names a
   fact the pack does not carry: a field unset on every record, a container that
   only ever held one element and was never opened, or device identity where the
   collection holds a single device.

Requiring all three is what keeps the report from over-claiming in the direction
that matters. Saying a check did not run when it did is far worse than the
reverse, so every uncertainty resolves to "applicable".

**What this deliberately does not claim.** A rule that reached its comparison is
reported as applicable, and that is all the report knows about it. Whether it
could *conceivably* have fired is a question about the meaning of the rule's own
arithmetic, and it is not decidable from outside the rule. Two shapes are known
to be reported as applicable when a person would call them inert, and both are
understatements of the gap rather than overstatements of the coverage:

* A rule that writes its defect test and its not-enough-material test as one
  expression. `if len(sized) < 2 or len(values) < 2: continue` is both "fewer
  than two interfaces declare an MTU" and "the ones that do agree", and nothing
  outside the rule can split them.
* A rule whose pairing happens inside a local list — `itertools.permutations`
  over members already copied out of the pack. The loop is simply never entered,
  and the container it came from is no longer in view.

Both were left alone rather than guessed at. `docs/RULES.md` carries what each
rule stays silent about; this report carries only what it was handed.

Neither needs an API to fix, and neither should get one — a rule set that has to
declare its own preconditions is a rule set with two places to keep in step, and
the second one goes stale. What both want is a convention in the rules
themselves: **write the not-enough-material guard and the no-defect guard as two
statements, and do the pairing where the container is still in view.** Splitting
`if len(sized) < 2 or len(values) < 2: continue` into two `if`s costs a line and
makes the first one measurable from here; iterating pairs of `group.members`
rather than pairs of a list already copied out of it does the same. Both are
things a rule may do or not do freely, and nothing breaks when a rule does not.

Every rule in the catalogue gets an entry, including any this module cannot
arrange to run, which appears as an explicit "could not be assessed" rather than
as an absence from the list.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import re
import sys
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from types import FrameType, ModuleType
from typing import Final

from cassandra.catalogue import SOURCES, RuleDoc, catalogue
from cassandra.factpack import schema
from cassandra.factpack.schema import StaticFactPack
from cassandra.findings import Finding, Tier
from cassandra.timing.timer_rules import DEFAULT_LIMITS, Limits

# Purely cosmetic. The schema names its classes and fields for machines, and the
# reader of a coverage report is not one: `BgpProcess` is said as "BGP process"
# and `mtu_bytes` as "MTU bytes". A term missing from here renders in lower case,
# which is untidy and nothing worse, so this may lag the schema without becoming
# wrong.
_ACRONYMS: Final[frozenset[str]] = frozenset(
    {
        "bfd",
        "bgp",
        "fhrp",
        "glbp",
        "hsrp",
        "igp",
        "ip",
        "ipv4",
        "ipv6",
        "isis",
        "l1",
        "l2",
        "l3",
        "lacp",
        "lag",
        "lsa",
        "mac",
        "mtu",
        "nos",
        "ospf",
        "prc",
        "sla",
        "spf",
        "stp",
        "svi",
        "vlan",
        "vrf",
        "vrrp",
    }
)

# The schema carries the unit in the name of every timer field. In a sentence
# about a value nobody configured the unit is noise: "no FHRP timers record sets
# hold time" says it, "sets hold time ms" does not say it better.
_UNITS: Final[tuple[str, ...]] = ("_ms", "_s")

# A rule that throws a candidate away does it with an `if` whose entire body is
# one of these. Anything else is the rule doing its work.
_SKIPS: Final = (ast.Continue, ast.Break, ast.Return)

# The fields that say which device a fact belongs to: `device` on nearly
# everything, `id` on `Device` itself, and `devices` for the collection.
_IDENTITY: Final[frozenset[str]] = frozenset({"device", "devices", "id"})

_SINGLE_DEVICE: Final = "only one device in the collection"


# --------------------------------------------------------------------------
# What the report says
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class RuleCoverage:
    """One rule, and whether this fact pack gave it anything to decide on."""

    rule: str
    tier: Tier
    module: str
    function: str
    applicable: bool
    findings: int = 0
    reason: str = ""
    detail: tuple[str, ...] = ()

    @property
    def sort_key(self) -> tuple[int, str]:
        return (0 if self.applicable else 1, self.rule)


# --------------------------------------------------------------------------
# Watching a rule read the fact pack
# --------------------------------------------------------------------------


class _Reads:
    """Every field read during one evaluation, and what it returned.

    A path names a shape rather than an object: `fhrp_groups[].members` is "the
    members of some group", however many groups there were. That is the level the
    question is asked at — what matters is that no group had a second member, not
    which group.
    """

    def __init__(self) -> None:
        self.order: list[str] = []
        self.sizes: dict[str, list[int]] = {}
        self.unset: dict[str, list[int]] = {}
        self.owner: dict[str, type] = {}
        self.consumed: set[str] = set()
        self.records: set[str] = set()

    def _seen(self, path: str, owner: type) -> None:
        if path not in self.sizes:
            self.order.append(path)
            self.sizes[path] = []
            self.unset[path] = [0, 0]
            self.owner[path] = owner
        # A path counts as opened once anything below it is read, which is what
        # tells a container the rule looked inside from one it only counted.
        head = path.rpartition("[].")[0]
        if head:
            self.consumed.add(head)

    def collection(self, path: str, owner: type, size: int, *, records: bool) -> None:
        self._seen(path, owner)
        self.sizes[path].append(size)
        if records:
            self.records.add(path)

    def value(self, path: str, owner: type, value: object) -> None:
        self._seen(path, owner)
        counts = self.unset[path]
        counts[0] += 1
        if value is None:
            counts[1] += 1

    def empty(self) -> list[str]:
        """Collections that held nothing on every read the rule made."""
        return [
            path
            for path in self.order
            if self.sizes[path] and not any(self.sizes[path])
        ]

    def never_set(self, field: str) -> list[str]:
        """Paths ending in this field that were unset on every record seen."""
        return [
            path
            for path in self.order
            if _field(path) == field
            and self.unset[path][0]
            and self.unset[path][0] == self.unset[path][1]
        ]

    def solitary(self, field: str) -> list[str]:
        """Collections named by this field that offered one element, unopened.

        A rule that reads `group.members`, finds one, and never reads a field of
        it has rejected the container on its size. It was handed something it
        could not use, which is not the same as something it judged.
        """
        return [
            path
            for path in self.order
            if _field(path) == field
            and path in self.records
            and path not in self.consumed
            and self.sizes[path]
            and max(self.sizes[path]) == 1
        ]


class _Watched:
    """A stand-in for one fact-pack object that reports what is asked of it.

    Attribute access is the only thing intercepted. Equality, hashing and text
    pass through to the real object, so a rule that puts these in a set or
    interpolates one into a message behaves exactly as it does without the
    watcher — `tests/test_coverage.py` holds that to the findings themselves,
    because a watcher that changed a verdict would make this a report about
    something other than the tool.
    """

    __slots__ = ("_path", "_reads", "_subject")

    def __init__(self, subject: object, path: str, reads: _Reads) -> None:
        object.__setattr__(self, "_subject", subject)
        object.__setattr__(self, "_path", path)
        object.__setattr__(self, "_reads", reads)

    def __getattr__(self, name: str) -> object:
        subject = object.__getattribute__(self, "_subject")
        value = getattr(subject, name)
        if name.startswith("__"):
            return value
        path = object.__getattribute__(self, "_path")
        reads: _Reads = object.__getattribute__(self, "_reads")
        return _watch(value, f"{path}.{name}" if path else name, type(subject), reads)

    def __eq__(self, other: object) -> bool:
        subject = object.__getattribute__(self, "_subject")
        if isinstance(other, _Watched):
            return bool(subject == object.__getattribute__(other, "_subject"))
        return bool(subject == other)

    def __hash__(self) -> int:
        return hash(object.__getattribute__(self, "_subject"))

    def __str__(self) -> str:
        return str(object.__getattribute__(self, "_subject"))

    def __repr__(self) -> str:
        return repr(object.__getattribute__(self, "_subject"))


def _is_record(value: object) -> bool:
    return dataclasses.is_dataclass(value) and not isinstance(value, type)


def _watch(value: object, path: str, owner: type, reads: _Reads) -> object:
    if _is_record(value):
        reads.value(path, owner, value)
        return _Watched(value, path, reads)
    if isinstance(value, tuple):
        records = bool(value) and _is_record(value[0])
        if records or _element_class(owner, _field(path)) is not None:
            reads.collection(path, owner, len(value), records=records)
            if records:
                return tuple(_watch(item, f"{path}[]", owner, reads) for item in value)
            return value
    reads.value(path, owner, value)
    return value


# --------------------------------------------------------------------------
# Naming what was absent
# --------------------------------------------------------------------------

_TUPLE_OF: Final = re.compile(r"tuple\[\s*([A-Za-z_][A-Za-z0-9_.]*)")
_WORD: Final = re.compile(r"[A-Z][a-z]*[0-9]*|[a-z]+[0-9]*|[0-9]+")

_ELEMENTS: Final[dict[tuple[type, str], type | None]] = {}


def _field(path: str) -> str:
    return path.rpartition(".")[2]


def _element_class(owner: type, field: str) -> type | None:
    """The record type a `tuple[...]` field holds, or None if it holds values.

    The annotation is read as text rather than resolved: the schema uses
    postponed annotations and several of its aliases are `type` statements that
    do not resolve at runtime. The name is then looked up in the schema, which is
    what tells a tuple of VLAN numbers from a tuple of records — the first is a
    value like any other, the second is a collection a rule iterates and can find
    empty.
    """
    key = (owner, field)
    if key in _ELEMENTS:
        return _ELEMENTS[key]
    found: type | None = None
    annotation = getattr(owner, "__annotations__", {}).get(field)
    if isinstance(annotation, str):
        match = _TUPLE_OF.search(annotation)
        if match is not None:
            named = getattr(schema, match.group(1).rpartition(".")[2], None)
            if isinstance(named, type) and dataclasses.is_dataclass(named):
                found = named
    _ELEMENTS[key] = found
    return found


def _words(name: str) -> str:
    """`BgpProcess` and `mtu_bytes` both as a person would say them."""
    parts = [part for chunk in name.split("_") for part in _WORD.findall(chunk)]
    return " ".join(
        part.upper() if part.lower() in _ACRONYMS else part.lower() for part in parts
    )


def _field_words(field: str) -> str:
    for unit in _UNITS:
        if field.endswith(unit):
            field = field[: -len(unit)]
            break
    return _words(field)


def _no_collection(reads: _Reads, path: str) -> str:
    element = _element_class(reads.owner[path], _field(path))
    noun = _words(element.__name__) if element else _field_words(_field(path))
    return f"no {noun} in these configs"


def _no_value(reads: _Reads, path: str) -> str:
    return (
        f"no {_words(reads.owner[path].__name__)} in these configs sets "
        f"{_field_words(_field(path))}"
    )


def _one_element(reads: _Reads, path: str) -> str:
    element = _field_words(_field(path)).removesuffix("s")
    return f"no {_words(reads.owner[path].__name__)} has more than one {element}"


# --------------------------------------------------------------------------
# Reading the rules
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class _Guard:
    """An `if` whose whole body is a skip — the shape a rejection takes."""

    test_line: int
    skip_line: int
    source: str
    fields: frozenset[str]
    identity: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class _Shape:
    """What one module's source says about how its rules reach a finding.

    Parsed once per module and kept, because `assess` asks the same questions of
    the same source forty-one times in a row.
    """

    file: str
    tree: ast.Module
    source: str
    guards: dict[str, tuple[_Guard, ...]]
    decisions: dict[tuple[str, str], tuple[tuple[int, int], ...]]


_SHAPES: Final[dict[str, _Shape]] = {}


def _attributes(node: ast.AST, bound: dict[str, ast.expr]) -> frozenset[str]:
    """The fact-pack fields an expression looks at, through one local name.

    `if len(group.members) < 2` names `members` outright. `hold =
    timers.hold_time_ms` followed by `if hold is None` names it one step away,
    and one step is enough for the guards in this rule set — a name bound once in
    the same function is resolved, and anything more indirect is left alone
    rather than guessed at.
    """
    found: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Attribute):
            found.add(child.attr)
        elif isinstance(child, ast.Name) and child.id in bound:
            found |= {
                inner.attr
                for inner in ast.walk(bound[child.id])
                if isinstance(inner, ast.Attribute)
            }
    return frozenset(found)


def _identity(test: ast.expr, bound: dict[str, ast.expr]) -> bool:
    """Does this guard turn on which device a fact belongs to?

    Two shapes say so, and only two. The guard names a device field outright —
    `a_interface.device == b_interface.device`, `len(pack.devices) < 2` — or it
    counts a collection of them, as `len(devices) < 2` does over a set built from
    `member.device`. A device field that merely passes through a guard on its way
    to being a dictionary key says nothing about devices, which is why a bound
    name is only followed inside a `len`.
    """
    if _direct(test) & _IDENTITY:
        return True
    for node in ast.walk(test):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Name) and node.func.id == "len"):
            continue
        for argument in node.args:
            if _attributes(argument, bound) & _IDENTITY:
                return True
    return False


def _direct(node: ast.AST) -> frozenset[str]:
    """Attribute names written in the expression itself."""
    return frozenset(
        child.attr for child in ast.walk(node) if isinstance(child, ast.Attribute)
    )


def _bindings(fn: ast.FunctionDef) -> dict[str, ast.expr]:
    """Local names assigned exactly once, so a guard can be read through them."""
    once: dict[str, ast.expr] = {}
    twice: set[str] = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                if target.id in once:
                    twice.add(target.id)
                once[target.id] = node.value
    return {name: value for name, value in once.items() if name not in twice}


def _parents(fn: ast.FunctionDef) -> dict[ast.AST, ast.AST]:
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(fn):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def _statement(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> ast.stmt | None:
    current: ast.AST | None = node
    while current is not None and not isinstance(current, ast.stmt):
        current = parents.get(current)
    return current if isinstance(current, ast.stmt) else None


def _block(
    statement: ast.stmt, parents: dict[ast.AST, ast.AST]
) -> tuple[list[ast.stmt], ast.stmt | None]:
    """The list of statements holding this one, and the block's own header."""
    parent: ast.AST | None = parents.get(statement)
    while parent is not None:
        for name in ("body", "orelse", "finalbody"):
            block = getattr(parent, name, None)
            if isinstance(block, list) and statement in block:
                return block, parent if isinstance(parent, ast.stmt) else None
        parent = parents.get(parent)
    return [statement], None


def _skips(statement: ast.stmt | None) -> bool:
    """Is this the `if ...: continue` shape a rule throws a candidate away with?"""
    return (
        isinstance(statement, ast.If)
        and len(statement.body) == 1
        and isinstance(statement.body[0], _SKIPS)
    )


def _span(node: ast.stmt | ast.expr) -> tuple[int, int]:
    return (node.lineno, node.end_lineno or node.lineno)


def _decision(goal: ast.expr, parents: dict[ast.AST, ast.AST]) -> tuple[int, int]:
    """The lines whose execution means the rule reached its comparison.

    The comparison is whatever stands between the last candidate the rule threw
    away and the finding it did not produce. So: the `if` the finding sits
    inside, where it sits inside one; otherwise the statement in front of it,
    unless that statement is itself a rejection, in which case nothing stands
    between them and reaching the finding is the only evidence there is.

    Reading it any earlier would report a rule as having decided when all it did
    was reject everything it was handed, which is the distinction this module
    exists to draw.
    """
    statement = _statement(goal, parents)
    if statement is None:
        return _span(goal)
    block, header = _block(statement, parents)
    index = block.index(statement)
    if index > 0:
        before = block[index - 1]
        if not _skips(before):
            return _span(before)
    elif isinstance(header, ast.If) and not _skips(header):
        return _span(header.test)
    return _span(statement)


def _goals(fn: ast.FunctionDef, rule_id: str, constructor: str) -> list[ast.expr]:
    """Where in this function a finding for one rule is produced.

    Usually a `Finding(rule="...")` written in place. `timing.sequences` builds
    its two findings in named functions and calls them from the enumeration, so a
    call to the function the catalogue names for the rule counts as well.
    """
    found: list[ast.expr] = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        name = node.func.id if isinstance(node.func, ast.Name) else ""
        if name == constructor and constructor != fn.name:
            found.append(node)
            continue
        if name != "Finding":
            continue
        for keyword in node.keywords:
            if (
                keyword.arg == "rule"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value == rule_id
            ):
                found.append(node)
    return found


def _shape(module: ModuleType) -> _Shape:
    """One rule module's source, parsed, with every rejection point in it."""
    cached = _SHAPES.get(module.__name__)
    if cached is not None:
        return cached
    try:
        source = inspect.getsource(module)
    except OSError:
        source = ""
    tree = ast.parse(source) if source else ast.Module(body=[], type_ignores=[])
    guards: dict[str, tuple[_Guard, ...]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        bound = _bindings(node)
        found: list[_Guard] = []
        for inner in ast.walk(node):
            if not isinstance(inner, ast.If) or len(inner.body) != 1:
                continue
            skip = inner.body[0]
            if not isinstance(skip, _SKIPS):
                continue
            text = ast.get_source_segment(source, inner.test) or ""
            found.append(
                _Guard(
                    test_line=inner.test.lineno,
                    skip_line=skip.lineno,
                    source=" ".join(text.split()),
                    fields=_attributes(inner.test, bound),
                    identity=_identity(inner.test, bound),
                )
            )
        guards[node.name] = tuple(found)
    shape = _Shape(
        file=module.__file__ or "",
        tree=tree,
        source=source,
        guards=guards,
        decisions={},
    )
    _SHAPES[module.__name__] = shape
    return shape


def _decisions(
    shape: _Shape, entry: str, rule_id: str, function: str
) -> tuple[tuple[int, int], ...]:
    """Line ranges that, if executed, mean the rule reached its comparison."""
    key = (entry, rule_id)
    cached = shape.decisions.get(key)
    if cached is not None:
        return cached
    ranges: tuple[tuple[int, int], ...] = ()
    for node in ast.walk(shape.tree):
        if isinstance(node, ast.FunctionDef) and node.name == entry:
            parents = _parents(node)
            ranges = tuple(
                _decision(goal, parents) for goal in _goals(node, rule_id, function)
            )
            break
    shape.decisions[key] = ranges
    return ranges


# --------------------------------------------------------------------------
# Running the rule set
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class _Group:
    """One callable that produces findings, and the rule ids it can produce.

    Most rules are one function each. `timing.sequences` keeps no registry — its
    findings come out of a single enumeration — so its two rule ids share one
    evaluation and therefore one set of observations.
    """

    module: ModuleType
    entry: Callable[..., object]
    rules: tuple[str, ...]


def _groups(docs: Sequence[RuleDoc]) -> tuple[list[_Group], list[RuleDoc]]:
    """Pair every catalogued rule with the callable that evaluates it.

    A module with a `RULES` registry is invoked one rule at a time. One without a
    registry is invoked through `analyse`, which is the only way in.
    """
    by_name = {module.__name__: module for module in SOURCES}
    order: list[tuple[ModuleType, Callable[..., object]]] = []
    rules: dict[int, list[str]] = {}
    orphans: list[RuleDoc] = []

    for doc in docs:
        module = by_name.get(doc.module)
        if module is None:
            orphans.append(doc)
            continue
        registry = getattr(module, "RULES", None)
        entry = getattr(module, doc.function, None)
        if registry is None or entry not in registry:
            entry = getattr(module, "analyse", None)
        if entry is None:
            orphans.append(doc)
            continue
        key = id(entry)
        if key not in rules:
            rules[key] = []
            order.append((module, entry))
        rules[key].append(doc.id)

    return (
        [
            _Group(module=module, entry=entry, rules=tuple(rules[id(entry)]))
            for module, entry in order
        ],
        orphans,
    )


def _call(entry: Callable[..., object], pack: object, limits: Limits) -> list[Finding]:
    """Invoke a rule, passing the limits only to the rules that take them.

    A rule is a generator and an `analyse` is a list; both are drained here,
    because an unread generator reads nothing and would look exactly like a rule
    with no facts to read.
    """
    parameters = inspect.signature(entry).parameters
    produced = entry(pack, limits) if len(parameters) > 1 else entry(pack)
    return list(produced)  # type: ignore[call-overload]


def _observe(
    group: _Group, pack: StaticFactPack, limits: Limits, files: frozenset[str]
) -> tuple[list[Finding], _Reads, Counter[tuple[str, int]]]:
    """Run one group against a watched pack, counting the lines it executes."""
    reads = _Reads()
    watched = _Watched(pack, "", reads)
    hits: Counter[tuple[str, int]] = Counter()

    def inside(frame: FrameType, event: str, arg: object) -> object:
        if event == "line":
            hits[(frame.f_code.co_filename, frame.f_lineno)] += 1
        return inside

    def entering(frame: FrameType, event: str, arg: object) -> object:
        return inside if frame.f_code.co_filename in files else None

    previous = sys.gettrace()
    sys.settrace(entering)
    try:
        findings = _call(group.entry, watched, limits)
    finally:
        sys.settrace(previous)
    return findings, reads, hits


def _rejections(
    shape: _Shape, entry: str, hits: Counter[tuple[str, int]]
) -> list[_Guard]:
    """Guards that were reached and threw away every candidate reaching them."""
    return [
        guard
        for guard in shape.guards.get(entry, ())
        if hits[(shape.file, guard.test_line)]
        and hits[(shape.file, guard.test_line)] == hits[(shape.file, guard.skip_line)]
    ]


def _absences(guard: _Guard, reads: _Reads, devices: int) -> list[str]:
    """What the pack failed to supply to a guard that rejected everything."""
    found: list[str] = []
    if devices < 2 and guard.identity:
        found.append(_SINGLE_DEVICE)
        # Worth quoting: the guard is the line that proves the count mattered to
        # this rule, rather than to the collection in general.
        found.append(f"rejected at `{guard.source}`")
    for field in sorted(guard.fields - _IDENTITY):
        found += [_one_element(reads, path) for path in reads.solitary(field)]
        found += [_no_value(reads, path) for path in reads.never_set(field)]
    return found


def _verdict(
    doc: RuleDoc,
    fired: int,
    reads: _Reads,
    reached: bool,
    rejections: Sequence[_Guard],
    devices: int,
) -> RuleCoverage:
    """What this pack gave one rule, in the order the answers are trustworthy."""
    if fired:
        return _entry(doc, applicable=True, findings=fired)
    if reached:
        return _entry(doc, applicable=True)

    absences = [_no_collection(reads, path) for path in reads.empty()]
    for guard in rejections:
        absences += _absences(guard, reads, devices)
    if not absences:
        return _entry(doc, applicable=True)

    ordered = list(dict.fromkeys(absences))
    return _entry(doc, applicable=False, reason=ordered[0], detail=tuple(ordered[1:]))


def _entry(
    doc: RuleDoc,
    *,
    applicable: bool,
    findings: int = 0,
    reason: str = "",
    detail: tuple[str, ...] = (),
) -> RuleCoverage:
    return RuleCoverage(
        rule=doc.id,
        tier=doc.tier,
        module=doc.module,
        function=doc.function,
        applicable=applicable,
        findings=findings,
        reason=reason,
        detail=detail,
    )


def assess(
    pack: StaticFactPack, *, limits: Limits = DEFAULT_LIMITS
) -> tuple[RuleCoverage, ...]:
    """Every catalogued rule, and whether this fact pack gave it anything.

    Ordered as the catalogue orders it, so a coverage line and a rule entry read
    side by side.
    """
    docs = catalogue()
    groups, orphans = _groups(docs)
    by_id = {doc.id: doc for doc in docs}
    files = frozenset(
        module.__file__ for module in SOURCES if module.__file__ is not None
    )
    covered: dict[str, RuleCoverage] = {}

    for group in groups:
        findings, reads, hits = _observe(group, pack, limits, files)
        counts = Counter(finding.rule for finding in findings)
        shape = _shape(group.module)
        name = group.entry.__name__
        rejections = _rejections(shape, name, hits)
        for rule_id in group.rules:
            doc = by_id[rule_id]
            reached = any(
                any(hits[(shape.file, line)] for line in range(start, end + 1))
                for start, end in _decisions(shape, name, rule_id, doc.function)
            )
            covered[rule_id] = _verdict(
                doc, counts[rule_id], reads, reached, rejections, len(pack.devices)
            )

    for doc in orphans:
        # Visible rather than absent. A rule the catalogue knows about and this
        # module cannot run is a defect in this module, and dropping it from the
        # list would reintroduce exactly the silence the report exists to remove.
        covered[doc.id] = _entry(
            doc,
            applicable=False,
            reason="could not be assessed: nothing in the module evaluates it",
        )

    return tuple(covered[doc.id] for doc in docs)


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def inert(coverage: Sequence[RuleCoverage]) -> tuple[RuleCoverage, ...]:
    """The checks this pack gave nothing to, in catalogue order."""
    return tuple(entry for entry in coverage if not entry.applicable)


def summary(coverage: Sequence[RuleCoverage], *, named: int = 3) -> str:
    """The short form, for the end of a check.

    The count is the headline: a run where a third of the rule set never had an
    input is a different result from a clean one, and noticing that should not
    take reading forty-one lines. A few names say what kind of gap it is.
    """
    total = len(coverage)
    quiet = inert(coverage)
    if not total:
        return "coverage: no rules to report on."
    if not quiet:
        return f"coverage: all {total} checks had something to look at."

    lines = [
        f"coverage: {total - len(quiet)} of {total} checks had something to look "
        f"at. {len(quiet)} {'was' if len(quiet) == 1 else 'were'} inert:"
    ]
    lines += [f"  {entry.rule} ({entry.reason})" for entry in quiet[:named]]
    if len(quiet) > named:
        lines.append(
            f"  and {len(quiet) - named} more — `--coverage full` lists every "
            f"check and what it was missing"
        )
    return "\n".join(lines)


def render_text(coverage: Sequence[RuleCoverage]) -> str:
    """Every rule, the ones that ran first, with the reason each inert one had."""
    if not coverage:
        return "no rules to report on"
    width = max(len(entry.rule) for entry in coverage)
    lines: list[str] = []
    for entry in sorted(coverage, key=lambda item: item.sort_key):
        if entry.applicable:
            found = (
                f"{entry.findings} finding{'' if entry.findings == 1 else 's'}"
                if entry.findings
                else "nothing to report"
            )
            lines.append(f"ran    {entry.rule:<{width}}  {found}")
            continue
        lines.append(f"INERT  {entry.rule:<{width}}  {entry.reason}")
        lines += [f"       {'':<{width}}  {note}" for note in entry.detail]
    return "\n".join([*lines, "", summary(coverage)])
