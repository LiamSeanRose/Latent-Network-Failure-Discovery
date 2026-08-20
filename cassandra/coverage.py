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

**On cost.** Watching a rule set run is not free, and the collections where the
question matters most are the large ones — a report nobody waits for answers
nothing. Three things keep it to roughly a third on top of running the rules
themselves, and none of them changes an answer, because every question asked
here is monotone: *did* this line run, *was* this ever set, *was* this ever
larger than one. Once a path or a line has answered, further reads of it are
arithmetic nobody looks at. So the line watcher disables each location the first
time it fires, the recorder stops counting a path once its answer can no longer
move, and each record is stood in for by one object rather than a fresh one per
read. `tests/test_coverage.py` runs the whole thing under both watchers and
requires the verdicts to match, which is what keeps "faster" from quietly
becoming "different".
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import re
import sys
from collections import Counter
from collections.abc import Callable, Collection, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from types import CodeType, FrameType, ModuleType
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

# `sys.monitoring` has six tool ids and hands out none that is already claimed.
_TOOL_IDS: Final = 6


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
        self.sizes: dict[str, int] = {}
        self.unset: dict[str, list[int]] = {}
        self.owner: dict[str, type] = {}
        self.consumed: set[str] = set()
        self.records: set[str] = set()
        # Paths whose remaining reads cannot change the answer. Every question
        # asked below is monotone — was this ever set, was this ever larger than
        # one — so once a path has answered it, it has answered it for good and
        # the next hundred thousand reads of it are counted and thrown away. The
        # timing model reads a group's members once per simulated millisecond,
        # which is where that stops being a micro-optimisation.
        self.settled: set[str] = set()
        # One stand-in per object per path, kept alongside the object it stands
        # for. A rule can read the same interface a thousand times — the timing
        # model reads every group's members once per simulated millisecond — and
        # the thousandth read says exactly what the first one said. The counts
        # above are still taken on every read; only the wrapping is reused.
        self.stood_in: dict[tuple[str, int], tuple[object, object]] = {}
        # Per path, the field names whose next read cannot teach this anything:
        # a plain value, on a path already settled. Held here rather than worked
        # out each time because it is the answer to the question the stand-in
        # asks most — the timing model reads a timer field millions of times in
        # a run and the first read of it settled the matter.
        self.finished: dict[str, set[str]] = {}

    def nothing_left(self, path: str) -> set[str]:
        found = self.finished.get(path)
        if found is None:
            found = set()
            self.finished[path] = found
        return found

    def _seen(self, path: str, owner: type) -> None:
        if path in self.sizes:
            return
        self.order.append(path)
        # -1 until something reads this path as a collection, which is what
        # keeps a plain value out of the questions asked about containers.
        self.sizes[path] = -1
        self.unset[path] = [0, 0]
        self.owner[path] = owner
        # A path counts as opened once anything below it is read, which is what
        # tells a container the rule looked inside from one it only counted.
        head = path.rpartition("[].")[0]
        if head:
            self.consumed.add(head)

    def collection(self, path: str, owner: type, size: int, *, records: bool) -> None:
        if path in self.settled:
            return
        self._seen(path, owner)
        if size > self.sizes[path]:
            self.sizes[path] = size
        if records:
            self.records.add(path)
        if size > 1:
            # Neither "empty every time" nor "never more than one" can come back
            # from this, and those are the only two questions asked of a size.
            self.settled.add(path)

    def value(self, path: str, owner: type, value: object) -> None:
        if path in self.settled:
            return
        self._seen(path, owner)
        counts = self.unset[path]
        counts[0] += 1
        if value is None:
            counts[1] += 1
        else:
            # One value settles it: "unset on every record" is now false and
            # stays false.
            self.settled.add(path)

    def empty(self) -> list[str]:
        """Collections that held nothing on every read the rule made."""
        return [path for path in self.order if self.sizes[path] == 0]

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
            and self.sizes[path] == 1
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

    __slots__ = ("_done", "_path", "_reads", "_subject")

    def __init__(self, subject: object, path: str, reads: _Reads) -> None:
        object.__setattr__(self, "_subject", subject)
        object.__setattr__(self, "_path", path)
        object.__setattr__(self, "_reads", reads)
        object.__setattr__(self, "_done", reads.nothing_left(path))

    def __getattr__(self, name: str) -> object:
        subject = object.__getattribute__(self, "_subject")
        value = getattr(subject, name)
        # Every read below this line is one the recorder has already learned
        # everything it can from, and it hands back exactly what the slow path
        # would. Shared across every stand-in at this path, so one read of a
        # field settles it for the whole collection.
        if name in object.__getattribute__(self, "_done"):
            return value
        if name.startswith("__"):
            return value
        path = object.__getattribute__(self, "_path")
        reads: _Reads = object.__getattribute__(self, "_reads")
        full = f"{path}.{name}" if path else name
        watched = _watch(value, full, name, type(subject), reads)
        if (
            watched is value
            and full in reads.settled
            and _KINDS.get((type(subject), name)) is _VALUE
        ):
            object.__getattribute__(self, "_done").add(name)
        return watched

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


# What one field of one record type holds. Deciding this costs two `isinstance`
# calls and a dataclass check, and the answer is a property of the schema rather
# than of the network, so it is decided once per field and remembered.
_RECORD: Final = 0
_COLLECTION: Final = 1
_VALUE: Final = 2

_KINDS: Final[dict[tuple[type, str], int]] = {}


def _kind(owner: type, field: str, value: object) -> int:
    """Whether a field holds a record, a collection of them, or a plain value.

    Answered from the schema's own annotation wherever the annotation settles
    it, which is every collection of records in the pack. Two cases are
    deliberately re-decided on every read rather than remembered: a field that
    is unset this time says nothing about what it holds when it is set, and a
    tuple the annotation did not describe has to be judged by what is in it.
    Remembering either would let the first read of a run decide the rest of it.
    """
    key = (owner, field)
    known = _KINDS.get(key)
    if known is not None:
        return known
    if _element_class(owner, field) is not None:
        _KINDS[key] = _COLLECTION
        return _COLLECTION
    if value is None:
        return _VALUE
    if isinstance(value, tuple):
        return _COLLECTION if value and _is_record(value[0]) else _VALUE
    kind = _RECORD if _is_record(value) else _VALUE
    _KINDS[key] = kind
    return kind


def _watch(value: object, path: str, field: str, owner: type, reads: _Reads) -> object:
    kind = _kind(owner, field, value)
    if kind is _VALUE:
        reads.value(path, owner, value)
        return value

    if kind is _RECORD:
        reads.value(path, owner, value)
        key = (path, id(value))
        held = reads.stood_in.get(key)
        if held is None:
            held = (value, _Watched(value, path, reads))
            reads.stood_in[key] = held
        return held[1]

    reads.collection(path, owner, len(value), records=bool(value))  # type: ignore[arg-type]
    key = (path, id(value))
    held = reads.stood_in.get(key)
    if held is None:
        element = f"{path}[]"
        held = (
            value,
            tuple(_element(item, element, owner, reads) for item in value),  # type: ignore[union-attr]
        )
        reads.stood_in[key] = held
    return held[1]


def _element(value: object, path: str, owner: type, reads: _Reads) -> object:
    """One member of a collection of records, noted and stood in for."""
    reads.value(path, owner, value)
    return _Watched(value, path, reads)


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
    return " ".join(_SPELLED.get(part.lower(), _cased(part)) for part in parts)


# Terms whose conventional spelling is neither all upper nor all lower. Kept
# apart from the acronym set because that set is a membership test and these are
# substitutions, and folding them together would mean the set could no longer
# lag the schema harmlessly.
_SPELLED: Final[dict[str, str]] = {"ipv4": "IPv4", "ipv6": "IPv6"}


def _cased(part: str) -> str:
    return part.upper() if part.lower() in _ACRONYMS else part.lower()


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
    """An `if` whose whole body is a skip — the shape a rejection takes.

    `after_line` is the statement standing immediately behind it in the same
    block, and it is how "every candidate was thrown away here" is read off a
    run. Within one block that statement is reachable by exactly one route —
    falling through this guard — so it ran if and only if the test was ever
    false. That makes the question a membership test rather than a tally, which
    is what lets each line be watched once and then left alone.
    """

    test_line: int
    after_line: int
    source: str
    fields: frozenset[str]
    identity: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class _Shape:
    """What one module's source says about how its rules reach a finding.

    Parsed once per module and kept, because `assess` asks the same questions of
    the same source once per rule, and re-walking a fifteen-hundred-line module
    forty-five times to find one function in it costs more than the rules do on
    a small pack.
    """

    file: str
    tree: ast.Module
    source: str
    functions: dict[str, ast.FunctionDef]
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


def _blocks(fn: ast.FunctionDef) -> Iterator[list[ast.stmt]]:
    """Every run of statements in a function, so a statement has neighbours.

    `ast.walk` hands back nodes with no idea what stands beside them, and what
    stands beside a guard is the whole question here.
    """
    for node in ast.walk(fn):
        for _name, value in ast.iter_fields(node):
            if isinstance(value, list) and value and isinstance(value[0], ast.stmt):
                yield value


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
    functions: dict[str, ast.FunctionDef] = {}
    guards: dict[str, tuple[_Guard, ...]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        functions.setdefault(node.name, node)
        bound = _bindings(node)
        found: list[_Guard] = []
        for block in _blocks(node):
            for index, inner in enumerate(block):
                # A guard with nothing behind it in its block guards nothing,
                # and there is no statement whose running would show a candidate
                # got past it. Left out rather than reported on a hunch.
                if not isinstance(inner, ast.If) or not _skips(inner):
                    continue
                if index + 1 >= len(block):
                    continue
                text = ast.get_source_segment(source, inner.test) or ""
                found.append(
                    _Guard(
                        test_line=inner.test.lineno,
                        after_line=block[index + 1].lineno,
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
        functions=functions,
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
    node = shape.functions.get(entry)
    if node is not None:
        parents = _parents(node)
        ranges = tuple(
            _decision(goal, parents) for goal in _goals(node, rule_id, function)
        )
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


def _code_objects(module: ModuleType) -> list[CodeType]:
    """Every piece of compiled code in a module, nested ones included.

    A generator expression inside a rule is its own code object and its lines
    would otherwise go unwatched, which would read as a decision the rule never
    reached.
    """
    where = module.__file__
    found: dict[int, CodeType] = {}
    stack: list[CodeType] = []
    for value in vars(module).values():
        holders = vars(value).values() if isinstance(value, type) else (value,)
        for holder in holders:
            code = getattr(holder, "__code__", None)
            if isinstance(code, CodeType) and code.co_filename == where:
                stack.append(code)
    while stack:
        code = stack.pop()
        if id(code) in found:
            continue
        found[id(code)] = code
        stack += [const for const in code.co_consts if isinstance(const, CodeType)]
    return list(found.values())


class _Trace:
    """Which lines of the rule modules ran, one evaluation at a time.

    Only membership is ever asked of the answer — did this guard reject
    everything, did this rule reach its decision — so the second execution of a
    line carries no information and the millionth carries no information twice.
    `sys.monitoring` is told exactly that: the callback returns `DISABLE`, and
    that location stops being watched for the rest of the evaluation.

    The difference is the whole reason the report is usable on a real archive.
    Rules over two hundred devices execute tens of millions of lines and a few
    hundred distinct ones, and `sys.settrace` charges for every one of them —
    twice over, because a global trace function also intercepts every call the
    recorder makes.

    `settrace` remains the fallback for a process where all six monitoring tool
    ids are already taken, by a debugger or a coverage tool. It records the same
    set to the same fidelity and is simply slower, so a verdict never depends on
    which one ran.
    """

    __slots__ = ("_codes", "_executed", "_files", "_tool")

    def __init__(self, modules: Sequence[ModuleType]) -> None:
        self._codes = [code for module in modules for code in _code_objects(module)]
        self._files = frozenset(
            module.__file__ for module in modules if module.__file__ is not None
        )
        self._executed: set[tuple[str, int]] = set()
        self._tool: int | None = None

    def __enter__(self) -> _Trace:
        monitoring = sys.monitoring
        self._tool = next(
            (tool for tool in range(_TOOL_IDS) if monitoring.get_tool(tool) is None),
            None,
        )
        if self._tool is None:
            return self
        monitoring.use_tool_id(self._tool, "cassandra-coverage")
        try:
            monitoring.register_callback(self._tool, monitoring.events.LINE, self._line)
            for code in self._codes:
                monitoring.set_local_events(self._tool, code, monitoring.events.LINE)
        except BaseException:
            # A tool id is process-wide. Handing it back on the way out of a
            # failed setup keeps a later run — or another tool — from finding
            # every slot taken by a session that never started.
            self.__exit__()
            raise
        return self

    def __exit__(self, *exception: object) -> None:
        monitoring = sys.monitoring
        if self._tool is None:
            return
        for code in self._codes:
            monitoring.set_local_events(self._tool, code, 0)
        monitoring.register_callback(self._tool, monitoring.events.LINE, None)
        monitoring.free_tool_id(self._tool)
        self._tool = None

    @contextmanager
    def watching(self) -> Iterator[set[tuple[str, int]]]:
        """Collect one evaluation's lines, starting from nothing."""
        self._executed = set()
        if self._tool is not None:
            # Re-arms the locations the previous evaluation switched off. Every
            # rule has to be watched from a clean slate or the second rule
            # inherits the first one's silence.
            sys.monitoring.restart_events()
            yield self._executed
            return
        previous = sys.gettrace()
        sys.settrace(self._entering)
        try:
            yield self._executed
        finally:
            sys.settrace(previous)

    def _line(self, code: CodeType, line_number: int) -> object:
        self._executed.add((code.co_filename, line_number))
        return sys.monitoring.DISABLE

    def _inside(self, frame: FrameType, event: str, arg: object) -> object:
        if event == "line":
            self._executed.add((frame.f_code.co_filename, frame.f_lineno))
        return self._inside

    def _entering(self, frame: FrameType, event: str, arg: object) -> object:
        return self._inside if frame.f_code.co_filename in self._files else None


def _observe(
    group: _Group, pack: StaticFactPack, limits: Limits, trace: _Trace
) -> tuple[list[Finding], _Reads, frozenset[tuple[str, int]]]:
    """Run one group against a watched pack, noting the lines it executes."""
    reads = _Reads()
    watched = _Watched(pack, "", reads)
    with trace.watching() as executed:
        findings = _call(group.entry, watched, limits)
    return findings, reads, frozenset(executed)


def _rejections(
    shape: _Shape, entry: str, executed: frozenset[tuple[str, int]]
) -> list[_Guard]:
    """Guards that were reached and threw away every candidate reaching them.

    The test ran and the statement behind it did not, which within one block
    says the test was never false.
    """
    return [
        guard
        for guard in shape.guards.get(entry, ())
        if (shape.file, guard.test_line) in executed
        and (shape.file, guard.after_line) not in executed
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


_CATALOGUED: Final[dict[tuple[str, ...], tuple[RuleDoc, ...]]] = {}


def _catalogued() -> tuple[RuleDoc, ...]:
    """The rule set, read once per process unless the registries change.

    `catalogue()` re-parses every test file to find what each rule is asserted to
    stay quiet about. This report does not use those notes and the parse costs
    more than assessing a small pack does, so the answer is kept — keyed on the
    registered rule functions, so a test that adds or removes one is handed a
    fresh reading rather than the previous run's.
    """
    key = tuple(
        f"{module.__name__}.{function.__name__}"
        for module in SOURCES
        for function in getattr(module, "RULES", ())
    )
    found = _CATALOGUED.get(key)
    if found is None:
        found = catalogue()
        _CATALOGUED[key] = found
    return found


@dataclass(frozen=True, slots=True, kw_only=True)
class UnreadFact:
    """One thing the parsers put in the pack that no rule read on this run.

    The rule side of this report answers "did this check have an input". This is
    the same question from the other end — "did anything read this input" — and
    the two are not the same. A pack can hand every rule something to look at and
    still carry a field that was parsed, tested, documented, and consulted by
    nothing, which is a check nobody has written yet rather than a check that ran.

    Measured per run rather than declared, which is what makes it honest and
    also what makes it narrower than it first reads. A field only one rule
    consults, on a run where that rule returned before reaching it, is on this
    list — correctly, because nothing looked at it, and the rule side of the
    report is where that rule explains why.
    """

    path: str
    label: str
    records: int

    @property
    def sentence(self) -> str:
        many = "" if self.records == 1 else "s"
        return f"{self.label} — stated by {self.records} record{many}, read by no rule"


def _states_something(field: dataclasses.Field[object], value: object) -> bool:
    """Did this record actually say anything at this field?

    The first version asked only whether the value was `None`, `""` or `False`,
    which let three shapes of nothing through and put them on a report whose
    whole subject is what the configs contain.

    An empty tuple is the commonest: `Device.vrfs` is `()` on every device in
    every shipped corpus, and it was reported as "stated by 6 records". A
    sentinel enum is the subtler one — `StpMode.NONE` and `DeviceRole.UNKNOWN`
    both mean "not determined", and both are truthy strings. Neither is
    distinguishable from a real value by looking at it, so the field's own
    declared default is what decides: a value equal to the default is the
    absence of a statement, and one that differs is a statement.

    A stated zero survives, because `0` is a real answer to how many of
    something there are and `int` fields here default to `None` rather than to
    it.
    """
    if value is None or value is False:
        return False
    if isinstance(value, str | tuple | list | frozenset | set | dict) and not value:
        return False
    default = field.default
    if default is not dataclasses.MISSING and value == default:
        # A field left at what the schema declares is a field nobody set. The
        # sentinel enums are the reason this exists and the reason it cannot be
        # a truthiness test: `StpMode.NONE` is the string "none".
        return False
    return True


def _populated(pack: StaticFactPack) -> dict[str, int]:
    """Every path the pack actually states something at, and how often.

    Paths are built exactly as `_Watched` builds them, because the two sets are
    compared: a walk that spelled `devices[].interfaces` differently would report
    every field in the pack as unread. Absence is not counted — a field that is
    None on every record it could sit on is not a fact this collection contains,
    and reporting it would bury the ones that are in a list of the ones that
    are not. `_states_something` decides what counts, and there are more shapes
    of nothing than there look to be.
    """
    found: dict[str, int] = {}

    def walk(record: object, path: str) -> None:
        for field in dataclasses.fields(record):  # type: ignore[arg-type]
            value = getattr(record, field.name)
            full = f"{path}.{field.name}" if path else field.name
            kind = _kind(type(record), field.name, value)
            if kind is _VALUE:
                if _states_something(field, value):
                    found[full] = found.get(full, 0) + 1
                continue
            if kind is _RECORD:
                if value is not None:
                    walk(value, full)
                continue
            if not value:
                continue
            found[full] = found.get(full, 0) + len(value)
            for item in value:
                walk(item, f"{full}[]")

    walk(pack, "")
    return found


def unread(pack: StaticFactPack, consulted: Collection[str]) -> tuple[UnreadFact, ...]:
    """Facts this pack states that nothing in `consulted` read.

    `meta` is excluded: it is the pack's identity rather than a fact about the
    network, every field of it is reported elsewhere, and a rule reading it would
    be reasoning about the collection instead of the configuration. So is the
    citation and identity machinery — see `_BOOKKEEPING`.
    """
    candidates = [
        path
        for path in sorted(_populated(pack))
        if path not in consulted
        and not path.startswith("meta")
        and _field(path).removesuffix("[]") not in _BOOKKEEPING
    ]
    # A field of a collection nothing opened is not a second thing nobody reads.
    # Listing `l2_segments` and then each of its six fields says one fact six
    # times and pushes the other findings off the end of the report.
    unopened = set(candidates)
    populated = _populated(pack)
    return tuple(
        UnreadFact(path=path, label=_describe(path), records=populated[path])
        for path in candidates
        if not any(ancestor in unopened for ancestor in _ancestors(path))
    )


def _ancestors(path: str) -> Iterator[str]:
    """Every path this one sits inside, longest first."""
    head = path
    while True:
        head = head.rpartition(".")[0]
        if not head:
            return
        yield head.removesuffix("[]")
        yield head


# Fields that exist so a finding can be cited, printed or joined back to its
# record, rather than so a rule can reason about them. Every one of them is read
# — by `findings.locate`, by the figures, by the views — and none of them is read
# by a rule, so listing them here would fill the report with thirty true
# sentences that mean nothing and bury the four that mean something.
_BOOKKEEPING: Final = frozenset(
    {
        "config_line",
        "config_path",
        "config_line_count",
        "id",
        "device",
        "hostname",
        "description",
        "label",
        "name",
        "segment",
    }
)


def _singular(word: str) -> str:
    if word.endswith("ies"):
        return f"{word[:-3]}y"
    if word.endswith("ses"):
        return word[:-2]
    return word.removesuffix("s")


def _describe(path: str) -> str:
    """`devices[].interfaces[].lag_member_of` as a sentence fragment.

    Built from the path rather than from a table, so a field added to the schema
    is described the day it is added rather than the day somebody remembers to
    describe it. Only the immediate owner is named — the full chain reads worse
    at every extra level and the path itself is printed beside this for anyone
    who needs the exact name.
    """
    parts = [part.removesuffix("[]") for part in path.split(".") if part]
    leaf = _field_words(parts[-1])
    # A record named `a` or `b` — one end of an adjacency — is not a noun, so
    # the name a reader would recognise is the collection those ends sit in.
    owners = [part for part in parts[:-1] if len(part) > 2]
    if not owners:
        return leaf
    # A short structural name — `scope`, `meta` — names the shape of a record
    # rather than the thing it is about, so it borrows the segment above it.
    named = owners[-2:] if len(owners[-1]) <= 5 and len(owners) > 1 else owners[-1:]
    owner = " ".join(_words(part) for part in [*named[:-1], _singular(named[-1])])
    return f"{leaf} on {_article(owner)} {owner}"


# Letters whose *name* begins with a vowel sound, which is what decides the
# article in front of an initialism: an L2 segment, an MTU, a VLAN.
_VOWEL_SOUNDED: Final = frozenset("aeiouAEFHILMNORSX")


def _article(noun: str) -> str:
    first = noun.split()[0]
    if first.isupper() or (first[:-1].isupper() and first[-1:].isdigit()):
        return "an" if first[0] in _VOWEL_SOUNDED else "a"
    return "an" if first[0].lower() in "aeiou" else "a"


@dataclass(frozen=True, slots=True, kw_only=True)
class Assessment:
    """Both halves of the coverage question, from one run of the rules.

    Together rather than separately because the second half is free once the
    first has been paid for: the recorder that answers "did this rule have an
    input" already knows every path the rules touched, and the paths it did not
    touch are the answer to "does anything read this input". Running the rules
    twice to ask them apart would be the same work for the same answer.
    """

    rules: tuple[RuleCoverage, ...]
    unread: tuple[UnreadFact, ...]


def assess(
    pack: StaticFactPack, *, limits: Limits = DEFAULT_LIMITS
) -> tuple[RuleCoverage, ...]:
    """Every catalogued rule, and whether this fact pack gave it anything.

    Ordered as the catalogue orders it, so a coverage line and a rule entry read
    side by side.
    """
    return assess_all(pack, limits=limits).rules


def assess_all(pack: StaticFactPack, *, limits: Limits = DEFAULT_LIMITS) -> Assessment:
    """The rule verdicts, and the facts no rule consulted."""
    docs = _catalogued()
    groups, orphans = _groups(docs)
    by_id = {doc.id: doc for doc in docs}
    covered: dict[str, RuleCoverage] = {}
    consulted: set[str] = set()

    with _Trace(SOURCES) as trace:
        for group in groups:
            findings, reads, executed = _observe(group, pack, limits, trace)
            consulted.update(reads.order)
            counts = Counter(finding.rule for finding in findings)
            shape = _shape(group.module)
            name = group.entry.__name__
            rejections = _rejections(shape, name, executed)
            for rule_id in group.rules:
                doc = by_id[rule_id]
                reached = any(
                    (shape.file, line) in executed
                    for start, end in _decisions(shape, name, rule_id, doc.function)
                    for line in range(start, end + 1)
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

    return Assessment(
        rules=tuple(covered[doc.id] for doc in docs),
        unread=unread(pack, consulted),
    )


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


def render_text(
    coverage: Sequence[RuleCoverage], unread_facts: Sequence[UnreadFact] = ()
) -> str:
    """Every rule, the ones that ran first, with the reason each inert one had.

    The unread facts come last and are optional, because they answer a different
    question from everything above them. A rule that could not run is a gap in
    what this collection contains; a fact nothing reads is a gap in what this
    tool checks, and only the second one is a suggestion about the tool itself.
    """
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
    tail = [""]
    if unread_facts:
        # Its own column width. Borrowing the rule column's leaves the longest
        # labels hanging past it, which reads as a broken table rather than as a
        # wide one.
        labelled = max(len(fact.label) for fact in unread_facts)
        tail += [
            f"{len(unread_facts)} facts these configs state that no check read:",
            *(f"  {fact.label:<{labelled}}  {fact.path}" for fact in unread_facts),
            "",
            "Each is parsed and in the pack, and nothing above opened it on this",
            "run. Some are read by no rule at all — a check nobody has written",
            "rather than a check that passed. Others are read only by a rule that",
            "did not get far enough to ask, which is the line above saying the",
            "same thing from the other end.",
            "",
        ]
    return "\n".join([*lines, *tail, summary(coverage)])
