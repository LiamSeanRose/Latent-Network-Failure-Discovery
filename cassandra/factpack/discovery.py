"""Find the configuration files in a directory tree.

A real config collection is not a flat folder of `.cfg`. It is a working copy or
a backup target: nested a directory deep per site or per role, named `.cfg`,
`.conf`, `.txt` or nothing at all, and sharing the tree with a README, a `.git`,
a handful of JSON exports and whatever else lives beside them. Globbing one
extension in one directory reports "nothing here" on a directory full of
configs, which is the worst answer the tool can give on first contact.

Three decisions this module makes, in the order it makes them:

**Identity.** A device's id is its path relative to the discovery root, with a
recognised config extension removed and the remaining components joined by `/`
— `site-a/agg-a`. For a file sitting directly in the root that reduces to the
bare filename, so a flat collection keeps the short ids it always had. Two files
called `agg-a` under different site folders are two devices, because their paths
differ. This id is what a config *without* a `hostname` line is named by; a
config that declares a hostname keeps it, and `builders` falls back to the
path-derived id only when two configs claim the same one.

**What is a config.** Extension decides first because it costs nothing:
`.cfg` and `.conf` are asserted configs, `.txt` and no-extension are plausible
ones, a long list of document, data, code, image and archive extensions are
never opened, and anything else is treated as plausible — a backup written as
`agg-a.example.com` has an extension only by accident. Every plausible candidate
then has to pass a content sniff over its first few kilobytes. The bias is
deliberate and one-directional: a file that is not a config must not become a
device, because a device parsed out of a README is a garbage row in every
finding downstream. Missing a real config is recoverable — the tool says which
files it passed over and why.

**What is worth saying out loud.** Skipping `README.md` is not news. Skipping a
file the operator named `.cfg` is, and so is a file that reads as a config but
yields no device. Those come back as `notes`, and everything skipped is
enumerable in the result for a caller that wants the full list.

**What encoding it is in.** A byte-order mark is believed, because it is the
only statement a file makes about itself; UTF-8 is assumed otherwise, and
latin-1 is the fallback that cannot fail. Without a mark, NUL bytes still mean
binary — a UTF-16 file that omits its mark is refused rather than guessed at,
and the refusal is reported because the operator named the file.

Nothing here raises on a hostile tree, and nothing here blocks on one:
unreadable files, dangling symlinks, symlink loops and anything that is not a
regular file are recorded and stepped over.
"""

from __future__ import annotations

import codecs
import os
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from stat import S_ISREG
from typing import Final

from cassandra.factpack.builders.common import strip_banners

# Extensions asserting the file is a device config. A rejection here is worth
# reporting, because someone chose the name.
ASSERTED_SUFFIXES: Final[frozenset[str]] = frozenset({".cfg", ".conf"})

# Extensions consistent with a device config without claiming to be one. Backup
# tools write bare hostnames, and `.txt` is what a copy-paste gets saved as.
PLAUSIBLE_SUFFIXES: Final[frozenset[str]] = frozenset({".txt", ""})

# Never opened. Documents, structured data, source, images, archives, keys and
# logs: none of them is a device config, and several are large or binary.
IGNORED_SUFFIXES: Final[frozenset[str]] = frozenset(
    {
        # documents and markup
        ".md",
        ".markdown",
        ".rst",
        ".adoc",
        ".html",
        ".htm",
        ".xml",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        # structured data
        ".json",
        ".yml",
        ".yaml",
        ".toml",
        ".ini",
        ".csv",
        ".tsv",
        ".sql",
        ".db",
        ".sqlite",
        ".sqlite3",
        # source and build
        ".py",
        ".pyc",
        ".pyo",
        ".pyi",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".bat",
        ".go",
        ".rs",
        ".js",
        ".mjs",
        ".ts",
        ".c",
        ".h",
        ".cc",
        ".cpp",
        ".hpp",
        ".java",
        ".rb",
        ".pl",
        ".lua",
        ".tf",
        ".tfstate",
        ".j2",
        ".jinja",
        ".jinja2",
        ".mk",
        ".cmake",
        # images and media
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".ico",
        ".svg",
        ".webp",
        ".tif",
        ".tiff",
        ".mp4",
        ".mov",
        # archives and binaries
        ".zip",
        ".gz",
        ".tgz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".tar",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".img",
        ".iso",
        ".whl",
        ".deb",
        ".rpm",
        # captures, logs, keys
        ".pcap",
        ".pcapng",
        ".log",
        ".pem",
        ".crt",
        ".cer",
        ".key",
        ".p12",
        ".pub",
        ".lock",
        ".swp",
    }
)

# Extensionless files that are conventionally documentation or build scaffolding.
# Matched case-insensitively on the whole name, so a device genuinely called
# `license` in some address plan is not what this catches.
IGNORED_NAMES: Final[frozenset[str]] = frozenset(
    {
        "readme",
        "license",
        "licence",
        "copying",
        "notice",
        "authors",
        "contributors",
        "changelog",
        "changes",
        "history",
        "todo",
        "version",
        "makefile",
        "dockerfile",
        "vagrantfile",
        "jenkinsfile",
        "procfile",
        "codeowners",
    }
)

# Directories never descended into. Hidden directories are excluded separately,
# which is what keeps `.git` out; these are the unhidden equivalents.
IGNORED_DIRS: Final[frozenset[str]] = frozenset(
    {"__pycache__", "node_modules", "site-packages", "venv", "target", "dist"}
)

# A device config is text, and a large one is a few hundred kilobytes. Anything
# past this is something else wearing a config's extension, and reading it is
# how a directory scan turns into a memory problem.
MAX_CONFIG_BYTES: Final[int] = 8 * 1024 * 1024

# How much of a candidate is read before deciding whether to read the rest.
SNIFF_BYTES: Final[int] = 16 * 1024

# Byte-order marks, longest first: a UTF-32-LE mark begins with a UTF-16-LE one,
# so checking the short mark first would decode a UTF-32 file as UTF-16. A config
# arrives with a mark when it has been through an editor on Windows or been
# exported by a management station, and the mark is the only reliable statement
# a file makes about its own encoding.
_BYTE_ORDER_MARKS: Final[tuple[tuple[bytes, str], ...]] = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)

# Bound on how much walking a hostile tree can cost, on top of the loop
# detection below: a symlink farm can be finite and still absurdly deep.
MAX_DEPTH: Final[int] = 24

# Bound on the recorded skip list. A working copy can hold tens of thousands of
# ignored files and none of them is worth carrying in memory to print.
MAX_RECORDED_SKIPS: Final[int] = 500

# A top-level line that reads as IOS-style configuration. Deliberately wide:
# the question is "is this a config file", not "does this tool model this line",
# so out-of-scope domains (AAA, SNMP, logging) count as evidence too.
_CONFIG_LINE: Final[re.Pattern[str]] = re.compile(
    r"^(?:no |default )?(?:"
    r"hostname|switchname|interface|vlan|vrf|track|router|feature|version|"
    r"system|ip|ipv6|mac|arp|switchport|spanning-tree|mtu|bfd|mpls|"
    r"port-channel|portchannel|lacp|lldp|cdp|control-plane|vpc|nv|evpn|"
    r"standby|vrrp|hsrp|glbp|"
    r"username|enable|aaa|tacacs|radius|snmp|snmp-server|logging|ntp|clock|"
    r"line|banner|boot|service|crypto|key|license|hardware|platform|module|"
    r"policy-map|class-map|route-map|access-list|object-group|errdisable|"
    r"monitor|archive|management|daemon|agent|event-handler|sflow|"
    r"queue-monitor|transceiver|alias|prompt|terminal|role|privilege|"
    r"dot1x|storm-control|power|qos|multicast|pim|igmp|dhcp|"
    r"end|exit|configure|write|copy|"
    r"aliases|dns|domain-name|errdisable-recovery"
    r")\b",
    re.IGNORECASE,
)

# The hostname a config declares for itself, if it declares one. Used to tell a
# config that named itself from one that only has a filename.
_HOSTNAME_LINE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(?:hostname|switchname)\s+(\S+)", re.MULTILINE
)

# Fewer than half the top-level lines reading as configuration means it is prose
# that happens to mention interfaces. One matching line is enough on its own for
# a very short file, which is what a minimal config looks like.
_MIN_CONFIG_LINE_RATIO: Final[int] = 2


class SkipReason(StrEnum):
    """Why a path in the tree did not become a device."""

    HIDDEN = "hidden"
    IGNORED_DIR = "ignored-directory"
    IGNORED_NAME = "ignored-name"
    EXTENSION = "extension"
    TOO_LARGE = "too-large"
    UNREADABLE = "unreadable"
    BINARY = "binary"
    NOT_CONFIG = "not-config"
    SYMLINK_LOOP = "symlink-loop"
    TOO_DEEP = "too-deep"


@dataclass(frozen=True, slots=True, kw_only=True)
class ConfigFile:
    """One file that survived discovery, with the text already read."""

    path: Path
    relative: str
    device_id: str
    declared_hostname: str | None
    text: str
    asserted: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class Skipped:
    """One path discovery passed over, and why."""

    path: Path
    reason: SkipReason
    detail: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class Discovery:
    """Everything one walk of a tree found."""

    root: Path
    configs: tuple[ConfigFile, ...] = ()
    skipped: tuple[Skipped, ...] = ()
    skips_truncated: bool = False

    def notes(self) -> tuple[str, ...]:
        """The skips a person would want told to them, in one line each.

        Ignoring a README is not news and is left to `skipped`. A file named
        `.cfg` that was rejected is news, and so is anything the filesystem
        would not hand over — those are the cases where silence would read as
        "there was nothing there".
        """
        loud = {
            SkipReason.UNREADABLE,
            SkipReason.SYMLINK_LOOP,
            # A directory refused for depth takes every config under it with
            # it, so silence here reads as "that site has no devices".
            SkipReason.TOO_DEEP,
        }
        named = {SkipReason.NOT_CONFIG, SkipReason.TOO_LARGE, SkipReason.BINARY}
        return tuple(
            f"skipped {skip.path}: {skip.reason.value}"
            + (f" ({skip.detail})" if skip.detail else "")
            for skip in self.skipped
            if skip.reason in loud
            or (skip.reason in named and skip.path.suffix.lower() in ASSERTED_SUFFIXES)
        )


class ConfigDiscoveryWarning(UserWarning):
    """Raised through `warnings.warn` when discovery passed over something the
    operator probably meant to be read.

    A warning rather than an exception because the run is still useful: the
    other configs parsed, and a directory of a thousand devices should not fail
    because one of them is a broken symlink."""


def _is_hidden(name: str) -> bool:
    return name.startswith(".")


def _suffix_of(name: str) -> str:
    return Path(name).suffix.lower()


def looks_like_config(text: str) -> bool:
    """Does this text read as IOS-style device configuration?

    Structural rather than keyword-counting: a config is top-level directives
    with indented bodies, so the test is what fraction of the *top-level* lines
    are recognisable commands. Prose about networking fails it — a README's
    lines are sentences, and a sentence is not a command — while a config whose
    body is mostly indented ACL entries passes it, because the handful of lines
    at column zero are all real.
    """
    top_level: int = 0
    matches: int = 0
    # Banner bodies sit at column zero and are arbitrary prose, so without this
    # a config with a long login banner reads as a document.
    for line in strip_banners(text).splitlines():
        if not line.strip() or line.strip().startswith("!"):
            continue
        if line[0].isspace():
            continue
        top_level += 1
        if _CONFIG_LINE.match(line.strip()):
            matches += 1
    if not matches:
        return False
    return matches * _MIN_CONFIG_LINE_RATIO >= top_level


def _device_id(relative: Path) -> str:
    """`site-a/agg-a` from `site-a/agg-a.cfg`; `agg-a` from `agg-a.cfg`.

    Only a recognised config extension is stripped. `agg-a.example.com` keeps
    its dots, because `.com` is part of the device's name and not a file type.
    """
    name = relative.name
    if _suffix_of(name) in ASSERTED_SUFFIXES | PLAUSIBLE_SUFFIXES:
        name = relative.stem
    return "/".join([*relative.parts[:-1], name])


def _declared_encoding(raw: bytes) -> str | None:
    """The encoding this file's byte-order mark declares, if it carries one."""
    for mark, encoding in _BYTE_ORDER_MARKS:
        if raw.startswith(mark):
            return encoding
    return None


def _decode(raw: bytes, encoding: str | None = None) -> str:
    """Config text is usually UTF-8 and occasionally an 8-bit encoding from a
    device that predates the question. Latin-1 cannot fail, and the binary check
    has already run, so this never turns a JPEG into a device.

    A file that declared its encoding with a byte-order mark is decoded by that
    declaration instead, and the mark is consumed rather than left on the front
    of the first line. That matters because the first line of a config is very
    often `hostname`, and a mark in front of it matches neither the hostname
    pattern nor any parser, so the device silently loses its name and answers to
    its filename. Errors are replaced rather than falling back to latin-1,
    because the sniff reads a fixed number of bytes and will routinely cut a
    multi-byte unit in half.
    """
    if encoding is not None:
        return raw.decode(encoding, errors="replace")
    try:
        return raw.decode()
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _read_candidate(path: Path, size: int) -> tuple[str, SkipReason | None, str]:
    """Read a candidate, cheapest check first.

    The prefix is sniffed before the rest of the file is read, so a large
    non-config that got past the extension gate costs one `SNIFF_BYTES` read
    rather than its whole length, and it is one open rather than two.
    """
    if size > MAX_CONFIG_BYTES:
        return "", SkipReason.TOO_LARGE, f"{size} bytes"
    try:
        with path.open("rb") as handle:
            head = handle.read(SNIFF_BYTES)
            encoding = _declared_encoding(head)
            # UTF-16 and UTF-32 are full of NULs by construction, so the binary
            # check only applies to a file that did not say it was either.
            if encoding is None and b"\x00" in head:
                return "", SkipReason.BINARY, ""
            if not looks_like_config(_decode(head, encoding)):
                return "", SkipReason.NOT_CONFIG, ""
            raw = head + handle.read()
    except OSError as error:
        return "", SkipReason.UNREADABLE, error.strerror or type(error).__name__
    return _decode(raw, encoding), None, ""


def _walk(root: Path, skipped: list[Skipped]) -> list[Path]:
    """Depth-first walk that survives a hostile tree.

    Symlinked directories are followed, because a collection assembled by
    symlink is a real thing, but every directory is identified by device and
    inode and visited once. That breaks a loop without refusing the legitimate
    case, which `followlinks=False` would also have done.
    """
    found: list[Path] = []
    seen: set[tuple[int, int]] = set()
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        try:
            key = directory.stat()
        except OSError as error:
            skipped.append(
                Skipped(
                    path=directory,
                    reason=SkipReason.UNREADABLE,
                    detail=error.strerror or type(error).__name__,
                )
            )
            continue
        identity = (key.st_dev, key.st_ino)
        if identity in seen:
            skipped.append(Skipped(path=directory, reason=SkipReason.SYMLINK_LOOP))
            continue
        seen.add(identity)
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as error:
            skipped.append(
                Skipped(
                    path=directory,
                    reason=SkipReason.UNREADABLE,
                    detail=error.strerror or type(error).__name__,
                )
            )
            continue
        for entry in entries:
            path = Path(entry.path)
            try:
                is_dir = entry.is_dir()
            except OSError:
                is_dir = False
            if _is_hidden(entry.name):
                skipped.append(Skipped(path=path, reason=SkipReason.HIDDEN))
                continue
            if is_dir:
                if entry.name in IGNORED_DIRS:
                    skipped.append(Skipped(path=path, reason=SkipReason.IGNORED_DIR))
                    continue
                if depth + 1 > MAX_DEPTH:
                    skipped.append(Skipped(path=path, reason=SkipReason.TOO_DEEP))
                    continue
                stack.append((path, depth + 1))
                continue
            found.append(path)
    return found


def discover(root: Path) -> Discovery:
    """Walk `root` and return the configs in it, plus what was passed over.

    A missing or non-directory `root` is an empty result rather than an error:
    the callers that care already say "not a directory" in their own words, and
    this returning cleanly keeps one less traceback out of the tool.
    """
    root = Path(root)
    if not root.is_dir():
        return Discovery(root=root)

    skipped: list[Skipped] = []
    configs: list[ConfigFile] = []
    for path in sorted(_walk(root, skipped)):
        name = path.name
        suffix = _suffix_of(name)
        if suffix in IGNORED_SUFFIXES:
            skipped.append(
                Skipped(path=path, reason=SkipReason.EXTENSION, detail=suffix)
            )
            continue
        if not suffix and name.lower() in IGNORED_NAMES:
            skipped.append(Skipped(path=path, reason=SkipReason.IGNORED_NAME))
            continue
        try:
            status = path.stat()
        except OSError as error:
            skipped.append(
                Skipped(
                    path=path,
                    reason=SkipReason.UNREADABLE,
                    detail=error.strerror or type(error).__name__,
                )
            )
            continue
        # A named pipe with no writer blocks in `open` forever, and a device
        # node is worse. Nothing but a regular file is ever a config, so the
        # kind is checked before anything opens it.
        if not S_ISREG(status.st_mode):
            skipped.append(
                Skipped(
                    path=path,
                    reason=SkipReason.UNREADABLE,
                    detail="not a regular file",
                )
            )
            continue
        text, reason, detail = _read_candidate(path, status.st_size)
        if reason is not None:
            skipped.append(Skipped(path=path, reason=reason, detail=detail))
            continue
        relative = path.relative_to(root)
        declared = _HOSTNAME_LINE.search(text)
        configs.append(
            ConfigFile(
                path=path,
                relative=relative.as_posix(),
                device_id=_device_id(relative),
                declared_hostname=declared.group(1) if declared else None,
                text=text,
                asserted=suffix in ASSERTED_SUFFIXES,
            )
        )

    truncated = len(skipped) > MAX_RECORDED_SKIPS
    return Discovery(
        root=root,
        configs=tuple(configs),
        skipped=tuple(skipped[:MAX_RECORDED_SKIPS]),
        skips_truncated=truncated,
    )
