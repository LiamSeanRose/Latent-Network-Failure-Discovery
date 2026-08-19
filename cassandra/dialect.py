"""Writing a configuration line in the dialect a device speaks.

PROJECT.md §5.4 asks a finding to carry the change that would remove it, and a
change is only useful in the syntax of the box it goes on. Three dialects say
the same thing three ways — `vrrp 14 preempt`, `standby 14 preempt`, and
`preempt` nested inside an `hsrp 14` block — and a line that does not parse costs
the reader more than no line at all.

So every function here returns nothing rather than something plausible when it
cannot be sure. A dialect the parsers do not recognise, a device the fact pack
does not hold: both produce an empty tuple, and the finding simply carries no
suggested change. That is the whole design rule of this module.

It lives outside both tiers because both need it: the timing tier suggests
preempt delays, the deterministic tier suggests the reciprocal peering and the
missing VLAN, and neither should have to import from the other to write a line.
"""

from __future__ import annotations

from cassandra.factpack.schema import (
    AddressFamily,
    FhrpGroup,
    NosFamily,
    StaticFactPack,
)

# How deep a sub-command sits under its interface, per dialect. Cosmetic to a
# parser and not to a reader: a block pasted at the wrong indentation reads as
# something the author did not check.
_INDENT = {
    NosFamily.EOS: "   ",
    NosFamily.IOS_XE: " ",
    NosFamily.NX_OS: "  ",
}


def nos_of(pack: StaticFactPack, device: str) -> NosFamily | None:
    """The dialect a device speaks, or None if the pack does not hold it."""
    for entry in pack.devices:
        if entry.id == device:
            return entry.nos_family if entry.nos_family in _INDENT else None
    return None


def under_interface(nos: NosFamily, interface: str, *lines: str) -> tuple[str, ...]:
    """Configuration lines in an interface block, indented for the dialect."""
    if nos not in _INDENT or not lines:
        return ()
    pad = _INDENT[nos]
    return (f"interface {interface}", *(f"{pad}{line}" for line in lines))


def fhrp_setting(nos: NosFamily, group: FhrpGroup, setting: str) -> tuple[str, ...]:
    """One FHRP sub-command, in the shape its dialect writes groups.

    EOS and IOS state the group on every line; NX-OS opens a block and indents
    beneath it, so this returns two lines there and one everywhere else.
    """
    number = group.group_number
    family = " ipv6" if group.family is AddressFamily.IPV6_UNICAST else ""
    if nos is NosFamily.EOS:
        return (f"vrrp {number}{family} {setting}",)
    if nos is NosFamily.IOS_XE:
        return (f"standby {number} {setting}",)
    if nos is NosFamily.NX_OS:
        return (f"hsrp {number}{family}", f"  {setting}")
    return ()


def fhrp_change(
    pack: StaticFactPack, group: FhrpGroup, device: str, setting: str
) -> tuple[str, ...]:
    """A complete edit: the interface, the group, and the setting under it."""
    nos = nos_of(pack, device)
    if nos is None:
        return ()
    interface = next((m.interface for m in group.members if m.device == device), None)
    if interface is None:
        return ()
    lines = fhrp_setting(nos, group, setting)
    return under_interface(nos, interface, *lines) if lines else ()
