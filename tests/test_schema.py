"""Invariants for the Fact Pack schema.

These are not tests of behaviour — `schema.py` has none by design. They guard
the properties the rest of the system relies on: that a built Fact Pack cannot
mutate under a prompt cache, that every timer is scoped and carries its unit in
its name, and that the module stays free of logic.
"""

from __future__ import annotations

import dataclasses
import inspect
from datetime import UTC, datetime
from enum import StrEnum

import pytest

from cassandra.factpack import schema

TIMER_RECORDS: tuple[type, ...] = (
    schema.IgpHelloTimers,
    schema.BfdTimers,
    schema.BgpTimers,
    schema.DampeningProfile,
    schema.SpfThrottleTimers,
    schema.CarrierDelayTimers,
    schema.StpTimers,
    schema.FhrpTimers,
)


def _dataclasses() -> list[type]:
    return [
        obj
        for _, obj in inspect.getmembers(schema, inspect.isclass)
        if dataclasses.is_dataclass(obj) and obj.__module__ == schema.__name__
    ]


def _enums() -> list[type[StrEnum]]:
    return [
        obj
        for _, obj in inspect.getmembers(schema, inspect.isclass)
        if issubclass(obj, StrEnum)
        and obj is not StrEnum
        and obj.__module__ == schema.__name__
    ]


def _meta() -> schema.FactPackMeta:
    return schema.FactPackMeta(
        fact_pack_id="fp_test",
        schema_version=1,
        config_digest="0" * 64,
        source_snapshot="synthetic/test",
        generated_at=datetime(2026, 8, 18, tzinfo=UTC),
    )


@pytest.mark.parametrize("cls", _dataclasses(), ids=lambda c: c.__name__)
def test_dataclasses_are_frozen_slotted_and_kw_only(cls: type) -> None:
    """A Fact Pack is a cached prompt prefix; it must not be able to mutate."""
    params = cls.__dataclass_params__
    assert params.frozen, f"{cls.__name__} is mutable"
    assert "__slots__" in cls.__dict__, f"{cls.__name__} has no slots"
    for f in dataclasses.fields(cls):
        assert f.kw_only, f"{cls.__name__}.{f.name} is positional"


@pytest.mark.parametrize("cls", _dataclasses(), ids=lambda c: c.__name__)
def test_sequence_fields_are_tuples_not_lists(cls: type) -> None:
    for f in dataclasses.fields(cls):
        assert "list[" not in str(f.type), f"{cls.__name__}.{f.name} is a list"
        assert "dict[" not in str(f.type), f"{cls.__name__}.{f.name} is a dict"


def test_module_declares_no_logic() -> None:
    """Declarations only: no parsers, no serialization, no derivation."""
    functions = [
        name
        for name, obj in inspect.getmembers(schema, inspect.isfunction)
        if obj.__module__ == schema.__name__
    ]
    assert functions == []

    for cls in _dataclasses():
        methods = [
            name
            for name, obj in vars(cls).items()
            if inspect.isfunction(obj) and not name.startswith("__")
        ]
        assert methods == [], f"{cls.__name__} defines {methods}"


@pytest.mark.parametrize("cls", TIMER_RECORDS, ids=lambda c: c.__name__)
def test_every_timer_record_is_scoped(cls: type) -> None:
    """Timers live in the inventory, not on the objects they configure, so each
    record has to say what it applies to."""
    scope = {f.name: f for f in dataclasses.fields(cls)}["scope"]
    assert str(scope.type) == "TimerScope"
    assert scope.default is dataclasses.MISSING, f"{cls.__name__}.scope is optional"


@pytest.mark.parametrize("cls", TIMER_RECORDS, ids=lambda c: c.__name__)
def test_timer_fields_carry_their_unit(cls: type) -> None:
    """An unlabelled duration is a bug waiting for the ±20% perturbation run."""
    suffixes = {"Milliseconds": "_ms", "Seconds": "_s", "Minutes": "_min"}
    for f in dataclasses.fields(cls):
        for alias, suffix in suffixes.items():
            if alias in str(f.type):
                assert f.name.endswith(suffix), (
                    f"{cls.__name__}.{f.name} is {alias} but not named {suffix}"
                )


def test_timer_inventory_covers_every_record_type() -> None:
    inventory_fields = dataclasses.fields(schema.TimerInventory)
    assert len(inventory_fields) == len(TIMER_RECORDS)
    for f in inventory_fields:
        assert schema.TimerInventory().__getattribute__(f.name) == ()


@pytest.mark.parametrize("cls", _enums(), ids=lambda c: c.__name__)
def test_enum_values_are_stable_lowercase_tokens(cls: type[StrEnum]) -> None:
    """Enum values reach the serialized prompt prefix; casing drift there is a
    cache invalidation."""
    for member in cls:
        assert member.value == member.value.lower()
        assert " " not in member.value
        assert "_" not in member.value


def test_static_fact_pack_needs_only_meta() -> None:
    pack = schema.StaticFactPack(meta=_meta())
    assert pack.devices == ()
    assert pack.timers == schema.TimerInventory()


def test_built_fact_pack_is_hashable_and_immutable() -> None:
    pack = schema.StaticFactPack(meta=_meta())
    assert isinstance(hash(pack.timers), int)
    with pytest.raises(dataclasses.FrozenInstanceError):
        pack.devices = ()  # type: ignore[misc]


def test_unimplemented_sections_are_absent_not_stubbed() -> None:
    """PROJECT.md §3 bullets without builders yet must not appear as empty
    fields that read as 'this network has none'."""
    present = {f.name for f in dataclasses.fields(schema.StaticFactPack)}
    for absent in (
        "protocol_adjacencies",
        "vrf_route_targets",
        "redistribution_points",
        "summarization_points",
        "ecmp_fanout",
        "incidents",
    ):
        assert absent not in present
