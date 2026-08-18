# Cassandra — Latent Network Failure Discovery

Proactive discovery of dormant, timing-dependent network failure modes: generate
conjectures cheaply, filter them deterministically, and escalate only the
survivors into protocol emulation, where failures that steady-state analysis
cannot express become observable.

**[PROJECT.md](PROJECT.md) is the spec and the source of truth.** Read it first.
[docs/CONVENTIONS.md](docs/CONVENTIONS.md) holds the standing rules for working in this
repository.

## Setup

Requires [uv](https://docs.astral.sh/uv/). Python 3.12 is pinned in
`.python-version` and fetched automatically.

```sh
uv sync              # create .venv and install dev dependencies
uv run ruff check .  # lint
uv run ruff format . # format
uv run pytest        # tests
```

## Layout

The target layout is PROJECT.md §4.1. What exists today:

```
cassandra/
  factpack/
    schema.py    # static fact pack dataclasses: inventory, L1/L2/L3
                 # adjacency, FHRP groups, timer inventory
tests/
  test_schema.py # schema invariants: immutability, timer scoping, unit naming
```

Everything else in §4.1 is unbuilt.

## State

Phase 0 (§4.2) — reproducing a known outage in Containerlab and demonstrating
that Batfish reports the same configs healthy — is the existence proof for the
whole thesis and has not been done yet. It needs Docker, Containerlab, and a
Batfish container locally.

The Fact Pack schema above is Phase 1 work that landed early. No parsers,
no serialization, no agents.
