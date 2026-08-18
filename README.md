# Cassandra — network lab QA

A QA tool for network labs you own.

Describe a scenario — a topology, an event sequence, and hard conditions for what must and
must not happen. It runs the scenario in emulation with real protocol timing, scores it
against those conditions, and separately asks a static analyser the same question about the
same configs.

**The interesting output is the disagreement.** Failures that are real under timing and
invisible to steady-state analysis are a class of bug that config verification structurally
cannot reach.

**[PROJECT.md](PROJECT.md) is the spec and the source of truth.** Read it first.
[docs/CONVENTIONS.md](docs/CONVENTIONS.md) holds the standing rules for working in this
repository.

## Setup

Requires [uv](https://docs.astral.sh/uv/). Python 3.12 is pinned in `.python-version` and
fetched automatically.

```sh
uv sync              # create .venv and install dev dependencies
uv run ruff check .  # lint
uv run pytest        # tests
```

Running a scenario additionally needs Docker, Containerlab, and an imported Arista cEOS
image. See [docs/emulation-fidelity.md](docs/emulation-fidelity.md) for why cEOS
specifically — it is the only platform that both expresses the failures under test and can
be parsed by Batfish.

## Layout

Target layout is PROJECT.md §4.1. What exists today:

```
cassandra/factpack/schema.py            static facts: inventory, adjacency, FHRP, timers
scenarios/site14_vrrp_lockstep/         Phase 0 scenario — topology, configs, runner, scorer
docs/                                   conventions, emulation fidelity, Phase 0 design
tests/                                  schema invariants, scenario lint, scoring logic
```

## State

**Phase 0 is in progress and unverified.** The scenario is written and statically checked,
but has never been booted — it was authored in an environment with no Docker daemon. Its
README lists the untested assumptions in order of likelihood.

Phase 0 is the existence proof: a timing-dependent failure that reproduces in emulation
while Batfish calls the identical configs healthy. Nothing else gets built until it runs.
