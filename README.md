# Cassandra — network config QA

**Point it at a directory of network configs. Get back a ranked list of latent failure modes,
each with the evidence that produced it.**

```
$ cassandra check ./configs
HIGH   agg-a  VRRP 14 and 24 can diverge under repeated uplink flap
              group 14 preempts back immediately; group 24 waits 90s
              trigger: flap Ethernet1 twice within 90s
LOW    acc1   trunk Ethernet2 omits VLAN 99, which agg-b has an SVI in
```

No lab, no containers, no account. The interesting findings are the timing-dependent ones —
failures that no steady-state config analysis can express, because they are properties of a
configuration *plus* a sequence of events *plus* the timers governing the reaction.

Emulation still exists, but it runs in this project's CI to prove the timing model tells the
truth. It is never something a user has to set up.

**[PROJECT.md](PROJECT.md) is the spec and the source of truth.** Read it first.
[docs/CONVENTIONS.md](docs/CONVENTIONS.md) holds the standing rules, including how the
autonomous build loop makes decisions. [docs/DECISIONS.md](docs/DECISIONS.md) is the log of
those decisions and the current phase status.

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
cassandra/factpack/schema.py       static facts: inventory, adjacency, FHRP, timers
scenarios/site14_vrrp_lockstep/    CI emulation validator + its configs
docs/                              spec conventions, decisions, fidelity, design
tests/                             schema, scenario lint, scoring, spec references
```

## State

**Phase 1** — Fact Pack builders. See `docs/DECISIONS.md` for live phase status.

The symbolic half of the original ground-truth scenario has been run and passes: Batfish
parses the configs, models all six VRRP groups, and reports the network healthy, with a
recorded caveat about the lines it does not parse. The emulation half runs in CI from Phase 4.
