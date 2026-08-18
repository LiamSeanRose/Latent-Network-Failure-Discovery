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
uv sync                                      # install
uv run cassandra check ./configs             # findings, ranked; exit 1 if any
uv run cassandra check ./configs --explain   # + evidence, fixes, rule ids
uv run cassandra facts ./configs             # the materialised fact pack
uv run cassandra serve                       # local web view on 127.0.0.1:8765
```

Development:

```sh
uv run ruff check . && uv run ruff format --check . && uv run pytest
```

Running a scenario additionally needs Docker, Containerlab, and an imported Arista cEOS
image. See [docs/emulation-fidelity.md](docs/emulation-fidelity.md) for why cEOS
specifically — it is the only platform that both expresses the failures under test and can
be parsed by Batfish.

## Layout

Target layout is PROJECT.md §4.1. What exists today:

```
cassandra/factpack/    schema + EOS config parser
cassandra/facts/       FACTS tier: deterministic rules
cassandra/timing/      TIMING tier: discrete-event model + sequence enumeration
cassandra/app.py       local web view (stdlib only)
cassandra/cli.py       check | facts | serve
scenarios/             CI emulation validator + its configs
docs/                  spec, conventions, decisions, fidelity, design
tests/                 219 tests
```

## State

Phases 1, 2, 3 and 5 are complete; `docs/DECISIONS.md` carries live status and the reasoning
behind every choice.

**Phase 4 — validating the timing model against real firmware — is not done, and this matters.**
Timing findings currently rest on a model that no real protocol implementation has checked. The
model says so, the CI workflow says so, and the decision log says so. Supplying a cEOS image and
dispatching `validate-timing-model.yml` is what closes it.

Separately, Batfish has been run against the shipped corpus: it parses the configs, models all
six VRRP groups and reports the network healthy — while the timing tier finds a ninety-second
gateway split in the same configs. That contrast is the thesis, and it is reproducible today.
