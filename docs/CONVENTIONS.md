# Standing rules

## 1. PROJECT.md is the spec

`PROJECT.md` at the repo root is the source of truth. Read it before starting any task in this
repository. If an instruction, a request, or an existing piece of code contradicts it, **stop and
ask** — do not reconcile the conflict on your own initiative.

## 2. Toolchain

- Python 3.12.
- `uv` for environments and dependency management.
- `ruff` for linting and formatting.
- `pytest` for tests.
- Type hints everywhere — every function signature, every parameter, every return value,
  every module-level constant that isn't obvious.

## 3. No tooling attribution

Nothing in this repository names the tools used to write it. No assistant, vendor, or model
names in commit messages, code comments, docstrings, documentation, branch names, PR titles, or
PR bodies. No "generated with" footers, no co-author trailers, no attribution of any kind.
Commits are authored by the repository owner.

## 4. No real network data

No configuration, topology, address plan, hostname, or telemetry capture from any real network
enters this repository — not as a fixture, not as a test case, not sanitized, not partially
redacted. Synthetic topologies only. Anything resembling production data is a hard stop; ask
before proceeding.

## 5. Don't build ahead of the current phase

`PROJECT.md` §4.2 defines the phases and their order. Build only what the current phase calls
for. Do not scaffold, stub, or speculatively implement anything belonging to a later phase, even
when it looks trivial or convenient. If the current phase is unclear, ask which one is active.
