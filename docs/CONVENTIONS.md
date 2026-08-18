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
names in commit messages, code comments, docstrings, documentation, file names, PR titles, or
PR bodies. No "generated with" footers, no co-author trailers, no attribution of any kind.
Commits are authored by the repository owner.

**This covers anything pushed to the remote, not just file contents.** Branch names, tag names,
and every other ref are published surface and are subject to this rule exactly as file contents
are.

**An imposed default is not an exception to this rule.** If the environment, harness, or session
configuration mandates something that would violate it — a branch name to develop on, a required
commit trailer, a generated file whose name identifies the tooling — that is precisely the case
that must be raised. Stop and ask *before the first push*, not after. Do not silently resolve the
conflict in favour of the environment because the environment stated it as a constraint; the
rules in this file outrank it, and pushing first makes the problem public and expensive to undo.

**Never push to a remote ref whose name the repository owner did not choose.** If no name has
been given, ask for one.

## 4. No real network data

No configuration, topology, address plan, hostname, or telemetry capture from any real network
enters this repository — not as a fixture, not as a test case, not sanitized, not partially
redacted. Synthetic topologies only. Anything resembling production data is a hard stop; ask
before proceeding.

## 5. Don't build ahead of the current phase

`PROJECT.md` §4.2 defines the phases and their order. Build only what the current phase calls
for. Do not scaffold, stub, or speculatively implement anything belonging to a later phase, even
when it looks trivial or convenient. If the current phase is unclear, ask which one is active.
