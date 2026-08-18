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

## 6. Cite the spec by section, and keep the citations true

Code and docs refer to `PROJECT.md` by section number. Those citations are load-bearing and
they rot silently when the spec is revised. `tests/test_spec_references.py` fails on any
`§n.n` in the repository that does not resolve to a heading in the spec — when a revision
moves a section, update the references in the same change rather than leaving citations that
still look authoritative while pointing somewhere else.

## 7. How the build loop runs

This project is built autonomously. The repository owner should be able to leave it alone for
long stretches and come back to working, pushed, tested code. That requires the loop to make
decisions rather than queue them.

### 7.1 The loop

One iteration:

1. **Read** `PROJECT.md` §4.2 and pick the smallest next unfinished piece of the *current*
   phase. Never a later phase (rule 5).
2. **Decide** anything the piece requires, per §7.2. Record it per §7.3.
3. **Build** it, with tests that would fail without it.
4. **Verify**: `uv run ruff check .`, `uv run ruff format --check .`, `uv run pytest`. All
   three green, or the iteration is not finished.
5. **Commit and push.** Never end an iteration with a dirty tree or unpushed work — the
   session's container is ephemeral and uncommitted work is lost work.
6. **Update status**: the phase checklist in `docs/DECISIONS.md`, so the next iteration (or a
   fresh session with no memory of this one) knows exactly where things stand.

A phase is done when its "Done when" clause in §4.2 is objectively true — a command runs and
produces the stated output. Not when it feels complete.

### 7.2 Decide, do not block

**Default: choose, act, and record.** A blocked loop produces nothing, and most decisions are
reversible in minutes.

Escalate to the owner *only* when one of these is true:

- The action is **irreversible or externally visible** — publishing, deleting remote refs,
  posting, spending money, anything touching a system outside this repository.
- It requires a **credential, licence, or account** only they can obtain.
- It **contradicts `PROJECT.md`**. The spec outranks the loop; a conflict is a stop-and-ask
  (rule 1), not a judgement call.
- Getting it wrong would **waste a phase or more** of work, and there is no cheap way to find
  out which choice is right.

Everything else — library choice, file layout, naming, test strategy, parser scope, output
format, what to build first within a phase — is decided by the loop and logged.

When escalating, do the parts that do not depend on the answer first, ask one specific
question with a recommendation, and leave the repository in a working state.

### 7.3 The decision log

Every decision that a future reader might otherwise have to reverse-engineer goes in
`docs/DECISIONS.md`, newest first:

```
## YYYY-MM-DD — <the decision, in one line>
**Context:** what forced a choice
**Options:** what else was considered
**Chosen:** what was done, and why
**Reversal:** what it would cost to undo
```

This is not ceremony. It is what makes an unattended loop auditable: the owner can read the
log and see not just what was built but what was traded away, and disagree with any of it
after the fact rather than being asked in advance.

### 7.4 Reporting honestly

The loop reports what it did, including what it broke, skipped, or could not verify. An
iteration that discovered a flaw in earlier work and fixed it is a good iteration and should
say so plainly. Never describe work as verified when it has only been written — the difference
between "the tests pass" and "it has never been run" is the difference between a tool and a
document.
