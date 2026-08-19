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

### 7.2 Decide and act

**The repository owner has given standing authorisation to decide and act.** The default is
not "ask" and it is not "ask when unsure" — it is act, record the reasoning, and let the owner
overrule afterwards by reading the log. A loop that queues questions produces nothing, and
being asked to approve choices you delegated is worse than being told what was done.

This applies to the whole surface: libraries, layout, naming, scope, output format, test
strategy, refactors, deleting code that no longer earns its place, and **amending
`PROJECT.md` itself** when the build shows the spec is wrong. A spec that cannot be corrected
by the work is a spec that goes stale. Amend it, and log why.

Two things remain outside this, and neither is a permission gate:

- **Blocked, not forbidden.** Some things are impossible from a session — a licensed image, a
  credential, a GitHub operation the token cannot perform. These are not decisions to escalate;
  they are obstacles to route around, report plainly, and record so the next session does not
  re-derive them. Do everything that does not depend on the blocker.
- **Genuinely destructive and outside the task.** Deleting the owner's data, force-pushing over
  work that is not yours to replace, publishing to somewhere the task never mentioned. Not
  because permission is missing, but because a reasonable person doing this job would not do it
  without being asked. Judgement, not paperwork.

Everything else: decide, do it, write it down.
### 7.3 Fan out by default

**When the next work splits into independent pieces, run them in parallel rather than in
sequence.** This is the default, not an optimisation to consider later. A parser, a rule set, a
view and a packaging change touch different files and have no ordering between them; doing them
one after another wastes most of the available throughput.

The coordination rule that makes it safe is **exclusive file ownership**: every parallel worker
is given the exact list of files it may create or edit, and no two lists overlap. Shared files —
the CLI, the spec, this document — are integrated afterwards by whoever is coordinating, never
edited concurrently. Workers do not commit; the coordinator runs the full suite and commits once
the pieces fit together.

Workers cannot message each other. Anything one needs from another goes through the coordinator,
so a task that depends on another's output is sequenced, not parallelised. Split on independence,
not on convenience.

**When not to fan out:** work with tight coupling between the pieces, and work whose bottleneck
is a slow external signal. Several workers guessing blindly against a five-minute CI loop is not
five times the progress; it is five times the guessing.

**What running this has actually taught, and what it costs to ignore:**

- *Ownership has to include the test files, and one worker per test file.* Two workers were
  once given the same test file — one adding rules, one adding tests for existing rules — and
  both appended to it. It merged because both appended, and because one of them said so in its
  report. That was luck. Name the test file in exactly one worker's list.
- *A worker appending to a file it does not own is a worse failure than editing it.* It leaves
  no conflict to notice: the file is valid, the tests pass, and the duplication (two helpers with
  the same job under different names) only shows up when someone reads it. Every worker that
  appends must say so in its report, by name.
- *Ask for the wiring, do not let the worker do it.* A worker that builds a module the CLI or
  the view should expose is told to describe the wiring precisely and not apply it. Its report
  becomes a patch the coordinator applies in one place, and two workers cannot then both be in
  `cli.py`.
- *Tell workers to leave a real defect failing.* The most valuable thing a worker produced this
  round was a red test naming a crash in a file it was forbidden to touch. A worker that
  quietly adjusts a test to match buggy behaviour has destroyed the finding; say so in the
  brief, every time.
- *The coordinator runs the suite last, not the workers.* A worker's "everything is green" is
  a claim about a tree that three other workers were editing at the time. Treat it as a claim,
  re-run it, and expect transient failures in files nobody owns to be exactly that.

### 7.4 The decision log

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

### 7.5 Reporting honestly

The loop reports what it did, including what it broke, skipped, or could not verify. An
iteration that discovered a flaw in earlier work and fixed it is a good iteration and should
say so plainly. Never describe work as verified when it has only been written — the difference
between "the tests pass" and "it has never been run" is the difference between a tool and a
document.
