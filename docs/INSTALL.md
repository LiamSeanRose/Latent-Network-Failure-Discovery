# Installing Cassandra

## What you need

[uv](https://docs.astral.sh/uv/). That is the list. Python 3.12 is pinned in `.python-version`
and uv fetches it; the tool itself is standard library only and has no dependencies.

```sh
git clone https://github.com/LiamSeanRose/Latent-Network-Failure-Discovery
cd Latent-Network-Failure-Discovery
uv sync
uv run cassandra check examples/two-site
```

Pointed at your own files, the shortest run is two words. `cassandra` on its own counts the
configs in the directory you are standing in and prints the command; `cassandra check` with no
directory checks that same directory. It never reads a directory you did not name — being run
with no arguments is a question, and it answers it rather than guessing.

If you would rather have `cassandra` on your PATH than type `uv run`:

```sh
uv tool install --python 3.12 \
  git+https://github.com/LiamSeanRose/Latent-Network-Failure-Discovery
```

`pipx install --python python3.12 git+https://…` does the same job. Upgrade with
`uv tool upgrade cassandra` or `pipx upgrade cassandra`. The distribution is not on PyPI, so
every one of these commands names the repository: `pip install cassandra` fetches an unrelated
project of the same name.

## What you do not need

No Docker. No container runtime, no lab, no emulator, no images to obtain or license. No account,
no API key, no service to sign up for. No network access at run time — the tool reads local files
and writes local files, and the web view fetches no font, script, stylesheet or image.

Emulation exists in this repository, but it runs in *this project's* CI to check the timing model
against real protocol implementations (PROJECT.md §2.3). It is never something you set up.

## Getting configs into a directory

Point `check` at a directory. It walks the tree; it does not glob one level.

```sh
uv run cassandra check ./configs
```

**What it opens.** `.cfg` and `.conf` are taken as configs on the strength of the name. `.txt`,
files with no extension, and files whose extension is not on the ignore list — a backup written
as `agg-a.example.internal` has an extension only by accident — are opened and sniffed: the first
16 KiB is read, and at least half the lines at column zero have to parse as IOS-style commands.
Prose fails that test, because a sentence is not a command.

**What it never opens.** Documents and markup, structured data, source and build files, images,
archives, binaries, captures, logs and keys, by extension. Extensionless files conventionally
named `README`, `LICENSE`, `Makefile`, `Dockerfile` and the like. Hidden files and directories, so
a `.git` alongside your configs costs nothing. Files over 8 MiB, and anything with a NUL byte in
the first 16 KiB.

**What it says out loud.** Skipping a `README.md` is not news and is not reported. Skipping a file
*you* named `.cfg`, or a file that reads as configuration but yields no device, is:

```
$ cassandra check /tmp/configs
… ConfigDiscoveryWarning: skipped /tmp/configs/site-a/rack-notes.cfg: not-config
HIGH  north-acc1  Ethernet4 is in VLAN 20, which leaves north-acc1 on no trunk
...
```

Trimmed twice: after the first finding, and at the start of the warning, where Python's warning
machinery prepends the installed path of `cli.py` and a line number and appends an echo of the
line that raised it. The message itself is the part after `ConfigDiscoveryWarning:`. It goes to
stderr, so a piped run keeps it out of the findings.

**Device names.** A config's `hostname` line names its device. A config without one is named by
its path relative to the directory you pointed at, minus the config extension — `site-a/agg-a.cfg`
becomes `site-a/agg-a`. Two files called `agg-a` under different site folders are two devices.

**Dialects.** Arista EOS, Cisco IOS, NX-OS and IOS-XR, chosen per file and never by you: by a
decisive marker where there is one, otherwise by which parser accounts for more of the file —
fewest lines left unexplained first, and then most facts actually read, because two parsers can
both explain a file completely while only one of them took anything out of it.

So a working copy, a backup target or a directory of files pulled off devices with `scp` all work
as they are. Nesting one directory per site or per role is fine and is the shape the walk was
written for.

## What it does with those files

It reads them. Nothing else: no file is written in the directory you name, nothing is uploaded,
no device is contacted, and the tool needs no credentials because it never logs in anywhere.

From the text it materialises a fact pack — interfaces, addressing, VLANs, trunks, FHRP groups,
tracked objects, BGP peerings and a timer inventory (PROJECT.md §3) — and runs the checks over
that. `cassandra facts <dir>` prints the pack, including an `unparsed` section listing every line
no parser accounted for. That list is worth reading once on a new corpus: a rule cannot reason
about a line nobody read, and a group whose priority line was missed still produces findings that
are confident and wrong.

What it does *not* do: compute a RIB or a FIB, resolve routing policy, evaluate ACLs, or answer
reachability questions. Those are steady-state questions and other tools answer them well
(PROJECT.md §1.3). This one answers the questions with a time quantity, a repetition count or an
ordering claim in them.

## Check it works

```
$ cassandra --version
cassandra 0.1.0 (checks 6c86fda181aa)
```

Two numbers because both matter in a bug report, and the second moves far more often: it is a
digest of the rule set, and it changes whenever a check is added, removed, or has its severity
reconsidered.

From a clone, there is a corpus to point it at:

```
$ uv run cassandra check examples/two-site
```

The shipped example corpus has four deliberate defects; the run prints seven findings and exits
1. [TUTORIAL.md](TUTORIAL.md) walks through what each of them means and how to fix it. Installed
on your PATH without a clone there is no `examples/` on disk — point it at your own configs, or
clone the repository beside them just for that directory.

## Running it in CI

The exit status is the verdict, so nothing has to parse the output:

| Status | Meaning |
|---|---|
| 0 | no findings, or none at or above `--fail-on`, or nothing new since `--since` |
| 1 | at least one finding that counts |
| 2 | the argument was not a directory, no configs were found in it, or a baseline file could not be read |

A job that fails on anything:

```yaml
- uses: astral-sh/setup-uv@v5
- run: uv sync
- run: uv run cassandra check ./configs --explain
```

Two flags matter for a repository that is not clean yet. `--fail-on high` prints every finding
and blocks only on the severe ones. `--since baseline.json` prints only what is new relative to a
recorded run and fails only on that, so an accepted backlog does not keep the build red — which
is how a check gets switched off. Record the baseline with
`cassandra check ./configs --save-baseline baseline.json` and commit it beside the configs;
regenerate it deliberately when you accept a finding. The baseline stores a digest of the configs
*and* of the rule set that produced it, so a run can tell you which of the two moved: a new
finding against byte-identical configs is a new check rather than a new defect, and one against a
rule set that also changed may be either — and the footer says so instead of leaving you to
assume the network did it.

`--json` gives a pipeline the same findings with their rule ids, tiers, severities, devices,
evidence and remedies, plus the fact pack id and config digest.

`--format sarif` writes a SARIF 2.1.0 log for GitHub code scanning: upload it with
`upload-sarif` and each finding becomes an annotation on the configuration line responsible for
it. `--format junit` writes a test report of the rule set rather than of the findings — a rule
that fired is a failure, one that ran and found nothing is a pass, and one that never had a fact
to reason over is a skip carrying the reason. Both are byte-identical run to run, so the
artifacts are worth diffing.

## One caveat worth reading once

FACTS findings are decidable from the configuration. If one is wrong, it is a bug.

TIMING findings are not. They come from a model of timer interaction, not from running the
protocols, so the honest phrasing is "your configs permit this sequence", not "your network will
break" (PROJECT.md §5.3). Each one carries the sequence that triggers it so you can judge it, and
[timing-model.md](timing-model.md) records every assumption the model makes and what would
falsify it.
