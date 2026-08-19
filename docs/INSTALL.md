# Installing Cassandra

Cassandra is a single command with no runtime dependencies — standard library only, by
design (PROJECT.md §0). Installing it is installing one Python package. There is no lab,
no container, no account, and nothing to configure afterwards.

## Requirements

- **Python 3.12.** The package declares `>=3.12,<3.13`; an installer running under a
  different interpreter will refuse rather than half-work, so pass the interpreter
  explicitly if 3.12 is not your default.
- Git, for the install-from-repository commands below.

The distribution is not on PyPI, so every command below names the repository directly.
`pip install cassandra` would fetch an unrelated project of the same name.

## pipx — recommended

`pipx` keeps the tool in its own environment and puts `cassandra` on your PATH.

```sh
pipx install --python python3.12 \
  git+https://github.com/LiamSeanRose/Latent-Network-Failure-Discovery
```

`uv` does the same job without a separate installer:

```sh
uv tool install --python 3.12 \
  git+https://github.com/LiamSeanRose/Latent-Network-Failure-Discovery
```

Upgrade with `pipx upgrade cassandra` or `uv tool upgrade cassandra`; remove with
`pipx uninstall cassandra` or `uv tool uninstall cassandra`.

## pip

Into a virtual environment, so the tool does not land in your system interpreter:

```sh
python3.12 -m venv ~/.venvs/cassandra
~/.venvs/cassandra/bin/pip install \
  git+https://github.com/LiamSeanRose/Latent-Network-Failure-Discovery
~/.venvs/cassandra/bin/cassandra check ./configs
```

## From source

```sh
git clone https://github.com/LiamSeanRose/Latent-Network-Failure-Discovery
cd Latent-Network-Failure-Discovery
uv sync                    # dev environment, including pytest and ruff
uv run cassandra check ./configs
```

To build the distribution artifacts and install the wheel:

```sh
uv build                                   # dist/*.whl and dist/*.tar.gz
uv tool install ./dist/cassandra-0.0.0-py3-none-any.whl
```

`tests/test_packaging.py` reads `dist/` when a wheel is present and checks that every
package directory made it in; run `uv build && uv run pytest tests/test_packaging.py`
after changing anything about the build. `dist/` is untracked and unignored, so
`uv build --out-dir /somewhere/else` with `CASSANDRA_WHEEL_DIR=/somewhere/else` set for
the test run does the same job without leaving artifacts in the working tree.

## Verify the install

The repository ships a synthetic corpus that exercises the interesting tier. Point the
tool at it — this is the four-device site14 scenario under
`scenarios/site14_vrrp_lockstep/configs`:

```
$ cassandra check scenarios/site14_vrrp_lockstep/configs
HIGH  agg-a  VRRP 14 and VRRP 24 can end up on different devices
        they share a device pair but respond to the same event differently, leaving the gateways split for about 90s
        trigger: flap agg-a:Ethernet1 1x (10s down, 20s up)

HIGH  agg-a  VRRP 24 and VRRP 34 can end up on different devices
        they share a device pair but respond to the same event differently, leaving the gateways split for about 100s
        trigger: flap agg-a:Ethernet1 1x (10s down, 20s up)

MED   agg-a  VRRP 14 changes master 5 times under a single flap sequence
        each transition is a forwarding interruption for everything using that gateway
        trigger: flap agg-a:Ethernet1 3x (10s down, 20s up)

MED   agg-a  VRRP 24 changes master 5 times under a single flap sequence
        each transition is a forwarding interruption for everything using that gateway
        trigger: flap agg-a:Ethernet1 3x (10s down, 120s up)

high=2  medium=2   (timing=4)
run with --explain for evidence, fixes and rule ids
```

If you installed from pipx or pip rather than a clone, download the four `.cfg` files
from `scenarios/site14_vrrp_lockstep/configs/` in the repository into any directory and
pass that directory instead.

`--explain` adds the event sequence, the suggested fix and the rule id behind each
finding:

```
$ cassandra check scenarios/site14_vrrp_lockstep/configs --explain
HIGH  agg-a  VRRP 14 and VRRP 24 can end up on different devices
        they share a device pair but respond to the same event differently, leaving the gateways split for about 90s
        trigger: flap agg-a:Ethernet1 1x (10s down, 20s up)
        evidence: t=0s agg-a:Ethernet1 down
        evidence: t=10s agg-a:Ethernet1 up
        fix: make tracking and preempt delay consistent across groups on the same pair
        rule: fhrp-divergence (timing)
...
```

## The rest of the commands

```sh
cassandra facts ./configs    # the materialised fact pack the findings are derived from
cassandra serve              # local web view on http://127.0.0.1:8765
cassandra --help
```

Exit status is the verdict, so `check` drops straight into a pre-commit hook or a CI job
without anything parsing its output:

| Status | Meaning |
|---|---|
| 0 | no findings |
| 1 | at least one finding |
| 2 | the argument was not a directory, or held no `.cfg` files |

## Caveat worth reading once

Timing findings come from a model of timer interaction, not from real firmware. The
honest phrasing is "your configs permit this sequence", not "your network will break"
(PROJECT.md §5.3). Validation of that model against real protocol implementations runs in
this project's CI, never on your machine.
