# site14_vrrp_lockstep — Phase 0 ground truth

The existence proof for the whole project (PROJECT.md §4.2): a failure that is
real in emulation and invisible to static analysis. If Batfish catches this, §4.3
says the escalation boundary is wrong and the project stops.

**Nothing here has been run.** It was written in an environment with no Docker
daemon, so every file is untested. Expect to fix things on first boot; the
"Untested, in order of likelihood" section below is where to look first.

## The failure

Three VRRP groups on one aggregation pair, with asymmetry that accumulated
piecemeal and where no single line is wrong on its own:

| Group | agg-a priority | Tracks uplink | Decrement | Preempt delay min |
|---|---|---|---|---|
| 14 (clients) | 110 | yes | 40 | 0 s |
| 24 (voice) | 110 | yes | 40 | 90 s |
| 34 (mgmt) | 110 | **no** | — | 90 s |

agg-b is plain: priority 100, preempt, no tracking, no delay.

One flap of agg-a's uplink:

1. Groups 14 and 24 drop to 70, below agg-b's 100, and fail over. Group 34 does
   not track, so it stays on agg-a. **First divergence.**
2. Uplink returns. Group 14 preempts back immediately. Group 24 waits 90 s.
   **Second divergence.**
3. A second flap inside that 90 s window means group 24 never returns, while
   group 14 has now moved four times.

Three flaps at 30 s intervals leave the gateways split across both routers, with
group 14 changing master ≥4 times in 120 s — verbatim the `predicted_observable`
in PROJECT.md §6.

**The transit VLAN is load-bearing.** VLAN 99 carries an OSPF adjacency between
agg-a and agg-b over the acc1 trunks. Without it, group 34 — which does not track
the uplink — would sit on agg-a while agg-a's uplink is down, with no path
upstream, and blackhole. That would be a *reachability* failure, and "after link X
fails, is A still reachable" is a SYMBOLIC question (§1.4): Batfish would catch it,
and §4.3 reads that as the escalation boundary being wrong. The scenario has to
survive every single link failure in steady state and fail only on timing.

**Why Batfish cannot see it.** Batfish converges to one steady state, by design
(§1.3). It computes: uplink up, tracked objects up, priorities at base, all three
groups on agg-a. Healthy — and correct. The failure exists only between events,
and its existence depends on the ratio of flap interval to preempt delay. No
steady state contains it, so no steady-state analysis can reach it.

## Running it

Containerlab needs root on most installs; export `CLAB="sudo containerlab"` if
yours does.

```sh
./run.sh baseline    # deploy, settle 90s, confirm healthy
./run.sh trigger     # one flap sequence + 120s observation
./run.sh control     # same window, no flap
./run.sh perturb     # flap intervals randomised ±20%
./run.sh suite       # all of §2.5: 3x trigger, control, perturb (~30 min)
./run.sh destroy
```

`suite` redeploys the lab between runs so the three trigger runs are actually
independent rather than each inheriting the previous run's VRRP state.

Confirmation requires the observable in **≥2 of 3 `trigger` runs and absent in
`control`** (§2.5). One green run is not a result.

Score each run:

```sh
python score.py runs/<stamp>-<mode>
```

Exit status is the verdict — 0 if the run matches what its mode should produce,
1 if not — so it works as a hard condition (§2.5 wants exit codes, not judgment).
A `control` run's criterion is **inverted, not skipped**: a control that shows the
observable means the trigger was not what caused it, and the run scores as a
failure.

**Read the timeline, not the end state.** Group 24 is held on agg-b by its 90 s
preempt delay and returns roughly 90 s after the last flap, so the groups
re-converge before the window closes and the final `show vrrp` looks healthy. That
is the failure being transient, not the run failing. The evidence is in
`runs/<stamp>-<mode>/vrrp.log`: group 14 transitioning ≥4 times, and ≥60 s of
contiguous samples where group 24 and group 34 have different masters.

Each sample is written twice — human-readable to `vrrp.log`, and `| json` to
`vrrp.json.log`, both delimited by `### <epoch> <node>` lines. Build the
transition counter on the JSON: `show vrrp` text formatting is not a stable
interface, and this script was written with no lab to check it against.

Then the other half:

```sh
docker run --rm -p 9996:9996 -p 9997:9997 batfish/allinone
uv run --with pybatfish python batfish_check.py
```

`batfish_check.py` asserts in order: snapshot parses with no init issues → Batfish
actually modelled the VRRP groups → reachability healthy. Only the first two
passing makes the third mean anything. A `batfish_says: healthy` field derived
from a snapshot Batfish silently failed to parse is worse than no field at all.

## What has been checked without booting

`tests/test_scenario_site14.py` lints these files for the errors that are findable
without a lab: link endpoints naming declared nodes, every wired interface having
a config stanza, addressing that pairs up across each L3 link with no duplicates,
VRRP virtual addresses inside their own subnet and agreed between the pair, the
intended master outranking the backup, tracked objects being defined where they
are referenced, trunks carrying every group VLAN, and the asymmetry the scenario
depends on actually being present.

That catches typos and mangled addressing. It cannot tell you whether cEOS accepts
the syntax.

## Untested, in order of likelihood

1. **VRRP syntax version.** Written for current EOS (`vrrp 14 ipv4 …`,
   `priority-level`, `preempt delay minimum`, `tracked-object … decrement`).
   Releases before ~4.21 use `vrrp 14 ip …` / `vrrp 14 priority …`. Check
   `show version` and adjust if the configs reject.
2. **`show vrrp` output parsing** in `run.sh` is stored raw, not parsed. Once the
   real output format is known, add a transition counter — the summary currently
   requires reading the log.
   Probe resolution is also coarse: alpine ships busybox ping, which does not
   portably accept fractional `-i`, so loss is sampled at 1 s against a failover
   of roughly 3 s. `apk add iputils` in the client node and drop to `-i 0.2` when
   the window needs measuring properly.
3. **Admin shutdown is not a carrier loss.** `run.sh` flaps by shutting
   `agg-a Ethernet1` in config. That drives `line-protocol` tracking correctly but
   does not exercise carrier-delay or debounce behaviour, which a real flap would.
   Noted in `docs/emulation-fidelity.md` as an open fidelity item.
4. **cEOS image tag** in `topology.clab.yml` is a placeholder — retag to match
   `docker images`.
5. **OSPF adjacency over the SVIs** is suppressed with `passive-interface`, so the
   aggs peer with core1 only. If they unexpectedly peer with each other through
   acc1, that is a config bug here, not a finding.

## Caveats to carry onto any finding

- **HSRP→VRRP translation.** The original outage was HSRP; this is VRRP on cEOS,
  because cEOS is the only platform that both expresses the failure and can be
  parsed by Batfish (`docs/emulation-fidelity.md`). Preemption defaults and timer
  granularity differ between the protocols.
- **Container vs hardware** (§5.3). Before trusting any timing result, measure
  observed VRRP advertisement intervals against configured. If host scheduling
  jitter is comparable to the margins this scenario depends on, the ±20% timing
  control in §2.5 is measuring the machine rather than the network.

## Still provisional

The mechanism above is a reconstruction, not the confirmed outage. The topology,
runner, and Batfish check survive a correction; the timer table is what changes.
The part least certain is what made the real event last seven hours rather than
seconds — see `docs/phase0-design.md`.
