# hsrp_preempt_split — the same failure, a different dialect

`site14_vrrp_lockstep` is Arista EOS and VRRP. This is Cisco NX-OS and HSRP, and
it plants the same *class* of defect with none of the same numbers.

It exists to answer one question that the unit tests over config fragments cannot:
**PROJECT.md §5.2 claims the parser is the only dialect-aware component, and that
the FACTS and TIMING tiers needed no changes to work on HSRP.** A claim backed by
fragments is a claim about fragments. This is a whole site, parsed end to end,
analysed end to end, on a dialect and a protocol neither tier was written against.

The answer is in "Did anything have to change" below. Short version: nothing did.

## The site

Four devices, all NX-OS, addressed out of 172.16.0.0/12:

```
                    (campus core, not in these configs)
                       172.16.240.0/30    172.16.240.4/30
                              |                  |
                          Eth1/1             Eth1/1
                        +--------+  Eth1/2 +--------+
                        | dist-1 |---------| dist-2 |   VLAN 900 transit
                        +--------+  trunk  +--------+   172.16.9.0/30
                          |    |            |    |
                  Eth1/3  |    | Eth1/4     |    |
                        +-------+        +-------+
                        | acc-1 |        | acc-2 |      pure L2
                        +-------+        +-------+
```

| VLAN | Purpose | Subnet | Virtual address |
|---|---|---|---|
| 120 | user data | 172.16.120.0/24 | 172.16.120.1 |
| 220 | user voice | 172.16.220.0/24 | 172.16.220.1 |
| 900 | transit between the distribution pair | 172.16.9.0/30 | — |

`dist-1` is the intended active for both groups. `dist-2` is deliberately plain:
priority 100, preempt with no delay, no tracking. Every asymmetry lives on
`dist-1`.

The configs carry the filler a real capture carries — a banner, an access list,
SNMP location and contact, two NTP servers, syslog, OSPF, `spanning-tree port
type edge`, `feature` gates, a VTY line. None of it is a fact any tier reads, and
all of it goes through the noise filter (`builders/common.py: OUT_OF_SCOPE`)
rather than being reported as unhandled. That is the point of including it: an
idealised fragment does not exercise the filter, and the filter is what decides
whether `unparsed_lines` means anything.

Everything is synthetic. RFC 1918 addressing, invented hostnames, no
organisation's naming anywhere.

## The planted defect

Two HSRP groups on one distribution pair that answer the same event at two
different speeds.

| | HSRP 120 (data) | HSRP 220 (voice) |
|---|---|---|
| `dist-1` priority | 120 | 120 |
| `dist-2` priority | 100 | 100 |
| Tracks `Ethernet1/1` | yes | yes |
| Decrement | 35 | 35 |
| Preempt | yes | yes |
| Preempt delay minimum | **none** | **45 s** |

Both groups lose the same 35 points when `dist-1`'s uplink fails, landing at 85
against `dist-2`'s 100, so both leave together. Only group 220 was ever given a
`preempt delay minimum`, so they do not come back together:

1. `dist-1 Ethernet1/1` goes down. Both groups drop to 85, both fail over to
   `dist-2`. The gateways are still together — this part is correct behaviour and
   is what makes the defect hard to see.
2. The uplink returns. Group 120 preempts back to `dist-1` immediately. Group 220
   waits out its 45-second delay.
3. For those **45 seconds**, VLAN 120 leaves the site through `dist-1` and
   VLAN 220 leaves through `dist-2`. Anything assuming one default gateway per
   site — a stateful firewall, a NAT table, an asymmetric-path check, a voice
   media pinhole — is wrong for exactly that window, and then heals.
4. A second uplink flap inside those 45 seconds restarts the delay, so group 220
   never returns while the flapping continues, while group 120 has by then moved
   four times.

No single line of this is wrong. A preempt delay on a voice VLAN is good practice
— it stops the gateway chasing a bouncing uplink. The defect is that it was
applied to one group and not the other, which is what piecemeal change over years
produces.

**None of the numbers match `site14_vrrp_lockstep`.** That scenario is VRRP,
three groups, priority 110 against 100, decrement 40, a 90-second delay, and one
group that does not track at all. This one is HSRP, two groups, 120 against 100,
decrement 35, a 45-second delay, and both groups track. The two scenarios share a
shape, not a table.

## What a correct configuration would look like

Either delay applied to both groups, or to neither. Both are defensible; mixing
them is not.

```
interface Vlan120                    interface Vlan220
  hsrp 120                             hsrp 220
    preempt delay minimum 45             preempt delay minimum 45
```

The delay itself is a real trade. With it, the group tolerates a flapping uplink
at the cost of sitting on the standby for 45 seconds longer than it has to.
Without it, the group returns instantly and chases every flap. What is not a
trade is the two groups on one pair choosing differently, because the cost of
that is a split default gateway that neither group's configuration mentions.

Two other corrections would also remove the finding and are worse: giving the two
groups different tracking so they never leave together, or removing preempt from
`dist-1` so nothing ever comes back. Both trade a transient split for a permanent
one.

## What steady-state analysis says about it

Nothing. That is the whole reason the scenario is here, and it is worth stating
precisely rather than as a slogan.

Point any steady-state analyser at these four configs and it converges to one
state: uplinks up, tracked object up, both groups at priority 120 on `dist-1`,
both virtual addresses answered by one device, every VLAN reachable. That is not
an approximation — it is correct. There is no steady state in which the defect is
present, because the defect *is* the difference between two groups' transit
times, and a converged model has no transit times in it.

Run the FACTS tier (§2.1) over this corpus and it says nothing either, and every
one of its rules is right to:

- `fhrp-track-ineffective` — 120 − 35 = 85, below `dist-2`'s 100, so the tracking
  works. It fires when a decrement is too small to lose the election; this one is
  not.
- `fhrp-priority-tie` — the priorities differ, so there is a preferred master.
- `fhrp-no-preempt-on-preferred` — `dist-1` preempts on both groups, so it does
  reclaim.
- `fhrp-track-undefined` — `track 10` is defined on `dist-1` and resolves to
  `Ethernet1/1`.
- `fhrp-virtual-outside-subnet`, `fhrp-members-on-different-subnets` — the
  addressing pairs up correctly on both segments.
- `svi-vlan-not-trunked`, `trunk-vlan-dead`, `access-vlan-not-trunked`,
  `vlan-not-declared` — VLANs 120 and 220 are declared, trunked and terminated
  everywhere they appear; VLAN 900 is declared and trunked across the peer link
  and terminated by the two transit SVIs.
- `fhrp-hold-under-three-hellos`, `fhrp-hold-under-peer-hello` — `timers 1 3` on
  every member: hold is exactly three hellos, and no member's hold is shorter
  than its peer's hello.

**A silent FACTS tier here is the load-bearing half of the scenario.** If any of
those rules fired, the expensive tier would not be earning its place — that is
PROJECT.md §4.3's third kill criterion, in miniature, on one corpus.
`tests/test_scenario_hsrp.py` asserts the silence, so a rule that later starts
firing on a healthy site is caught here rather than in someone's inbox.

## What `cassandra check` prints

```
$ uv run cassandra check scenarios/hsrp_preempt_split/configs --explain
HIGH  dist-1  HSRP 120 and HSRP 220 can end up on different devices
        they share a device pair but respond to the same event differently,
        leaving the gateways split for about 45s
        trigger: flap dist-1:Ethernet1/1 1x (10s down, 15s up)
        evidence: t=0s dist-1:Ethernet1/1 down
        evidence: t=10s dist-1:Ethernet1/1 up
        evidence: held in 3 of 3 runs at ±20% of the interval; absent with no events
        fix: make tracking and preempt delay consistent across groups on the same pair
        rule: fhrp-divergence (timing)

MED   dist-1  HSRP 120 changes master 5 times under a single flap sequence
        ... rule: fhrp-oscillation (timing)

MED   dist-1  HSRP 220 changes master 5 times under a single flap sequence
        ... rule: fhrp-oscillation (timing)

high=1  medium=2   (timing=3)
```

`fhrp-divergence` is the planted defect. The two `fhrp-oscillation` findings are
consequences of the same asymmetry rather than separate defects: group 120 has no
delay so it follows a flapping uplink exactly, and group 220 chases flaps spaced
further apart than its 45-second delay. They are reported because each transition
is a real forwarding interruption, and they are worth knowing about even though
one fix removes all three.

The 45 seconds in the finding is read off the model's timeline, not restated from
the config. The two coincide here because the delay is what governs the window;
they would not coincide if the flap interval sat inside the delay.

## Did anything have to change

**No.** The FACTS tier and the TIMING tier were not edited to make this scenario
work, and nothing in either of them was found to be missing.

What that does and does not establish:

- The FACTS rules read `FhrpGroup`, `FhrpMember` and `TrackedObject`. They branch
  on `group.protocol` only for the label they print. HSRP populated the same
  records VRRP does, so they behaved identically.
- The TIMING model reads priority, preempt, preempt delay and tracked-object
  decrements. It has one HSRP-specific correctness gap that this corpus does not
  reach: `DEFAULT_ADVERT_MS` is 1000 for every group, which is VRRP's default and
  not HSRP's (HSRP hellos default to 3 seconds). Registered as A1 in
  `docs/timing-model.md` and already known. These configs set `timers 1 3`
  explicitly, so the model's number happens to be right here — which means this
  scenario does **not** test that assumption, and should not be read as having
  validated it.
- The parser is where all the dialect awareness lives, and NX-OS needed its own
  indentation-aware splitter to get there (`builders/nxos.py`). That is the seam
  §5.2 asks about, and it held: the splitter is dialect-specific, everything
  downstream of `ParsedDevice` is not.

## What the parsers did not read

Nothing in this corpus. `uv run cassandra facts scenarios/hsrp_preempt_split/configs`
reports an empty unparsed list for all four devices, and the test asserts it.

Three constructs were tried while writing it and are **absent from the shipped
configs because the NX-OS parser does not read them**. They are recorded here
rather than quietly forgotten, since each is ordinary in a real capture:

| Line | Where it belongs |
|---|---|
| `ip access-group CORE-IN in` | under `interface Ethernet1/1` — the ACL is defined in the configs but applied nowhere |
| `ip dhcp relay address 172.16.250.10` | under `interface Vlan120` |
| `line console` | top level; `line vty` is matched by the noise filter and this is not |

None of them carries a fact any tier reads, so the right fix is a wider noise
filter rather than a new parser rule. Left alone deliberately: this scenario does
not own `cassandra/`.

## Emulation

There is none, and there should not be one yet.

`site14_vrrp_lockstep` ships a Containerlab topology because Arista cEOS is a free
download that expresses the failure and that Batfish can parse
(`docs/emulation-fidelity.md`). NX-OS has no equivalent: Nexus 9000v is a licensed
VM rather than a native container, and PROJECT.md §4.3's last kill criterion says
plainly that a phase requiring the user to obtain an image is a redesign. The
EMULATION tier (§2.3) is CI infrastructure for validating the timing model, and
site14 is the vehicle for that.

## Caveats to carry onto the finding

- **The timing finding is model-derived and has never been validated against
  firmware.** It is a claim about what a discrete-event timer model does with
  these numbers, not a claim about what a Nexus does. The honest phrasing from
  §5.3 applies unchanged: *your configs permit this sequence*, not *your network
  will break*.
- The model does not simulate HSRP. It simulates priority, tracking, preemption
  and preempt delay, and treats HSRP and VRRP as the same shape. Where the two
  protocols genuinely differ — hello defaults, the active/standby state machine,
  version 1 versus version 2 group numbering — the model is silent rather than
  right.
- The 45-second window carries up to one sample of error at each edge, because
  the model samples on a one-second grid (A2 in `docs/timing-model.md`).
- The search behind the finding is a bounded neighbourhood of flap intervals
  derived from the configured delays, not the whole space of event sequences.
  §2.4's no-trigger and perturbation controls both ran and both held; repetition
  does not apply to a deterministic model.
