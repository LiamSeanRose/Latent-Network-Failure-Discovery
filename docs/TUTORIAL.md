# A worked example

This walks through one small network from first run to a clean check: what the tool derived from
the configs, what each finding means, how to fix it, and how to tell afterwards whether you broke
something else on the way. It ends with the parts that are not about one run in a terminal — the
baseline a later run compares itself against, the exit status a pipeline reads, and the page you
can send to someone who will not run anything.

Everything below is a real run against `examples/two-site/`, a corpus that ships with the
repository. Output is pasted as it came out. Where a block is trimmed, it says so.

You need `uv` and a clone of this repository — see [INSTALL.md](INSTALL.md) if you have neither.
Commands are written as `uv run cassandra …`; if you installed the tool with `pipx` or
`uv tool install`, drop the `uv run` and they work the same.

Work on a copy, so the corpus stays as the tests expect it:

```sh
cp -r examples/two-site /tmp/tutorial
```

## The network

Six devices, two sites, one edge router. Everything in the corpus is invented: the addresses are
RFC 1918, the AS numbers are private, and the names describe roles.

```
                            edge1  AS 65010
                         Et1  Et2   Et3
                          |    |      |
          .---------------'    |      '---------------.
          |                    |                      |
     north-agg1 --- Vlan99 --- north-agg2        south-agg1  AS 65003
     AS 65001                                    VRRP 30
     VRRP 10, 20               VRRP 10, 20            |
          |                    |                      |
          '----- north-acc1 ---'                 south-acc1
```

North has a redundant gateway pair carrying VLAN 10 (desks) and VLAN 20 (phones), with
`north-agg1` the intended master for both and `Ethernet1` on each of them the uplink to `edge1`.
South has a single gateway. `north-acc1` and `south-acc1` are pure layer 2.

## 1. What the tool read

Before the findings, look at what was materialised from the config text. Everything the checks
say is derived from this and nothing else.

```
$ uv run cassandra facts /tmp/tutorial
fact-pack fp_cd6b8292e4eb  devices=6  digest=cd6b8292e4eb

device edge1  nos=eos
  Loopback0  kind=loopback  10.255.0.10/32
  Ethernet1  kind=physical  10.0.10.0/31  mode=routed
  Ethernet2  kind=physical  10.0.10.2/31  mode=routed
  Ethernet3  kind=physical  10.0.20.0/31  mode=routed

device north-acc1  nos=eos
  Ethernet1  kind=physical  mode=trunk  trunk-vlans=10,99
  Ethernet2  kind=physical  mode=trunk  trunk-vlans=10,99
  Ethernet3  kind=physical  mode=access  access-vlan=10
  Ethernet4  kind=physical  mode=access  access-vlan=20
```

Trimmed after the second device — the other four print the same way. The tail is the part worth
reading twice:

```
fhrp vrrp group=10 virtual=10.10.0.1
  north-agg1:Vlan10  priority=110  preempt=yes  tracks=UPLINK->Ethernet1 -40
  north-agg2:Vlan10  priority=100  preempt=yes  tracks=none
fhrp vrrp group=20 virtual=10.20.0.1
  north-agg1:Vlan20  priority=110  preempt=yes  tracks=UPLINK->Ethernet1 -40
  north-agg2:Vlan20  priority=100  preempt=yes  tracks=none
fhrp vrrp group=30 virtual=10.30.0.1
  south-agg1:Vlan30  priority=110  preempt=yes  tracks=none

timers
  north-agg1:Vlan10  group=10  hello=1000ms  source=configured
  north-agg1:Vlan20  group=20  hello=1000ms  preempt-delay=60000ms  source=configured
  north-agg2:Vlan10  group=10  hello=1000ms  source=configured
  north-agg2:Vlan20  group=20  hello=1000ms  source=configured
  south-agg1:Vlan30  group=30  hello=1000ms  source=configured
```

Two facts there do the work in the rest of this document. Groups 10 and 20 have the same members,
the same priorities and the same tracked interface — and group 20 has a 60-second preempt delay
that group 10 does not. Group 30 has one member.

`facts` also prints an `unparsed` section listing lines no parser accounted for. This corpus has
none; if yours does, read that list before trusting any finding, because a rule cannot reason
about a line nobody read.

## 2. The first check

```
$ uv run cassandra check /tmp/tutorial
HIGH  edge1  BGP peering with south-agg1 is configured on one side only
        edge1 peers to 10.0.20.1, but south-agg1 has no neighbor statement back. The session never establishes and the config looks complete on this device

HIGH  north-acc1  Ethernet4 is in VLAN 20, which leaves north-acc1 on no trunk
        VLAN 20 is terminated on north-agg1, north-agg2, but no trunk on north-acc1 permits it and there is no SVI for it here, so anything on Ethernet4 is confined to this switch and has no route to its gateway

HIGH  north-agg1  VRRP 10 and VRRP 20 can end up on different devices
        they share a device pair but respond to the same event differently, leaving the gateways split for about 60s
        trigger: flap north-agg1:Ethernet1 1x (10s down, 20s up)

MED   north-agg1  VRRP 10 changes master 5 times under a single flap sequence
        each transition is a forwarding interruption for everything using that gateway; this group has no preempt delay, so it follows the interface immediately
        trigger: flap north-agg1:Ethernet1 3x (10s down, 20s up)

MED   north-agg1  VRRP 20 changes master 5 times under a single flap sequence
        each transition is a forwarding interruption for everything using that gateway; this group waits 60s before preempting, so it chases flaps spaced further apart than that
        trigger: flap north-agg1:Ethernet1 3x (10s down, 90s up)

MED   south-agg1  VRRP 30 has only 1 member
        a redundancy group with one member provides no redundancy

INFO  south-agg1  Vlan30 is the only interface on 10.30.0.0/24
        no other device in these configs is addressed in this subnet, so nothing here can be an IGP, BFD or FHRP peer of it

high=3  medium=3  info=1   (facts=4, timing=3)
run with --explain for evidence, fixes and rule ids
```

The exit status is 1, because there are findings. That is the whole interface for a hook or a
pipeline: nothing has to parse the text.

`--explain` adds four kinds of line to each finding: where in your files to go, the evidence it
was derived from, the change that would remove it, and the rule id so you can look the check up
with `cassandra rules <id>`. The sections below quote the `--explain` form of one finding at a
time.

## 3. A VLAN that leaves on no trunk

```
$ uv run cassandra check /tmp/tutorial --explain
...
HIGH  north-acc1  Ethernet4 is in VLAN 20, which leaves north-acc1 on no trunk
        VLAN 20 is terminated on north-agg1, north-agg2, but no trunk on north-acc1 permits it and there is no SVI for it here, so anything on Ethernet4 is confined to this switch and has no route to its gateway
        source: north/north-acc1.cfg:24
        evidence: north-acc1:Ethernet4 access vlan 20
        evidence: north-acc1:Ethernet1 allowed 10,99
        evidence: north-acc1:Ethernet2 allowed 10,99
        fix: add VLAN 20 to the trunk that carries this switch's uplink, or move the port to a VLAN the uplink already carries
        rule: access-vlan-not-trunked (facts)
```

One finding excerpted from the full run.

`source: north/north-acc1.cfg:24` is where to go: the path relative to the directory you pointed
at, and the line that declares the thing the rule objected to — here `interface Ethernet4`. A
finding about a VRRP group points at that group's first line rather than the interface header,
and a finding that is a statement about two devices at once names the file without a line,
because there is no single line to blame.

The three evidence lines are the whole argument: a port in VLAN 20, and the only two trunks on
that switch permitting 10 and 99. A phone on Ethernet4 comes up, gets a link light, learns
nothing and reaches nothing. The VLAN exists on the aggregation pair, so this is not a spare port
parked in an unused VLAN — that case is deliberate and the rule stays quiet on it.

This is what a VLAN looks like after it is removed from an allowed list during an unrelated
cleanup. Fix it on `north-acc1` by putting VLAN 20 back on both uplink trunks:

```
interface Ethernet1
   description to north-agg1
   switchport mode trunk
   switchport trunk allowed vlan 10,20,99
!
interface Ethernet2
   description to north-agg2
   switchport mode trunk
   switchport trunk allowed vlan 10,20,99
```

Run it again and the finding is gone — the count line drops from `high=3` to `high=2` and
`facts=4` to `facts=3`:

```
$ uv run cassandra check /tmp/tutorial
HIGH  edge1  BGP peering with south-agg1 is configured on one side only
        edge1 peers to 10.0.20.1, but south-agg1 has no neighbor statement back. The session never establishes and the config looks complete on this device

HIGH  north-agg1  VRRP 10 and VRRP 20 can end up on different devices
        they share a device pair but respond to the same event differently, leaving the gateways split for about 60s
        trigger: flap north-agg1:Ethernet1 1x (10s down, 20s up)
...
high=2  medium=3  info=1   (facts=3, timing=3)
run with --explain for evidence, fixes and rule ids
```

Trimmed after the second finding; the rest of the list is unchanged.

## 4. A session only one end knows about

```
HIGH  edge1  BGP peering with south-agg1 is configured on one side only
        edge1 peers to 10.0.20.1, but south-agg1 has no neighbor statement back. The session never establishes and the config looks complete on this device
        source: edge/edge1.cfg
        evidence: edge1 AS 65010 -> 10.0.20.1
        fix: add the reciprocal neighbor on south-agg1, or remove this one
        rule: bgp-session-one-sided (facts)
```

`edge1` has `neighbor 10.0.20.1 remote-as 65003`. `south-agg1` owns 10.0.20.1 and has a
`router bgp 65003` stanza with a router-id and no neighbors at all — a turn-up that was started
and not finished. The session will sit in Active on `edge1` forever, and `edge1`'s configuration
looks complete when you read it on its own. It only looks wrong next to the other file, which is
why this is a directory-level check rather than a per-device one.

The rule is decidable only when both devices are in the corpus. A peering with an upstream
provider whose config you do not have is silent, not reported — that is not a defect, it is a
missing file.

Finish the turn-up on `south-agg1`:

```
router bgp 65003
   router-id 10.255.0.3
   neighbor 10.0.20.0 remote-as 65010
   neighbor 10.0.20.0 description edge1
```

```
$ uv run cassandra check /tmp/tutorial
HIGH  north-agg1  VRRP 10 and VRRP 20 can end up on different devices
        they share a device pair but respond to the same event differently, leaving the gateways split for about 60s
        trigger: flap north-agg1:Ethernet1 1x (10s down, 20s up)
...
high=1  medium=3  info=1   (facts=2, timing=3)
run with --explain for evidence, fixes and rule ids
```

Trimmed to the first finding and the count line.

## 5. Two findings that are not bugs in a file

```
MED   south-agg1  VRRP 30 has only 1 member
        a redundancy group with one member provides no redundancy
        source: south/south-agg1.cfg:24
        fix: configure the group on the peer device, or remove it
        rule: fhrp-no-redundancy (facts)

INFO  south-agg1  Vlan30 is the only interface on 10.30.0.0/24
        no other device in these configs is addressed in this subnet, so nothing here can be an IGP, BFD or FHRP peer of it
        source: south/south-agg1.cfg:21
        evidence: south-agg1:Vlan30
        fix: confirm the far end is outside these configs; if it is not, check the address for a wrong octet or prefix length
        rule: l3-interface-isolated (facts)
```

Both are statements about the *input*, and both are worth keeping. `south-agg1` runs VRRP 30 with
no peer: either the peer's config is not in the directory you pointed at — in which case the
analysis of that group is incomplete and you should know it — or the group really is configured
on one device, and the virtual address is a second name for a single point of failure. Only you
can tell which. The same applies to the `INFO`: a subnet with one interface on it is either a
link to something outside the corpus or a typo in a prefix.

They are left as they are for the rest of this walkthrough. A tool that lets you silence findings
it cannot decide is a tool that will silence the ones it can; the baseline in section 7 is the
mechanism for accepting a known finding without deleting the check.

## 6. Reading a TIMING finding

This is the finding the tool exists for, and it is the one to be most careful with.

```
HIGH  north-agg1  VRRP 10 and VRRP 20 can end up on different devices
        they share a device pair but respond to the same event differently, leaving the gateways split for about 60s
        trigger: flap north-agg1:Ethernet1 1x (10s down, 20s up)
        source: north/north-agg1.cfg
        evidence: t=0s north-agg1:Ethernet1 down
        evidence: t=10s north-agg1:Ethernet1 up
        evidence: held in 3 of 3 runs at ±20% of the interval; absent with no events
        fix: make tracking and preempt delay consistent across groups on the same pair
        rule: fhrp-divergence (timing)
```

Nothing in the two configs is wrong on its own. Group 10 tracks the uplink and preempts back as
soon as it returns. Group 20 tracks the same uplink and waits 60 seconds before preempting back.
Both lines are defensible; the defect is that they are on the same pair of devices.

### What the trigger line means

`trigger: flap north-agg1:Ethernet1 1x (10s down, 20s up)` is a sequence of events, not a
prediction and not a description of anything that has happened. Read it as: *if* Ethernet1 on
north-agg1 goes down once and comes back ten seconds later, here is what the model says the
control plane does.

The tool arrives at that sequence by enumerating, not by guessing. It flaps only interfaces some
group actually tracks — nothing else can change an election — one, two and three times, always
ten seconds down, with an up-interval of twenty seconds by default and, for every preempt delay
it found in the configs, one interval well inside that delay and one comfortably past it. The
boundary is where behaviour changes, so that is where it looks. The trigger you see is the
sequence that exposed the finding, not the only one that would.

That is why the two `fhrp-oscillation` findings in the first run carry different triggers:
`3x (10s down, 20s up)` for group 10 and `3x (10s down, 90s up)` for group 20. Ninety seconds is
group 20's sixty-second preempt delay plus the settle time — the candidate interval that lets it
finish preempting before the next flap takes the group away again. Twenty seconds would not have
exposed anything on group 20, and ninety was never needed for group 10.

Each of those two findings says which of the two it is in its own detail line — group 10 *has no
preempt delay, so it follows the interface immediately*, group 20 *waits 60s before preempting,
so it chases flaps spaced further apart than that* — and they carry different fixes for the same
reason. Two timing findings with the same title are rarely the same finding; the trigger and the
detail are where they differ.

### Why the evidence matters

```
        evidence: t=0s north-agg1:Ethernet1 down
        evidence: t=10s north-agg1:Ethernet1 up
        evidence: held in 3 of 3 runs at ±20% of the interval; absent with no events
```

The first two lines are the event log the model was advanced through, on the model's own clock.
They exist so you can disagree with them. A FACTS finding is decidable from the configuration — if one is
wrong, it is a bug in the tool. A TIMING finding is the output of a model of timer interaction
(PROJECT.md §2.2), and the honest thing it can do is show its working.

Follow the arithmetic here. At `t=0` the uplink drops; `north-agg1` loses 40 priority on both
groups, falls below `north-agg2`'s 100, and both groups end up on `north-agg2`. At `t=10` the
uplink returns and both members are back to 110. Group 10 has no preempt delay and takes its
group straight back. Group 20 waits 60 seconds. For that minute, traffic for VLAN 10 leaves
through `north-agg1` and traffic for VLAN 20 leaves through `north-agg2`. A stateful firewall, a
NAT table or an asymmetric-path check that assumes one default gateway per site sees that minute
and then the network heals, which is exactly why it is so hard to find after the fact.

The third line is a different kind of evidence: it says the finding survived two attempts to
kill it (PROJECT.md §2.4). The sequence was run three times — at the interval printed in the
trigger, and at a fifth below and a fifth above it — and the divergence appeared in all three.
Then the same configs were run with no events in them at all, and it did not appear. A result
that shows up only at one exact interval is an artifact of the model's one-second grid rather
than a property of your configuration; a result that also shows up when nothing happens was
never caused by the trigger and belongs to the FACTS tier. Neither is true here, and this line
is where you would see it if it were.

The web view in section 10 draws that run as bands, which is the fastest way to check the
arithmetic yourself.

### What you should not conclude from it

- **Not that your network will break.** The claim is that your configuration *permits* this
  sequence. Whether the sequence happens is a question about your links, not your files
  (PROJECT.md §5.3).
- **Not that the window is exactly 60 seconds.** The model advances on a fixed one-second grid,
  loses nothing, jitters nothing and delivers every advertisement on time. "About 60s" is
  arithmetic over configured timers, not a measurement.
- **Not that this trigger is what will happen.** Ten seconds down and twenty up is a sequence the
  enumerator chose because it exposes the boundary. A real flap will not look like it.
- **Not that it is true on every platform.** The whole finding rests on preempt delay being
  measured from the moment a *tracked* interface recovers. That is Arista's reading. On Cisco's
  reading of `standby delay minimum` the delay applies to the group's own interface coming up, so
  an HSRP group whose tracked uplink flaps would preempt back immediately and this divergence
  would not exist at all. That risk is written down as assumption A11 in
  [timing-model.md](timing-model.md), with the lab observation that would settle it.
- **Not that silence means safe.** The enumeration is bounded — at most three flaps, a fixed
  ten-second down interval, up-intervals derived from the preempt delays it found. A defect that
  needs a fourth flap or a different interval is not in the search space.

[timing-model.md](timing-model.md) is the register of every assumption the model makes, each with
what firmware is believed to do instead, how confident that is, and the specific observation that
would falsify it. Read it before you act on a timing finding, and read it again before you
dismiss one.

### Fixing it

Make the two groups answer the event the same way. Give group 10 the same preempt delay group 20
has, on `north-agg1`:

```
interface Vlan10
   description clients
   ip address 10.10.0.2/24
   vrrp 10 ipv4 10.10.0.1
   vrrp 10 priority-level 110
   vrrp 10 preempt
   vrrp 10 preempt delay minimum 60
   vrrp 10 advertisement interval 1
   vrrp 10 tracked-object UPLINK decrement 40
```

```
$ uv run cassandra check /tmp/tutorial --explain
MED   north-agg1  VRRP 10 changes master 5 times under a single flap sequence
        each transition is a forwarding interruption for everything using that gateway; this group waits 60s before preempting, so it chases flaps spaced further apart than that
        trigger: flap north-agg1:Ethernet1 3x (10s down, 90s up)
        source: north/north-agg1.cfg:36
        evidence: t=0s north-agg1:Ethernet1 down
        evidence: t=10s north-agg1:Ethernet1 up
        evidence: t=100s north-agg1:Ethernet1 down
        evidence: t=110s north-agg1:Ethernet1 up
        evidence: t=200s north-agg1:Ethernet1 down
        evidence: t=210s north-agg1:Ethernet1 up
        evidence: held in 3 of 3 runs at ±20% of the interval; absent with no events
        fix: raise the preempt delay past 60s, or damp the interface so it stops flapping
        rule: fhrp-oscillation (timing)
...
medium=3  info=1   (facts=2, timing=2)
```

Trimmed to the first finding and the count line.

The divergence is gone: `timing=3` became `timing=2` and no `HIGH` is left. Both groups now move
together, which is what the finding asked for.

What remains is worth noticing. Group 10 still oscillates, and everything about that finding has
changed except its title. Its trigger moved from `3x (10s down, 20s up)` to
`3x (10s down, 90s up)`, its detail line went from *no preempt delay, so it follows the interface
immediately* to *waits 60s before preempting*, and its fix went from "add a preempt delay" to
"raise the preempt delay past 60s, or damp the interface". The two oscillation findings are now
identical apart from the group number and the line they point at, which is the tool saying the
two groups have become the same shape of problem.

Removing a divergence does not remove the underlying fact that both groups chase a flapping
uplink. Fixing *that* means either a delay longer than any plausible flap interval, or no preempt
at all on the groups that do not need it.

## 7. Did I break something?

`--since` is the question a QA tool is actually for. Record the current state, make a change, and
ask what is new.

```
$ uv run cassandra check /tmp/tutorial --save-baseline /tmp/base.json
baseline written to /tmp/base.json
```

The baseline notice goes to stderr and the findings still print on stdout, so saving one does not
change what a pipeline sees. The exit status still reports the check — a run with findings exits
1 even when the baseline is written.

With nothing changed:

```
$ uv run cassandra check /tmp/tutorial --since /tmp/base.json
no new findings since baseline

4 unchanged

baseline taken 2026-08-19 06:24Z
configs unchanged since baseline — any difference above is a
change in the checks, not in the network
run with --explain for evidence, fixes and rule ids
```

Exit status 0. The timestamp will be whenever you took yours. That last sentence is the part that
earns the feature: the baseline records a digest of the configs, so the tool can tell you whether
a difference came from your network or from the tool's own rules changing under you.

Now make a change. Add the second voice range everybody has been asking for — VLAN 21, with an
SVI on each aggregation switch. On `north-agg1` and `north-agg2`, extend the VLAN declaration and
add the interface:

```
vlan 10,20,21,99
```

```
interface Vlan21
   description second voice range
   ip address 10.21.0.2/24
```

(`.2` on `north-agg1`, `.3` on `north-agg2`.) Ask what changed:

```
$ uv run cassandra check /tmp/tutorial --since /tmp/base.json
2 new since baseline

MED   north-agg1  Vlan21 has no trunk carrying VLAN 21
        the interface is up and addressed but the VLAN reaches no neighbour, so anything relying on it is isolated

MED   north-agg2  Vlan21 has no trunk carrying VLAN 21
        the interface is up and addressed but the VLAN reaches no neighbour, so anything relying on it is isolated

4 unchanged

baseline taken 2026-08-19 06:24Z
configs changed since baseline (04d19e9e47f7 -> 9831133f8815)
run with --explain for evidence, fixes and rule ids
```

Exit status 1. The four findings you already knew about are one line, not four screens — they
were accepted when the baseline was taken, and a regression check that goes red on a backlog is a
regression check that gets switched off. Only *new* findings fail `--since`.

The addresses are routable and the SVIs are up; the VLAN just leaves on nothing. Put 21 on the
trunks that carry the north site — `Ethernet2` and `Ethernet3` on both aggregation switches, and
both uplinks on `north-acc1` — and add it to `north-acc1`'s VLAN declaration, which is the other
half of the same change:

```
   switchport trunk allowed vlan 10,20,21,99
```

```
vlan 10,20,21,99
```

```
$ uv run cassandra check /tmp/tutorial --since /tmp/base.json
no new findings since baseline

4 unchanged

baseline taken 2026-08-19 06:24Z
configs changed since baseline (04d19e9e47f7 -> fe10a7c21168)
run with --explain for evidence, fixes and rule ids
```

Exit status 0. The configs changed, the digest says so, and nothing new broke.

`--since` reports the other direction too. Record a baseline on the corpus as it ships and
compare your fixed copy against it, and everything you removed comes back under `fixed`:

```
$ uv run cassandra check examples/two-site --save-baseline /tmp/shipped.json
$ uv run cassandra check /tmp/tutorial --since /tmp/shipped.json
no new findings since baseline

3 fixed since baseline

HIGH  edge1  BGP peering with south-agg1 is configured on one side only
        edge1 peers to 10.0.20.1, but south-agg1 has no neighbor statement back. The session never establishes and the config looks complete on this device

HIGH  north-acc1  Ethernet4 is in VLAN 20, which leaves north-acc1 on no trunk
        VLAN 20 is terminated on north-agg1, north-agg2, but no trunk on north-acc1 permits it and there is no SVI for it here, so anything on Ethernet4 is confined to this switch and has no route to its gateway

HIGH  north-agg1  VRRP 10 and VRRP 20 can end up on different devices
        they share a device pair but respond to the same event differently, leaving the gateways split for about 60s
        trigger: flap north-agg1:Ethernet1 1x (10s down, 20s up)

4 unchanged

baseline taken 2026-08-19 06:25Z
configs changed since baseline (cd6b8292e4eb -> fe10a7c21168)
run with --explain for evidence, fixes and rule ids
```

The `--save-baseline` line printed `baseline written to /tmp/shipped.json` on stderr, which is
trimmed here. Those three are the sections above, in the order you fixed them, and they are the
baseline's copies rather than the current run's — a finding that no longer occurs has no current
copy left to print. That is also why the exit status is 0: fixing things is not a regression.

## 8. What the run did not check

A run that reports nothing has two possible meanings, and they are very different: the checks
looked and found nothing wrong, or the checks had nothing to look at. `--coverage` separates
them. It changes nothing about the findings and appends a summary underneath them:

```
$ uv run cassandra check /tmp/tutorial --coverage
...
coverage: 28 of 41 checks had something to look at. 13 were inert:
  bfd-multiplier-of-one (no BFD timers in these configs)
  dampening-exceeds-sla (no dampening profile in these configs)
  fhrp-hold-under-peer-hello (no FHRP timers in these configs sets hold time)
  and 10 more — `--coverage full` lists every check and what it was missing
```

The findings above the summary are the ones section 2 already printed; they are trimmed here.

Thirteen of forty-one checks never ran on this corpus, and none of them ran because a *fact* was
absent, not because a device was clean. Nothing in these configs sets a BFD timer, an OSPF hello,
an MTU, a native VLAN or a dampening profile, so every check that reads one of those had nothing
to decide. `--coverage full` names each one and what it was missing:

```
$ uv run cassandra check /tmp/tutorial --coverage full
...
INERT  bfd-detection-below-floor          no BFD timers in these configs
INERT  bfd-multiplier-of-one              no BFD timers in these configs
INERT  bfd-no-clients                     no BFD timers in these configs
INERT  bfd-no-faster-than-igp             no IGP hello timers in these configs
                                          no BFD timers in these configs
INERT  dampening-exceeds-sla              no dampening profile in these configs
INERT  dampening-never-suppresses         no dampening profile in these configs
INERT  fhrp-hold-under-peer-hello         no FHRP timers in these configs sets hold time
INERT  fhrp-hold-under-three-hellos       no FHRP timers in these configs sets hold time
INERT  igp-dead-not-a-multiple-of-hello   no IGP hello timers in these configs
INERT  igp-dead-under-three-hellos        no IGP hello timers in these configs
INERT  mtu-mismatch                       no interface in these configs sets MTU bytes
INERT  ospf-timers-disagree               no IGP hello timers in these configs
INERT  trunk-native-vlan-not-allowed      no interface in these configs sets native VLAN
```

Trimmed: the twenty-eight `ran` lines above these, and the summary repeated below them, are
omitted. A `ran` line says either how many findings the check produced or `nothing to report`,
which is the useful half — those are the checks that looked at your configs and were satisfied.

Two things this is good for. The first is calibrating a clean run: on a corpus like this one,
"no findings" is a statement about VLANs, addressing, BGP adjacency and FHRP, and says nothing
whatever about BFD or IGP timers, because there are none to say anything about. The second is
catching a parser gap. If a check is inert for want of a fact you know is in your files —
`mtu-mismatch` reporting no interface sets an MTU when half of them do — the fact did not survive
parsing, and `cassandra facts` will show you what did.

## 9. In CI

Exit status is the verdict, so nothing has to parse the output. Plain `check` exits 1 on any
finding, which is right once a repository is clean and wrong on the day you adopt the tool.
`--fail-on` decides the verdict without narrowing the report:

```
$ uv run cassandra check examples/two-site --fail-on high
```

That is the corpus as it ships, with three `HIGH` findings, and it exits 1. Its output is
byte-for-byte the run in section 2 — `--fail-on` decides the verdict and changes nothing else.
The same flag on the copy you have been fixing prints everything and exits 0, because nothing
above `MED` is left:

```
$ uv run cassandra check /tmp/tutorial --fail-on high
MED   north-agg1  VRRP 10 changes master 5 times under a single flap sequence
        each transition is a forwarding interruption for everything using that gateway; this group waits 60s before preempting, so it chases flaps spaced further apart than that
        trigger: flap north-agg1:Ethernet1 3x (10s down, 90s up)

MED   north-agg1  VRRP 20 changes master 5 times under a single flap sequence
        each transition is a forwarding interruption for everything using that gateway; this group waits 60s before preempting, so it chases flaps spaced further apart than that
        trigger: flap north-agg1:Ethernet1 3x (10s down, 90s up)

MED   south-agg1  VRRP 30 has only 1 member
        a redundancy group with one member provides no redundancy

INFO  south-agg1  Vlan30 is the only interface on 10.30.0.0/24
        no other device in these configs is addressed in this subnet, so nothing here can be an IGP, BFD or FHRP peer of it

medium=3  info=1   (facts=2, timing=2)
run with --explain for evidence, fixes and rule ids
```

A job that blocks on new findings and prints the rest:

```yaml
- name: config check
  run: |
    uv sync
    uv run cassandra check ./configs --explain --since baseline.json
```

Commit `baseline.json` next to the configs and regenerate it deliberately, with
`--save-baseline`, when you accept a finding. The two flags answer different questions and
compose: `--fail-on high` sets the bar for a first adoption, `--since` holds the line once you
are behind it.

For a pipeline that wants structure rather than text, `--json` prints the fact pack id, the
config digest, the counts and every finding with its rule, tier, severity, device, evidence and
remedy:

```
$ uv run cassandra check examples/two-site --json
{
  "fact_pack_id": "fp_cd6b8292e4eb",
  "config_digest": "cd6b8292e4ebeef2f3c9dddfb8f2661641448c09628b36788a3c8c63f0981269",
  "counts": {
    "high": 3,
    "medium": 3,
    "info": 1
  },
  "findings": [
    {
      "rule": "bgp-session-one-sided",
      "tier": "facts",
      "severity": "high",
      "device": "edge1",
      "title": "BGP peering with south-agg1 is configured on one side only",
...
```

Trimmed after the first finding.

## 10. The web view

```
$ uv run cassandra serve /tmp/tutorial
cassandra: http://127.0.0.1:8765/?dir=%2Ftmp%2Ftutorial  (ctrl-c to stop)
```

The link already has the directory in it. It binds to loopback and reads nothing you did not
name.

Five things it has that the CLI does not.

**An adjacency map.** The devices and the links between them, drawn from the same fact pack
`cassandra facts` prints. It is the fastest way to check that the tool understood your topology
before you argue with what it says about it — a device missing from that picture is a device
whose config did not parse the way you expected. A device with findings carries a dot in the
colour of its worst one and is a link to them, so "which of these is the problem" is one click.

**A picture of the cause.** Under the map, one row per FHRP group showing its preempt delay and
its tracked decrement. The timeline further down draws the effect; this draws the cause. Two
rows that do not match are two groups that will answer the same event at different speeds, which
on this corpus is the entire divergence finding in one glance.

**A timeline under every timing finding.** Point it at the corpus as it ships —
`?dir=<your clone>/examples/two-site` — and the divergence finding carries a figure captioned
*gateway ownership over time*: one band per group, coloured by the device holding it, across the
trigger sequence. VRRP 10 sits on `north-agg2` from 0s to 9s and on `north-agg1` from 10s onward;
VRRP 20 stays on `north-agg2` until 69s. The gap between those two bands is the finding. It is
the same run the `evidence:` lines describe, drawn instead of listed, and much easier to check
for an off-by-one.

**Filters that are links.** Severity, tier, device and a free-text search are all in the query
string, so any filtered view is a URL you can send someone, and `/findings.json` answers the
same question as the page it was linked from:

```
$ curl -s "http://127.0.0.1:8765/findings.json?dir=/tmp/tutorial&severity=high"
```

**A baseline comparison.** Put a saved baseline in the second box, or pass `&since=/tmp/base.json`,
and the page gains a line reading `0 new  1 fixed  6 unchanged`, every finding arrives tagged
`new` or `known`, and the ones that stopped being reported get their own *no longer
reported* section. The CLI prints the same three numbers; the page keeps them in front of you
while you filter, so a `new` tag is visible on the finding rather than in a header three screens
up. When the configs are byte-identical to the baseline it says so in as many words, which is
what makes a difference in the findings attributable to the checks rather than to the network.

The server also answers `/rules` (every check and when each stays quiet), `/rules.json`, and
`/report.html`, which downloads a standalone file. The same file comes out of the CLI:

```
$ uv run cassandra report examples/two-site -o /tmp/out.html
wrote /tmp/out.html
```

Both come from one renderer, so the file cannot drift from what the app shows. Both are entirely
self-contained: `grep` the file for `<script` or for `http` and you get nothing. A report you
email works on a laptop with no network, and anyone can read its source before opening it.

## Cleaning up

```sh
rm -rf /tmp/tutorial /tmp/base.json /tmp/shipped.json /tmp/out.html
```

The corpus under `examples/two-site/` was never touched, and `tests/test_examples.py` asserts it
still produces the findings this document quotes.

## Where to go next

- `cassandra rules` lists every check, and `cassandra rules <id>` explains one in full —
  including the cases it deliberately stays quiet on, which is usually the more useful half.
- [RULES.md](RULES.md) is the same content as a document.
- [timing-model.md](timing-model.md) is the assumption register behind every TIMING finding.
- [INSTALL.md](INSTALL.md) covers pointing the tool at your own configs.
