# Latent Network Failure Discovery

> Working name: **Cassandra**
> Status: Phase 1. This document is the source of truth for implementation.
> Revised 2026-08-18 (v3) — the user no longer needs a lab. Input is config text; emulation
> moved from a user requirement to a CI-only validator of this tool's own timing model.
> §8 records what changed and why.

---

## 0. What this is

**Point it at a directory of network configs. Get back a ranked list of latent failure modes,
each with the evidence that produced it.**

```
$ cassandra check ./configs
HIGH   agg-a  VRRP 14 and 24 can diverge under repeated uplink flap
              group 14 preempts back immediately; group 24 waits 90s
              trigger: flap Ethernet1 twice within 90s
              evidence: timer model, sequence enumerated (see --explain)

MED    agg-a  BFD detection (150ms) is slower than nothing — no client registered
LOW    acc1   trunk Ethernet2 omits VLAN 99, which agg-b has an SVI in
```

No lab. No containers. No account. `pip install`, run it on a folder, read the output.

The tool answers what it can from the configs alone, and is explicit about how it knows.
Emulation still exists — but it runs in *this project's* CI to prove the timing model tells
the truth, not on the user's machine as a prerequisite.

---

## 1. Why this is worth building

### 1.1 The gap

Config verification answers steady-state questions: is A reachable from B, does this ACL line
ever match, is there a forwarding loop. It answers them well, quickly, and offline.

It cannot answer questions containing a time quantity, a repetition count, or an ordering
claim, because those have no steady state to evaluate. What happens if a link flaps three
times in ninety seconds is not a property of a configuration. It is a property of a
configuration *plus* a sequence of events *plus* the timers that govern how the control plane
reacts.

That second class is where a large share of real outages live, and it is unserved.

### 1.2 What existing tools do

Commercial digital twins and research systems are **reactive** — a change is proposed, and the
system validates it — and predominantly **steady-state**. They also assume an operator with
infrastructure. The durable lesson from Aether (arXiv:2604.18233), whose query-writing agent
consumed 68% of its reasoning budget and produced most of its precision loss: **facts should
be materialised by deterministic code, not fetched by something that has to compose a query.**

### 1.3 Batfish — capability boundary

Batfish computes real RIB/FIB by running BGP best-path selection, OSPF SPF, IS-IS and
redistribution to convergence, offline from config text. It supports differential questions,
`differentialReachability`, ACL analysis, loop detection, traceroute, and L1-topology-aware
failure analysis.

**The decisive detail:** Batfish converges *deterministically by design*. Per the SIGCOMM 2023
evolution paper it uses protocol-specific graph colouring plus logical clocks on RIBs
specifically to eliminate race conditions from partially-converged state, so results are
stable across runs. It deliberately suppresses the exact failure class this project hunts.

Measured against this project's own configs (`docs/emulation-fidelity.md`): Batfish parses
them, models all six VRRP groups, reports the network healthy — and does **not** parse
`tracked-object`, bare `preempt`, or Arista-style `track` definitions. It is a useful
cross-check where available, and it is not a dependency.

### 1.4 Escalation boundary — canonical table

| Question shape | Tier | Rationale |
|---|---|---|
| Is A reachable from B? | SYMBOLIC | steady state |
| Does this ACL line ever match? | SYMBOLIC | static analysis |
| After link X fails, is A still reachable? | SYMBOLIC | steady state, one failure |
| Is there a forwarding loop in steady state? | SYMBOLIC | steady state |
| MTU / VLAN / tracked-object consistency | FACTS | direct assertion, no tool at all |
| Does the network converge *at all* after event E? | **TIMING** | needs event ordering |
| What happens if X flaps 3× in 90s? | **TIMING** | needs timers and repetition |
| Do FHRP groups move in lockstep or independently? | **TIMING** | needs per-group timer state |
| Is there a microloop during reconvergence? | **TIMING** | transient |
| Does preemption ordering cause oscillation? | **TIMING** | race |
| Does dampening suppress longer than the SLA? | **TIMING** | timer arithmetic |
| Does BFD detect before or after the IGP hold timer? | **TIMING** | timer race |
| Is a TIMING answer actually true on real firmware? | **EMULATION** | model validation only |

Rule of thumb: **a time quantity, a repetition count, or an ordering claim means it is not a
steady-state question.** The change in v3 is that such questions are answered by an explicit
timing model rather than requiring a lab — and the model is validated by emulation in CI.

---

## 2. The three tiers

Cost and confidence both rise down the list. The user only ever sees the first two.

### 2.1 FACTS — free, instant, certain

Deterministic assertions over the Fact Pack. No lab, no service, no model.

Catches consistency defects: an SVI whose VLAN is missing from a trunk it depends on, a
`tracked-object` naming a track that is not defined, a VRRP virtual address outside its own
subnet, MTU mismatch across a link, both `decrement` and `shutdown` on one group.

These are boring and they are real. `tests/test_scenario_site14.py` is this tier, written by
hand for one scenario; Phase 2 generalises it.

### 2.2 TIMING — free, seconds, model-derived

A discrete-event model over the timer inventory. Given the timers and a family of event
sequences (flap counts, intervals, orderings), it enumerates what the control plane does and
reports sequences that produce divergence, oscillation, a suppression window longer than an
SLA, or a detection race.

**This is the tier that makes the product interesting, and it is the one that can lie.** It
models timer interaction, not protocol implementations. Every finding it produces says so, and
carries the sequence that triggers it so a human can judge.

Its output is a *candidate*: "under this sequence, these two groups diverge for ~90s."

### 2.3 EMULATION — expensive, minutes, ground truth

Real protocol implementations in containers, with real timing.

**Not a user-facing tier.** It runs in this project's CI against public images (FRR, and cEOS
where a developer has one) for exactly one purpose: **proving the TIMING model agrees with
reality.** A timing model nobody has checked against real firmware is a guess with good
formatting.

If a TIMING prediction and an EMULATION run disagree, the model is wrong and gets fixed. That
is the only reason this tier exists in v3.

### 2.4 Falsification controls

Applies to the EMULATION tier, and to any TIMING finding that claims to be confirmed.

A run that only ever executes its happy path proves nothing. Every confirmed result must
survive:

1. **No-trigger control** — same lab, same window, no events. The observable must be absent.
   A control that exhibits it means the trigger did not cause it, and the run **fails**. The
   control's criterion is inverted, not skipped.
2. **Timing perturbation** — event intervals randomised ±20%. A result that appears only at
   exact timings is a knife-edge artifact.
3. **Repetition** — 3 runs; the observable in ≥2 of 3, to separate deterministic from flaky.

Perturbation has a prerequisite: **measure host scheduling jitter first.** If it is comparable
to the timer margins under test, the ±20% control is measuring the machine.

Conditions are evaluated over the *sampled timeline*, never the end state — a transient
failure has re-converged by the time a run finishes, so a correct run ends looking healthy.
Two properties the scorer holds to: an empty parse is never a pass, and ambiguity (two masters
for one group) is surfaced rather than resolved.

---

## 3. The Fact Pack

Structured facts materialised from config text by deterministic code: device inventory, L1/L2/L3
adjacency, FHRP groups, and a complete timer inventory. Frozen dataclasses in
`cassandra/factpack/schema.py`.

**Parsing is ours, not Batfish's.** Batfish needs Docker, which is the dependency being
removed. The tool needs a narrow slice — interfaces, addressing, VLANs, FHRP, tracking, timers
— not full RIB computation, and a line-oriented parser for IOS-style config (Arista and Cisco
share structure) is a tractable job. Where Docker *is* present, Batfish becomes an optional
cross-check on the facts, never a requirement.

### 3.1 Resource discipline

Applies to the CI emulation tier only. Containerlab imposes no default memory or CPU limits,
and an unbounded node destabilises the host: set `memory:` and `cpu:` explicitly on every
node, always. Keep topologies minimal — the smallest that can exhibit the behaviour, not the
most realistic.

---

## 4. Implementation

### 4.1 Repository layout

```
cassandra/
  factpack/
    schema.py          # frozen dataclasses (done)
    builders/          # config text -> facts. Phase 1.
  facts/
    rules.py           # FACTS tier assertions. Phase 2.
  timing/
    model.py           # discrete-event timer model. Phase 3.
    sequences.py       # event sequence enumeration. Phase 3.
  report.py            # findings -> ranked output. Phase 2.
  cli.py               # `cassandra check|facts|analyze|explain`. Phase 2.
scenarios/
  site14_vrrp_lockstep/   # emulation validator + its configs, CI only
docs/
  CONVENTIONS.md       # standing rules, including how the build loop runs
  DECISIONS.md         # decision log — every non-trivial choice, with reasoning
  emulation-fidelity.md
  phase0-design.md
tests/
```

### 4.2 Phases

Each phase ends with a working command a user could run. No phase depends on the user
installing anything beyond the package itself.

**Phase 1 — Fact Pack builders.** Parse Arista EOS config text into the existing schema:
interfaces, addressing, VLANs, trunks, FHRP groups, tracked objects, and the timer inventory.
Corpus is `scenarios/site14_vrrp_lockstep/configs/`. Done when `cassandra facts <dir>` prints
a complete fact pack and round-trips every construct those configs contain.

**Phase 2 — FACTS tier and CLI.** Assertion rules over the fact pack, a finding type, ranked
output, and the `cassandra check <dir>` entry point. Done when it finds the consistency
defects in a deliberately broken copy of the corpus and stays silent on the good one.

**Phase 3 — TIMING tier.** The timer model, sequence enumeration, and `--explain`. Done when
it independently rediscovers the site14 divergence from the configs alone, having never been
told about it.

**Phase 4 — CI emulation validation.** GitHub Actions: boot the scenario on public images,
run the falsification controls, compare against the Phase 3 prediction. Done when a
disagreement fails the build.

**Phase 5 — The app.** Local UI over the same engine: point at a folder, see findings by
severity, evidence, and the triggering sequence. Packaging so `pipx install` or a single
binary is the whole install.

**Phase 6 — Deferred discovery layer.** See §7.

### 4.3 Kill criteria

- **Phase 1** cannot parse the corpus without vendor-specific special cases piling up → the
  parsing scope is too wide; narrow to the timer inventory only.
- **Phase 3** produces findings that Phase 4 emulation contradicts more often than it confirms
  → the timing model is not trustworthy and must not ship to users.
- **Phase 3** finds nothing the FACTS tier did not already find → the expensive tier is not
  earning its place.
- Any phase requiring the user to install Docker, obtain an image, or configure a lab → the
  v3 premise has been violated; stop and redesign.

---

## 5. Open questions

### 5.1 Model fidelity versus scope

The TIMING model must be simple enough to reason about and faithful enough to be worth
trusting. Start with FHRP election and interface tracking only. Widen only where Phase 4
validation demonstrates the model already agrees with reality.

### 5.2 Config dialects

Arista EOS, Cisco IOS, Cisco NX-OS and Cisco IOS-XR are supported, chosen automatically — by
marker where one is decisive, otherwise by which parser accounts for more of the file: fewest
lines left unexplained first, then most facts actually read, because two parsers can both
explain a file completely while only one of them took anything out of it.

**The open question this section asked has been answered.** It asked where the shared machinery
stops paying, and named a third dialect as the test. Four exist now and the answer held: the
parser is the only dialect-aware component. Neither the FACTS tier nor the TIMING tier changed
for HSRP, for NX-OS, or for IOS-XR — no rule, no timer record, no view.

IOS-XR was the real test rather than the third one. It puts a first-hop redundancy group in a
top-level `router vrrp` block that nests the interface under itself, four levels down and often
a hundred lines from the interface stanza — where the other three write the group inside the
interface that runs it. The Fact Pack absorbed that without knowing it had been built for it: a
membership names its interface by name, and the subnet, the timer scope and the citation are all
resolved from that name afterwards, so a group written at the far end of a file joins the same
record as one written inside the interface.

What it cost was one thing, and it is the honest answer to "where does the shared machinery stop
paying": `stanzas` cuts a file once at column zero and strips what it finds, which cannot
represent four levels of nesting, so `blocks` cuts at the shallowest indentation and hands the
bodies back still indented, ready to be cut again. Everything else in `common.py` — VLAN ranges,
netmask conversion, IPv6 addressing, the BGP peer vocabulary, group assembly — carried over
unchanged. A fifth dialect is no longer a question about the seam; it is a question about
whether anyone needs it.

### 5.3 Slice fidelity

Container NOSes do not perfectly reproduce hardware timer behaviour, and the CI validator
inherits this: a model validated against FRR is validated against FRR. Findings carry the
caveat. This bounds how strong a claim the tool can make, and the honest phrasing is "your
configs permit this sequence," not "your network will break."

### 5.4 What the user does with a finding

A finding they cannot act on is noise. Every finding needs the specific lines responsible and
the change that would remove it.

---

## 6. Building this

The build itself runs as an autonomous loop, defined in `docs/CONVENTIONS.md` §7. The
operating rule: **decide and record, do not block.** Decisions go to `docs/DECISIONS.md` with
their reasoning and how to reverse them. Escalation to the repository owner is reserved for
the short list in that section — irreversible or external actions, licensing, anything
contradicting this document, and choices that would waste a phase if wrong.

---

## 7. Deferred: the discovery layer

Earlier versions specified an autonomous pipeline: a cheap model generating conjectures, a
deterministic filter, a frontier model attempting falsification in emulation. That machinery
exists to make *volume* affordable, and at this scale the volume is not there.

In v3 it has a clearer future job than it ever had: **the TIMING tier enumerates sequences
mechanically, and enumeration does not scale to interesting search spaces.** A model proposing
which sequences are worth enumerating is a well-defined problem, unlike "find bugs." Revisit
after Phase 4, when there is a validated model to propose against.

What survives regardless, and is reflected above: facts materialised by deterministic code,
verdicts as hard conditions rather than judgment, a survivor meaning nothing unless something
tried to kill it, and a result static analysis could have found not being a result.

---

## 8. Notes on this revision

v2 made the scenario harness the product, which required every user to run Containerlab and
obtain a licensed cEOS image. That is a lab, and building a lab is not a thing a personal QA
tool may ask of the person using it.

v3 keeps every capability and moves the cost: the input is config text, the tiers that run on
the user's machine are pure Python, and emulation becomes CI infrastructure that validates the
timing model rather than a prerequisite for using the tool.

Section numbers cited elsewhere in the repository were checked by
`tests/test_spec_references.py`. §2.2 was the Fact Pack and is now the TIMING tier; the Fact
Pack is §3. Section 2.5 was falsification controls; the EMULATION tier is now §2.3 and the controls
are §2.4. Written without the § sigil because it names a numbering that no longer
exists, and `tests/test_spec_references.py` rejects citations that do not resolve. §4.2 (phases),
§4.3 (kill criteria), §1.3, §1.4 and §5.3 keep their meanings.

## 9. Source index

- SIGCOMM 2023 — Lessons from the evolution of the Batfish configuration analysis tool
- arXiv:2604.18233 — Aether, network validation using agentic AI and digital twin
- SIGCOMM 2024 — Relational Network Verification
- PLDI 2024 — Diffy: data-driven bug finding for configurations
- containerlab.dev — kinds, resource limits
- batfish.readthedocs.io — supported devices, question framework
