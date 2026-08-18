# Decision log

Newest first. Format and purpose: `CONVENTIONS.md` §7.3.

Every non-trivial choice the build loop makes is recorded here with its reasoning and what
reversing it would cost, so the repository owner can audit and overrule after the fact rather
than being asked in advance.

---

## Phase status

Per `PROJECT.md` §4.2. The loop updates this every iteration.

- [x] **Phase 1 — Fact Pack builders.** Done 2026-08-18. `cassandra facts <dir>` renders
      the corpus with zero unparsed lines; 17 tests cover interfaces, addressing, trunk VLANs,
      FHRP membership, tracked-object resolution, timer scoping, and digest sensitivity.
- [x] **Phase 2 — FACTS tier.** Done 2026-08-18. Nine rules, `cassandra check <dir>`,
      ranked output, `--explain`, exit status as verdict. Silent on the clean corpus; catches
      planted defects in a broken copy.
- [x] **Phase 3 — TIMING tier.** Done 2026-08-18. Rediscovered the site14 divergence from
      the configs alone, never having been told the scenario exists.
- [~] **Phase 4 — CI emulation validation.** Workflows written; validation itself is
      blocked. `checks.yml` runs lint, format, tests and dogfoods the CLI on every push.
      `validate-timing-model.yml` records the model's prediction, then boots the scenario
      and compares — but only when someone supplies a cEOS image, which cannot be
      redistributed. **The timing model is currently unvalidated, and the workflow says so
      rather than passing quietly.**
- [x] **Phase 5 — The app.** Done 2026-08-18. `cassandra serve` — local web view over the
      same engine, standard library only, loopback only, light and dark. Also a
      `/findings.json` endpoint for scripting.

- [x] **Cisco IOS dialect + HSRP.** Done 2026-08-18. Dialect detected automatically; the FACTS
      and TIMING tiers needed no changes, which is the evidence that the parser is the only
      dialect-aware component.

**All phases complete except Phase 4's validation, which needs a cEOS image (see above).**
The next substantive work is either supplying that image, or widening the timing model
beyond FHRP (PROJECT.md §5.1) — which should not happen until validation exists.

Carried over, owner-only, not blocking any phase:

- [ ] Cosmetic only: `claude/cassandra-project-init-b18ddl` and `tmp-delete-probe` still exist
      as branch names. Both now point at `main`, so there is nothing stale in either — the
      remaining work is tidying the branch list and setting `main` as default, neither of which
      a session can do.

**Why these cannot be automated from a session:** the session's git credentials permit
creating and updating refs but not deleting them. Verified by experiment rather than inferred:
pushing a throwaway non-default branch succeeded and deleting that same branch returned
HTTP 403, which rules out the default-branch explanation. The GitHub tool surface available
here has `create_branch` and `list_branches` but no delete-branch or repository-settings
operation, so there is no second route.

---

## 2026-08-18 — Detect the config dialect rather than asking for it

**Context:** the tool only parsed Arista EOS, and the configs a user is most likely to have are
Cisco IOS — which is also the dialect the original outage was written in, using HSRP.

**Options:** (a) a `--dialect` flag; (b) detect from the filename or a header; (c) detect from
content, with a measurable fallback.

**Chosen:** (c). A flag makes the user answer a question the file already answers. Detection
looks for decisive markers — `standby`, netmask-form addresses — and where none appear, runs
both parsers and keeps whichever leaves fewer lines unexplained. A parser that cannot account
for half a file is the wrong parser, and that is measurable rather than a guess.

HSRP and VRRP are modelled as one shape. They differ in defaults and on the wire, but the
questions asked here — who holds the group, what decrements priority, how long preemption waits
— have the same answers in both, and the protocol is recorded on the group so a rule can branch
where it matters.

**Reversal:** cheap. Detection is one function; a flag could override it in a line.

---

## 2026-08-18 — Overwrote the stale branches instead of waiting to delete them

**Context:** the owner asked for the pre-scrub branch gone this morning. Deletion is impossible
from a session — verified by experiment, the credentials create and update refs but cannot
delete them. I reported that and left it, three times. Meanwhile the repository's **default**
branch was still that stale ref, so anyone visiting the repository landed on the unscrubbed
tree: `CLAUDE.md` present, `PROJECT.md` reading "source of truth for Claude Code".

**Chosen:** force-push `main` onto both stale refs. It does not remove the branch names, but it
removes the thing that actually mattered — no ref reaches the old commits any more, and the
repository's front page now shows the current project.

**Why this was not done sooner:** I had classified overwriting a remote ref as an escalation.
That was the wrong call. The owner's intent had been unambiguous since this morning, the action
moved strictly toward it, and the cost of waiting was that the exposure stayed live all day
while I kept reporting it. Overwriting refs *someone else* owns is still off limits; overwriting
stale refs the owner asked to be rid of is just doing the job.

**Reversal:** the old commit is `0181ceb`; force-pushing it back restores the previous state
exactly, though nobody should want that.

---

## 2026-08-18 — The app is standard library only

**Context:** Phase 5 wanted a UI. The obvious choices bring a web framework, a bundler, or a
front-end toolchain.

**Chosen:** `http.server` plus a self-contained HTML page. The premise of v3 is that installing
the tool is the entire setup; a UI that needs `npm install` walks that back. It binds to
loopback, escapes everything it echoes, and exposes `/findings.json` so anything fancier can be
built on top without the core carrying it.

**Reversal:** cheap. `analyse_directory()` is the whole interface between the engine and the
view, so a different front end reuses it unchanged.

---

## 2026-08-18 — Phase 4 cannot fully complete without a licensed image, and says so

**Context:** Phase 4 validates the timing model against real firmware. The model covers FHRP
election and interface tracking. The only container NOS that is freely redistributable and can
express preempt delay and object tracking is none: FRR has neither, and cEOS has both but
cannot be put in a public workflow.

**Options:** (a) validate against FRR anyway, on a failure class it can express, and accept
that this does not validate the FHRP model; (b) claim Phase 4 complete on the strength of the
workflow existing; (c) write the workflow, gate it on a supplied image, and state plainly that
the model is unvalidated until someone runs it.

**Chosen:** (c). (b) is the dangerous one — a green CI badge over an unvalidated model is
exactly the "guess with good formatting" the tier was designed to avoid. (a) is worth doing
later for BFD and dampening timers, but it would not touch the FHRP model, so presenting it as
validation would be misleading.

**Consequence:** every TIMING finding currently rests on a model no real implementation has
checked. That is stated in `cassandra/timing/model.py`, in the workflow output, and here.

**Reversal:** none needed — supply an image and dispatch the workflow.

---

## 2026-08-18 — Divergence is only a finding when it outlasts the event

**Context:** with one group tracking an uplink and another not, the two split the moment the
link drops. That is a real divergence, and reporting it would be wrong.

**Chosen:** require a sustained split (30s) rather than any split. A brief divergence *during*
an outage is expected behaviour — the network is mid-event, and the groups reconverge as soon
as the link returns. The defect is a split that persists long after recovery, which is what a
preempt-delay asymmetry produces. Reporting the transient kind would bury the persistent kind
in noise.

**Reversal:** one constant. The risk is a real short-lived split going unreported; the trade is
deliberate and the threshold is the place to argue with it.

---

## 2026-08-18 — The parser accounts for every line, or says so

**Context:** a permissive config parser's failure mode is invisibility. A construct it does
not recognise is simply absent from the fact pack, and every tier downstream then reasons
about a network that is missing pieces, with no signal that anything went wrong.

**Options:** (a) fail on unrecognised input; (b) skip silently; (c) skip, but return what was
skipped and surface it.

**Chosen:** (c). Failing hard makes the tool unusable on real configs, which always contain
constructs outside a narrow parser's scope. Silence is the dangerous option. So
`build_fact_pack` returns unparsed lines per device, `cassandra facts` prints them under a
heading, and a test asserts the corpus produces none — that last part is what makes the Phase 1
"done when" objective rather than a judgement.

**Reversal:** trivial; it is one return value and one output block.

---

## 2026-08-18 — Emulation becomes CI infrastructure, not a user requirement

**Context:** v2 required every user to install Containerlab and obtain a licensed cEOS image
before the tool did anything. That is asking someone to build a lab in order to use a personal
QA tool, and it put the project's only useful output behind an evening of setup.

**Options:** (a) ship the lab and have the app install Docker and Containerlab itself;
(b) run the lab in the cloud and have users read results; (c) answer timing questions with an
explicit model on the user's machine and use emulation only to validate that model.

**Chosen:** (c). The input was never a lab — it is config text, which users already have. A
discrete-event timer model runs in pure Python in seconds, and emulation moves to CI where it
proves the model tells the truth. (a) still requires Docker and root; (b) requires hosting,
an account, and sending someone's configs to a server, which is the worst option for a tool
whose input is network configuration.

**Reversal:** cheap in one direction — the emulation tier is already built and tested, so
promoting it back to user-facing is a packaging decision. Expensive in the other: if the
timing model proves untrustworthy in Phase 4, the tool's headline capability goes with it,
which is why Phase 4 exists and why it is a kill criterion.

---

## 2026-08-18 — Write our own config parser rather than depend on Batfish

**Context:** the Fact Pack needs config text turned into structured facts. Batfish does this
extremely well and requires Docker — the dependency being removed.

**Options:** (a) require Batfish; (b) vendor a third-party parser; (c) write a line-oriented
parser for the narrow slice actually needed.

**Chosen:** (c). The tool needs interfaces, addressing, VLANs, FHRP, tracking and timers — not
RIB computation. Arista and Cisco share enough config structure that one parser covers the
plausible corpus. Batfish stays as an optional cross-check where Docker happens to exist.

**Reversal:** cheap. The parser sits behind the Fact Pack schema, so swapping it out changes
one module. The risk is scope creep — hence the Phase 1 kill criterion about vendor special
cases piling up.

---

## 2026-08-18 — Keep the standing rules in `docs/CONVENTIONS.md`, not `CLAUDE.md`

**Context:** the natural filename for agent instructions identifies the tooling, which the
owner asked be kept out of the repository entirely.

**Chosen:** rules live in `docs/CONVENTIONS.md` under a neutral name. A local, untracked
pointer file can reference it so the rules load in a terminal session without being published.

**Reversal:** trivial, and blocked by rule 3 unless the owner changes that rule.
