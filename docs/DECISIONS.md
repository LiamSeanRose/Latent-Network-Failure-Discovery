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
- [ ] **Phase 4 — CI emulation validation.** Disagreement with the model fails the build.
      **Current phase.**
- [ ] **Phase 5 — The app.**

Carried over, owner-only, not blocking any phase:

- [ ] Delete `claude/cassandra-project-init-b18ddl` on GitHub (Settings → General → default
      branch to `main` first, since GitHub will not delete a default branch). It still holds
      pre-scrub history.
- [ ] Delete `tmp-delete-probe` — a throwaway ref created while diagnosing why deletion
      fails. It points at `main`, so it is clutter rather than exposure.

**Why these cannot be automated from a session:** the session's git credentials permit
creating and updating refs but not deleting them. Verified by experiment rather than inferred:
pushing a throwaway non-default branch succeeded and deleting that same branch returned
HTTP 403, which rules out the default-branch explanation. The GitHub tool surface available
here has `create_branch` and `list_branches` but no delete-branch or repository-settings
operation, so there is no second route.

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
