# frr_vrrp_election — partial validation of the TIMING model

> **Status: not working yet.** Two CI runs have failed during lab setup rather
> than during the comparison. FRR's vrrpd needs a macvlan device with the RFC
> virtual MAC on the parent interface, and it is not coming up inside a
> containerlab node the way FRR's documentation implies. The validator itself has
> therefore never run. Workflow is manual-dispatch only until it does.

PROJECT.md §4.2 Phase 4 asks whether the timing model agrees with real protocol
implementations. The full answer needs Arista cEOS, which cannot be redistributed
in a public workflow. This is the part that can be answered with free images.

**What it validates:** priority-based election, failover when a master's VRRP
interface goes down, and preemption returning the group afterwards — against
FRR's real VRRP implementation.

**What it does not validate, and this is the important half:** interface tracking
and preempt delay. FRR implements neither (`docs/emulation-fidelity.md`), and they
are precisely the mechanisms the divergence findings turn on. A green run here
means the model's foundation is sound, not that its findings are.

So this narrows the unvalidated surface. It does not close it.

## How it compares

The model is fed an EOS config. The lab runs FRR configured to the same intent.
The comparison is on *behaviour over time* — who holds the group at each moment —
not on config text, since the two dialects express the same thing differently.

A disagreement fails the job. That is the entire point: a model that cannot be
contradicted is not being tested.
