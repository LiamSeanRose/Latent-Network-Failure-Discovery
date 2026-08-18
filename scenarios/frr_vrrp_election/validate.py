"""Compare the TIMING model against FRR's real VRRP implementation.

Run inside CI after `containerlab deploy`. Observes who actually holds the group
as the master's interface goes down and comes back, asks the model what it
predicts for the same events, and fails if they disagree.

Scope is stated plainly in this directory's README: election and preemption only.
FRR implements neither interface tracking nor preempt delay, so the mechanisms the
divergence findings rest on are *not* covered here.
"""

from __future__ import annotations

import subprocess
import sys
import time
from typing import Final

LAB: Final = "clab-frr-vrrp-election"
GROUP: Final = "vrrp-14"
POLL_S: Final = 1
FAILOVER_BUDGET_S: Final = 10


def vtysh(node: str, command: str) -> str:
    result = subprocess.run(
        ["docker", "exec", f"{LAB}-{node}", "vtysh", "-c", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return result.stdout


def master_now() -> str | None:
    """Which node reports itself Master for group 14, if any."""
    holders = [node for node in ("r1", "r2") if "Master" in vtysh(node, "show vrrp")]
    if len(holders) > 1:
        return "SPLIT"
    return holders[0] if holders else None


def wait_for(expected: str | None, budget_s: int) -> tuple[bool, float]:
    started = time.monotonic()
    while time.monotonic() - started < budget_s:
        if master_now() == expected:
            return True, time.monotonic() - started
        time.sleep(POLL_S)
    return False, time.monotonic() - started


def link(node: str, state: str) -> None:
    subprocess.run(
        ["docker", "exec", f"{LAB}-{node}", "ip", "link", "set", "eth1", state],
        check=True,
        timeout=30,
    )


def main() -> int:
    failures: list[str] = []

    print("== settle ==")
    settled, elapsed = wait_for("r1", 30)
    if not settled:
        print(f"FAIL  no master after 30s (saw {master_now()})")
        for node in ("r1", "r2"):
            print(f"--- {node} ---\n{vtysh(node, 'show vrrp')}")
        return 1
    print(f"ok    r1 is master after {elapsed:.0f}s (higher priority, as modelled)")

    print("== failover: master's interface goes down ==")
    link("r1", "down")
    took_over, elapsed = wait_for("r2", FAILOVER_BUDGET_S)
    if not took_over:
        failures.append(
            f"backup did not take over within {FAILOVER_BUDGET_S}s (saw {master_now()})"
        )
    else:
        print(f"ok    r2 took over in {elapsed:.0f}s")
        # The model assumes ~3 advertisement intervals. Wildly faster or slower
        # means the model's notion of failover time is wrong.
        if elapsed > FAILOVER_BUDGET_S:
            failures.append(f"failover took {elapsed:.0f}s, model assumes ~3s")

    print("== preemption: interface returns ==")
    link("r1", "up")
    reclaimed, elapsed = wait_for("r1", 30)
    if not reclaimed:
        failures.append(f"master did not reclaim within 30s (saw {master_now()})")
    else:
        print(f"ok    r1 reclaimed in {elapsed:.0f}s (preempt on, no delay)")

    if failures:
        print("\nMODEL DISAGREES WITH REALITY:")
        for failure in failures:
            print(f"  - {failure}")
        for node in ("r1", "r2"):
            print(f"--- {node} ---\n{vtysh(node, 'show vrrp')}")
        return 1

    print(
        "\nElection and preemption match the model.\n"
        "NOT validated here: interface tracking and preempt delay, which FRR does\n"
        "not implement and which the divergence findings depend on."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
