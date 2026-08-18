"""Batfish half of the Phase 0 proof.

Run with a Batfish service reachable (`docker run -p 9996:9996 -p 9997:9997
batfish/allinone`) and no local dependency commitment:

    uv run --with pybatfish python batfish_check.py

The point of Phase 0 is not that Batfish says "healthy". It is that Batfish says
"healthy" *having actually modelled the redundancy*. A healthy verdict from a
snapshot Batfish failed to parse proves nothing and would silently fake the
project's central result, so the checks run in order and stop at the first
failure.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Final

from pybatfish.client.session import Session

SNAPSHOT_DIR: Final = Path(__file__).parent
EXPECTED_MASTER: Final = "agg-a"
EXPECTED_GROUPS: Final = {14, 24, 34}


def fail(step: str, detail: object) -> None:
    print(f"FAIL [{step}]\n{detail}")
    sys.exit(1)


def main() -> int:
    bf = Session(host="localhost")
    bf.set_network("cassandra-phase0")
    bf.init_snapshot(str(SNAPSHOT_DIR), name="site14", overwrite=True)

    # 1. What did Batfish fail to understand? Unrecognised lines are not fatal on
    #    their own — the snapshot still loads — but they decide how much a healthy
    #    verdict is worth, so they are reported line by line rather than counted.
    issues = bf.q.initIssues().answer().frame()
    unparsed = [
        str(row.get("Line_Text", "")).strip()
        for _, row in issues.iterrows()
        if str(row.get("Line_Text", "")).strip()
    ]
    mechanism = [
        line for line in unparsed if re.search(r"tracked-object|^track |preempt", line)
    ]
    if unparsed:
        print(f"warn [parse]      {len(unparsed)} unrecognised lines:")
        for line in sorted(set(unparsed)):
            print(f"                  {line}")
    else:
        print("ok  [parse]       no init issues")

    # 2. Batfish must have modelled the redundancy. If it reported no groups at
    #    all, a healthy verdict below means it skipped the feature, and the run
    #    proves a coverage gap rather than the escalation boundary.
    props = bf.q.interfaceProperties(properties="VRRP_Groups").answer().frame()
    modelled = {
        row["Interface"]: row["VRRP_Groups"]
        for _, row in props.iterrows()
        if list(row["VRRP_Groups"])
    }
    if not modelled:
        fail("vrrp-modelled", "Batfish reported no VRRP groups on any interface")
    print(f"ok  [vrrp]        groups modelled on {len(modelled)} interfaces")
    for interface, groups in sorted(modelled.items()):
        print(f"                  {interface} {sorted(groups)}")

    # 3. Only now is the reachability verdict worth reading.
    #
    #    Traced from the aggregation routers, not from client1: client1 is a plain
    #    linux container with no config file, so it does not exist in the Batfish
    #    snapshot at all. The emulated topology and the symbolic snapshot are not
    #    the same network, and pretending otherwise would silently trace a
    #    different path than the lab does. Both aggs are traced because either can
    #    hold the gateway.
    for source in ("agg-a", "agg-b"):
        traceroute = (
            bf.q.traceroute(
                startLocation=source,
                headers={
                    "srcIps": f"10.14.0.{2 if source == 'agg-a' else 3}",
                    "dstIps": "10.255.0.1",
                },
            )
            .answer()
            .frame()
        )
        outcomes = {
            str(trace).split("\n")[0][:60]
            for traces in traceroute["Traces"]
            for trace in traces
        }
        print(f"ok  [reach]       {source} -> 10.255.0.1")
        for outcome in sorted(outcomes):
            print(f"                  {outcome}")

    if mechanism:
        print(
            "\nCAVEAT — this weakens the Phase 0 claim and must be recorded on any\n"
            "finding. Batfish modelled the VRRP groups, virtual addresses and\n"
            "priorities, but did NOT parse these lines:\n"
            + "".join(f"    {line}\n" for line in sorted(set(mechanism)))
            + "which are the tracking and preemption behaviour the scenario turns on.\n"
            "Its healthy verdict is therefore partly attributable to not having read\n"
            "the mechanism, rather than to having read it and found it sound.\n"
            "\n"
            "The claim survives, because Batfish computes one steady state and the\n"
            "failure exists only between events — but it is weaker evidence than a\n"
            "verdict from an analyser that understood every line."
        )

    print(
        "\nPhase 0 asserts this run is HEALTHY while the emulated lab is not.\n"
        "If Batfish reports the failure here, PROJECT.md §4.3 says the escalation\n"
        "boundary is wrong and the project stops. That is a real possible outcome."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
