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

    # 1. Parse cleanly. Silent parse failure is the failure mode that would fake
    #    this entire result, so it is checked before anything else.
    parse = bf.q.initIssues().answer().frame()
    if not parse.empty:
        fail("parse", parse)
    print("ok  [parse]      no init issues")

    # 2. Batfish modelled the VRRP groups. If this is empty, a healthy verdict
    #    below means Batfish ignored the redundancy, not that the design is sound.
    props = bf.q.interfaceProperties(properties="VRRP_Groups").answer().frame()
    seen = {
        node: groups
        for node, groups in zip(props["Interface"], props["VRRP_Groups"], strict=False)
        if groups
    }
    if not seen:
        fail("vrrp-modelled", "Batfish reported no VRRP groups on any interface")
    print(f"ok  [vrrp]       groups modelled on {len(seen)} interfaces")

    # 3. Only now is the reachability verdict worth reading.
    traceroute = (
        bf.q.traceroute(
            startLocation="client1",
            headers={"dstIps": "10.255.0.1"},
        )
        .answer()
        .frame()
    )
    print("ok  [reach]      traceroute answered")
    print(traceroute)

    print(
        "\nPhase 0 asserts this run is HEALTHY while the emulated lab is not.\n"
        "If Batfish reports the failure here, PROJECT.md §4.3 says the escalation\n"
        "boundary is wrong and the project stops. That is a real possible outcome."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
