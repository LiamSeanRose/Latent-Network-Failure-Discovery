#!/usr/bin/env bash
# Phase 0 scenario runner.
#
#   ./run.sh baseline   deploy, settle, confirm healthy, leave running
#   ./run.sh trigger    run the flap sequence and collect
#   ./run.sh control    run the same observation window with NO flap
#   ./run.sh destroy    tear down
#
# Confirmation (PROJECT.md §2.5) needs the observable in >=2 of 3 `trigger` runs
# AND absent in `control`. One green run is not a result.
set -euo pipefail

LAB=site14-vrrp-lockstep
CLAB="${CLAB:-containerlab}"  # set CLAB="sudo containerlab" if your install needs root
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${HERE}/runs/$(date +%Y%m%dT%H%M%S)"

FLAPS=3
FLAP_DOWN_S=10
FLAP_UP_S=20
OBSERVE_S=120
SETTLE_S=90

cli() { docker exec "clab-${LAB}-$1" Cli -p 15 -c "$2"; }

conf() {
  local node=$1 iface=$2 state=$3
  # One -c with embedded newlines: cEOS Cli does not reliably stack -c flags.
  docker exec "clab-${LAB}-${node}" Cli -p 15 \
    -c "$(printf 'configure\ninterface %s\n%s\n' "${iface}" "${state}")"
}

sample_vrrp() {
  local out=$1
  while true; do
    printf '=== %s ===\n' "$(date +%s)" >>"$out"
    cli agg-a "show vrrp" >>"$out" 2>&1 || true
    cli agg-b "show vrrp" >>"$out" 2>&1 || true
    sleep 2
  done
}

case "${1:-}" in
  baseline)
    ${CLAB} deploy -t "${HERE}/topology.clab.yml"
    echo "settling ${SETTLE_S}s for OSPF and VRRP..."
    sleep "${SETTLE_S}"
    cli agg-a "show vrrp"
    cli agg-b "show vrrp"
    docker exec "clab-${LAB}-client1" ping -c 5 10.255.0.1
    ;;

  trigger|control)
    mkdir -p "${OUT}"
    sample_vrrp "${OUT}/vrrp.log" &
    SAMPLER=$!
    trap 'kill ${SAMPLER} 2>/dev/null || true' EXIT

    # -i 1 rather than sub-second: alpine's ping is busybox and fractional
    # intervals are not portable. This caps loss-window resolution at 1s, which
    # is coarse against a ~3s VRRP failover. For finer resolution, `apk add
    # iputils` in the client node and drop to -i 0.2.
    docker exec "clab-${LAB}-client1" \
      ping -i 1 -w $((OBSERVE_S + FLAPS * (FLAP_DOWN_S + FLAP_UP_S))) 10.255.0.1 \
      >"${OUT}/probe.log" 2>&1 &
    PROBE=$!

    if [[ "$1" == "trigger" ]]; then
      for i in $(seq 1 "${FLAPS}"); do
        echo "flap ${i}/${FLAPS}: down"
        conf agg-a Ethernet1 "shutdown"
        sleep "${FLAP_DOWN_S}"
        echo "flap ${i}/${FLAPS}: up"
        conf agg-a Ethernet1 "no shutdown"
        sleep "${FLAP_UP_S}"
      done
    else
      echo "control run: no trigger"
      sleep $((FLAPS * (FLAP_DOWN_S + FLAP_UP_S)))
    fi

    echo "observing ${OBSERVE_S}s..."
    sleep "${OBSERVE_S}"
    wait "${PROBE}" 2>/dev/null || true
    kill "${SAMPLER}" 2>/dev/null || true

    echo "--- final placement ---" | tee -a "${OUT}/summary.txt"
    cli agg-a "show vrrp" | tee -a "${OUT}/summary.txt"
    cli agg-b "show vrrp" | tee -a "${OUT}/summary.txt"
    echo "artifacts in ${OUT}"
    ;;

  destroy)
    ${CLAB} destroy -t "${HERE}/topology.clab.yml" --cleanup
    ;;

  *)
    sed -n '2,12p' "${BASH_SOURCE[0]}"
    exit 1
    ;;
esac
