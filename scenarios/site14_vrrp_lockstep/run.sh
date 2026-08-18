#!/usr/bin/env bash
# Phase 0 scenario runner.
#
#   ./run.sh baseline    deploy, settle, confirm healthy, leave running
#   ./run.sh trigger     one flap sequence + observation
#   ./run.sh control     same window, NO flap (must not show the observable)
#   ./run.sh perturb     flap intervals randomised ±20% (knife-edge check)
#   ./run.sh suite       the full §2.5 control set: 3x trigger, 1x control,
#                        1x perturb, each on a freshly deployed lab (~30 min)
#   ./run.sh destroy     tear down
#
# Confirmation (PROJECT.md §2.5) requires the observable in >=2 of 3 trigger runs
# AND absent in control. One green run is not a result, which is why `suite`
# exists — the discipline belongs in the tool, not in a README nobody rereads.
set -euo pipefail

LAB=site14-vrrp-lockstep
CLAB="${CLAB:-containerlab}"   # export CLAB="sudo containerlab" if yours needs root
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

# Sample both text and JSON. The text is for reading; the JSON is what a
# transition counter should be built on, since `show vrrp` text formatting is not
# a stable interface and this script was written without a lab to check it
# against. Records are delimited so they can be split without jq.
sample_vrrp() {
  local dir=$1 node
  while true; do
    for node in agg-a agg-b; do
      printf '### %s %s\n' "$(date +%s)" "${node}" >>"${dir}/vrrp.log"
      cli "${node}" "show vrrp" >>"${dir}/vrrp.log" 2>&1 || true
      printf '### %s %s\n' "$(date +%s)" "${node}" >>"${dir}/vrrp.json.log"
      cli "${node}" "show vrrp | json" >>"${dir}/vrrp.json.log" 2>&1 || true
    done
    sleep 2
  done
}

# ±20% of a base interval, per §2.5's knife-edge control.
jitter() {
  local base=$1
  echo $(( base * (80 + RANDOM % 41) / 100 ))
}

deploy() {
  ${CLAB} deploy -t "${HERE}/topology.clab.yml"
  echo "settling ${SETTLE_S}s for OSPF and VRRP..."
  sleep "${SETTLE_S}"
}

destroy() { ${CLAB} destroy -t "${HERE}/topology.clab.yml" --cleanup; }

# mode: trigger | control | perturb
observe() {
  local mode=$1
  local out stamp
  stamp=$(date +%Y%m%dT%H%M%S)
  out="${HERE}/runs/${stamp}-${mode}"
  mkdir -p "${out}"
  echo "${mode}" >"${out}/mode"

  sample_vrrp "${out}" &
  local sampler=$!
  # shellcheck disable=SC2064  # expand sampler pid now, not at trap time
  trap "kill ${sampler} 2>/dev/null || true" EXIT

  # -i 1 rather than sub-second: alpine ships busybox ping and fractional
  # intervals are not portable. Caps loss resolution at 1s against a ~3s
  # failover; `apk add iputils` in the client node to do better.
  docker exec "clab-${LAB}-client1" \
    ping -i 1 -w $((OBSERVE_S + FLAPS * (FLAP_DOWN_S + FLAP_UP_S))) 10.255.0.1 \
    >"${out}/probe.log" 2>&1 &
  local probe=$!

  local down="${FLAP_DOWN_S}" up="${FLAP_UP_S}" i
  for i in $(seq 1 "${FLAPS}"); do
    case "${mode}" in
      control)
        echo "control: no trigger (${i}/${FLAPS})"
        sleep $((FLAP_DOWN_S + FLAP_UP_S))
        continue
        ;;
      perturb)
        down=$(jitter "${FLAP_DOWN_S}")
        up=$(jitter "${FLAP_UP_S}")
        ;;
    esac
    printf 'flap %d/%d: down %ss, up %ss\n' "${i}" "${FLAPS}" "${down}" "${up}" \
      | tee -a "${out}/events.log"
    conf agg-a Ethernet1 "shutdown"
    sleep "${down}"
    conf agg-a Ethernet1 "no shutdown"
    sleep "${up}"
  done

  echo "observing ${OBSERVE_S}s..."
  sleep "${OBSERVE_S}"
  wait "${probe}" 2>/dev/null || true
  kill "${sampler}" 2>/dev/null || true
  trap - EXIT

  # Deliberately not a verdict. The criteria are evaluated over the sampled
  # timeline (group 14 transitioning >=4 times, >=60s where group 24 and group 34
  # disagree), and the network has re-converged by now — the end state looks
  # healthy on a run that worked exactly as designed.
  {
    echo "--- end state (NOT the criterion; see vrrp.log for the timeline) ---"
    cli agg-a "show vrrp" || true
    cli agg-b "show vrrp" || true
  } >>"${out}/end-state.txt" 2>&1
  echo "artifacts in ${out}"
}

case "${1:-}" in
  baseline)
    deploy
    cli agg-a "show vrrp"
    cli agg-b "show vrrp"
    docker exec "clab-${LAB}-client1" ping -c 5 10.255.0.1
    ;;
  trigger|control|perturb)
    observe "$1"
    ;;
  suite)
    for mode in trigger trigger trigger control perturb; do
      echo "=== ${mode} ==="
      destroy 2>/dev/null || true
      deploy
      observe "${mode}"
    done
    echo "suite complete; compare runs/ — >=2 of 3 triggers positive, control negative"
    ;;
  destroy)
    destroy
    ;;
  *)
    sed -n '2,15p' "${BASH_SOURCE[0]}"
    exit 1
    ;;
esac
