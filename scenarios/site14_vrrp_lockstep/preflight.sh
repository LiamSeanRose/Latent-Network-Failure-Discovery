#!/usr/bin/env bash
# Check this machine can run the scenario, before you spend an evening finding
# out it cannot. Read-only: probes, reports, changes nothing.
#
#   ./preflight.sh
#
# Exits 0 if everything needed is present, 1 if something blocking is missing.
set -uo pipefail

ok=0
fail=0
warn=0

pass() { printf '  \033[32mok\033[0m    %s\n' "$1"; ok=$((ok + 1)); }
bad()  { printf '  \033[31mMISS\033[0m  %s\n' "$1"; fail=$((fail + 1)); }
note() { printf '  \033[33mnote\033[0m  %s\n' "$1"; warn=$((warn + 1)); }
info() { printf '        %s\n' "$1"; }

echo "== emulation =="

if command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then
    pass "docker daemon reachable"
  else
    bad "docker is installed but the daemon is not reachable (try: sudo systemctl start docker)"
  fi
else
  bad "docker not installed"
fi

if command -v containerlab >/dev/null 2>&1; then
  pass "containerlab $(containerlab version 2>/dev/null | awk '/version:/ {print $2; exit}')"
  if [[ $(id -u) -ne 0 ]] && ! docker info >/dev/null 2>&1; then
    note "containerlab usually needs root; run with CLAB=\"sudo containerlab\""
  fi
else
  bad "containerlab not installed (https://containerlab.dev/install/)"
fi

# cEOS image, and the EOS version — which decides the VRRP config syntax.
ceos=$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -iE 'ceos' | head -5)
if [[ -n "${ceos}" ]]; then
  pass "cEOS image present"
  printf '%s\n' "${ceos}" | while read -r img; do info "${img}"; done
  first=$(printf '%s\n' "${ceos}" | head -1)
  info ""
  info "export CEOS_IMAGE=\"${first}\"    # the topology reads this"

  # EOS >= 4.21 uses `vrrp <id> ipv4 ...` / `priority-level`; older uses
  # `vrrp <id> ip ...` / `priority`. The configs are written for the newer form.
  version=$(printf '%s' "${first}" | grep -oE '4\.[0-9]+' | head -1)
  if [[ -n "${version}" ]]; then
    minor=${version#4.}
    if [[ "${minor}" -ge 21 ]]; then
      pass "EOS ${version} — configs match this VRRP syntax, no edit needed"
    else
      note "EOS ${version} predates the current VRRP syntax. The configs use"
      info "\`vrrp 14 ipv4 ...\` / \`priority-level\`; yours wants \`vrrp 14 ip ...\` / \`priority\`."
    fi
  else
    note "could not read an EOS version from the tag — confirm with:"
    info "docker run --rm ${first} Cli -c 'show version' 2>/dev/null | head -3"
  fi
else
  bad "no cEOS image found in \`docker images\` (needs a free Arista account + docker import)"
fi

echo
echo "== symbolic =="

if docker image inspect batfish/allinone >/dev/null 2>&1; then
  pass "batfish/allinone image present"
else
  note "batfish image not pulled yet — needed only for the second half of the proof:"
  info "docker pull batfish/allinone"
fi

echo
echo "== host capacity =="

# Four cEOS nodes at 2Gb each, plus overhead.
mem_gb=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo 2>/dev/null)
if [[ -n "${mem_gb}" ]]; then
  if [[ "${mem_gb}" -ge 10 ]]; then
    pass "${mem_gb}GB RAM (scenario reserves 8GB across four cEOS nodes)"
  else
    note "${mem_gb}GB RAM — the scenario reserves 8GB for cEOS alone; expect swapping,"
    info "and swapping invalidates every timing measurement this scenario makes."
  fi
fi

cores=$(nproc 2>/dev/null)
if [[ -n "${cores}" ]]; then
  if [[ "${cores}" -ge 4 ]]; then
    pass "${cores} CPU cores"
  else
    note "${cores} cores — scheduling jitter may exceed the timer margins under test."
    info "Measure observed VRRP advert intervals against configured before trusting a result."
  fi
fi

echo
if [[ "${fail}" -gt 0 ]]; then
  printf 'BLOCKED: %d missing, %d ok, %d notes\n' "${fail}" "${ok}" "${warn}"
  exit 1
fi
printf 'READY: %d ok, %d notes\n' "${ok}" "${warn}"
echo "next: ./run.sh baseline"
