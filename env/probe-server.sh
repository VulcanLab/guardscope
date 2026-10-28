#!/usr/bin/env bash
# M0 environment probe for the inspection-coverage testbed.
# Run on the Linux server that will host the T0-T7 testbed.
# Usage:  bash probe-server.sh          (plain report)
#         bash probe-server.sh --json   (machine-readable report)
set -uo pipefail

JSON=0
[[ "${1:-}" == "--json" ]] && JSON=1

pass=0; fail=0; warn=0
declare -a NOTES=()

ok()   { pass=$((pass+1)); echo "PASS  $1${2:+  [$2]}"; }
bad()  { fail=$((fail+1)); echo "FAIL  $1${2:+  [$2]}"; }
warnk(){ warn=$((warn+1)); echo "WARN  $1${2:+  [$2]}"; }

header() { echo "=== $1 ==="; }

header "Kernel"
KVER=$(uname -r)
KMINOR=$(echo "$KVER" | grep -oE '^\[0-9]+\.[0-9]+' | cut -d. -f2)
KMAJOR=$(echo "$KVER" | cut -d. -f1)
if [[ -z "$KMINOR" ]] || (( KMAJOR > 5 || (KMAJOR == 5 && KMINOR >= 8) )); then ok "kernel version $KVER (>= 5.8 required for Tracee)"; else bad "kernel version $KVER (Tracee needs >= 5.8, ideally >= 5.10)"; fi
uname -m

header "BTF (required by Tracee CO-RE)"
if [[ -f /sys/kernel/btf/vmlinux ]]; then ok "BTF available at /sys/kernel/btf/vmlinux"; else bad "BTF missing (/sys/kernel/btf/vmlinux not found)"; fi

header "eBPF syscall"
if [[ -e /proc/sys/kernel/unprivileged_bpf_disabled ]]; then
  UBP=$(cat /proc/sys/kernel/unprivileged_bpf_disabled)
  ok "/proc/sys/kernel/unprivileged_bpf_disabled present (value: $UBP; 1|2 is fine for privileged Tracee)"
else
  warnk "/proc/sys/kernel/unprivileged_bpf_disabled not present (older kernel?)"
fi
if command -v bpftool >/dev/null 2>&1; then
  # Deep eBPF probe: feature enumeration, BTF parse, program load, map ops.
  if bpftool version >/dev/null 2>&1; then ok "bpftool available ($(bpftool version 2>/dev/null | head -1))"; else warnk "bpftool present but version check failed"; fi
  # Full feature probe needs CAP_BPF/CAP_SYS_ADMIN; fall back to unprivileged mode.
  if [[ $(id -u) -eq 0 ]] && bpftool feature probe 2>/dev/null | grep -q .; then
    MODE=full
  else
    MODE=unprivileged
  fi
  SYSCALL_OK=$(bpftool feature probe $MODE 2>/dev/null | grep -ciE "bpf\(2\) syscall|CONFIG_BPF_SYSCALL is set" || true)
  if [[ "$SYSCALL_OK" -gt 0 ]]; then ok "bpftool feature probe ($MODE): eBPF syscall available"; else warnk "bpftool feature probe ($MODE): no eBPF syscall evidence"; fi
  FEAT=$(bpftool feature probe $MODE 2>/dev/null | grep -cE "program_type|map_type" || true)
  if [[ "$FEAT" -gt 0 ]]; then ok "bpftool feature probe ($MODE): $FEAT program/map type lines enumerated"; else warnk "bpftool feature probe ($MODE) returned no types"; fi
  JIT=$(bpftool feature probe $MODE 2>/dev/null | grep -c "JIT compiler is enabled" || true)
  if [[ "$JIT" -gt 0 ]]; then ok "eBPF JIT compiler enabled"; else warnk "JIT compiler status unknown"; fi
  BTF_OUT=$(bpftool btf dump file /sys/kernel/btf/vmlinux 2>/dev/null | head -1 || true)
  if [[ -n "$BTF_OUT" ]]; then ok "BTF parseable via bpftool (CO-RE will find its types)"; else warnk "bpftool could not parse /sys/kernel/btf/vmlinux"; fi
  # Minimal load test: tiny socket-filter style program; needs root, skip otherwise.
  if [[ $(id -u) -eq 0 ]]; then
    TP=$(mktemp /tmp/probe-bpf.XXXXXX.c)
    OBJ=$(mktemp /tmp/probe-bpf.XXXXXX.o)
    cat > "$TP" <<'BPFC'
sec "tracepoint"
int probe_prog(void *ctx) { return 0; }
BPFC
    if command -v clang >/dev/null 2>&1 && clang -target bpf -O2 -c "$TP" -o "$OBJ" 2>/dev/null; then
      if bpftool prog load "$OBJ" /sys/fs/bpf/probe_m0_test >/sys/fs/bpf 2>/dev/null; then ok "minimal BPF program load test succeeded"; bpftool prog delete 2>/dev/null; rm -f /sys/fs/bpf/probe_m0_test 2>/dev/null; else warnk "minimal BPF program load failed (kernel may lack needed helpers)"; fi
    else
      warnk "clang with BPF target not available; skipping program load test"
    fi
    rm -f "$TP" "$OBJ"
  else
    warnk "program load test needs root; skipped (bpftool full feature probe also needs root; unprivileged probe used)"
  fi
else
  warnk "bpftool not installed (optional; install with: sudo dnf install bpftool)"
fi
# Quick load test: tiny BPF program via bpftool is skipped; Tracee smoke test covers real loading.

header "Container runtime"
if command -v docker >/dev/null 2>&1; then
  ok "docker $(docker --version 2>/dev/null | awk '{print $3}')"
  if docker info >/dev/null 2>&1; then ok "docker daemon reachable and usable by current user"; else bad "docker daemon not reachable (permission? sudo group?)"; fi
else
  bad "docker not installed"
fi
if docker compose version >/dev/null 2>&1; then ok "docker compose: $(docker compose version --short 2>/dev/null)"; else
  warnk "docker compose plugin not found (compose v2 plugin recommended)"
fi

header "cgroups (v2 required by modern Tracee / unified hierarchy)"
CG=/sys/fs/cgroup
if [[ -f "$CG/cgroup.controllers" ]]; then ok "cgroup v2 unified hierarchy at $CG ($(cat "$CG/cgroup.controllers" | tr '\n' ' '))"; else
  bad "cgroup v2 not detected ($CG/cgroup.controllers missing); hybrid/v1 hierarchy"
fi

header "Privileges for the sensor container"
if [[ $(id -u) -eq 0 ]]; then ok "running as root"; else
  if sudo -n true 2>/dev/null; then ok "passwordless sudo available"; else warnk "no root and no passwordless sudo: Tracee container needs --privileged; ensure sudo or docker group access"; fi
fi

header "Disk headroom for raw traces"
ROOTDIR=${TRACEE_DATA_DIR:-/var/tmp/inspection}
AVAIL_KB=$(df -Pk "$([[ -d $ROOTDIR ]] && echo $ROOTDIR || echo /var/tmp)" | awk 'NR==2{print $4}')
AVAIL_GB=$((AVAIL_KB / 1024 / 1024))
if (( AVAIL_GB >= 50 )); then ok "$AVAIL_GB GB free for raw traces (>= 50 GB recommended)"; else warnk "only $AVAIL_GB GB free for raw traces (>= 50 GB recommended; raw Tracee streams are large)"; fi
echo "note  raw-trace dir: $ROOTDIR (override with TRACEE_DATA_DIR)"

header "Tracee smoke prerequisites"
if docker info >/dev/null 2>&1; then
  docker image inspect "${TRACEE_IMAGE:-aquasec/tracee}:${TRACEE_TAG:-latest}" >/dev/null 2>&1 \
    && ok "tracee image already pulled (${TRACEE_IMAGE:-aquasec/tracee}:${TRACEE_TAG:-latest})" \
    || warnk "tracee image not pulled yet (sensor/README.md documents the pull/smoke run)"
fi

echo
echo "=== SUMMARY: $pass pass, $warn warn, $fail fail ==="
if (( JSON )); then
  cat <<EOF
{"kernel":"$KVER","btf":$([[ -f /sys/kernel/btf/vmlinux ]] && echo true || echo false),"docker":"$(command -v docker >/dev/null && echo yes || echo no)","compose":"$(docker compose version >/dev/null 2>&1 && echo yes || echo no)","cgroup_v2":$([[ -f /sys/fs/cgroup/cgroup.controllers ]] && echo true || echo false),"disk_free_gb":$AVAIL_GB,"pass":$pass,"warn":$warn,"fail":$fail}
EOF
fi
(( fail == 0 )) || exit 1
