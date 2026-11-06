# ActPlane (T7 exemplar) — kernel/arch compatibility incident (RESOLVED: 2026-10-31)

**Status: RESOLVED — ActPlane is workable on kernel 6.17.** The
2026-10-31 probe (wider-control phase 0, run-id actplane-probe-20261031,
evidence in ~/research/wider-control/results/actplane-probe-20261031/)
found the working zone and verified live enforcement. The original matrix
below is preserved: its conclusion was correct for the kernels it tested
(6.8, 7.0) but the failure classes are kernel-version properties, not
ActPlane build artifacts.

## Resolution details (probe, x86_64, Ubuntu 24.04, c6i.xlarge spot)

| kernel | result |
|---|---|
| 6.1.189 (AL2023) | FAIL: bpf_user_ringbuf_drain helper missing — hard floor is 6.2+ (the README's "6.1+" is stale for current code) |
| 6.8.0-1055-aws | FAIL: combined stack 608 > 512 (trace_recvfrom_exit) — reproduces with a FROM-SOURCE clang-18 rebuild, so not a stale-binary artifact |
| 7.0.0-1014-aws / 1017-azure | FAIL: verifier 1M-insn budget (CAP_DOMAIN_DEPTH exec handler); byte-identical verifier stats on both cloud builds |
| **6.17.0-1010-aws** | **PASS: engine loads; kill + notify + block enforced live; full e2e suites 12/12 + 8/8 green; the crate 0.1.8 PREBUILT object also loads (no rebuild needed)** |

Context: ActPlane's CI was green through Oct 16 on GitHub's 24.04 runner
(kernel 6.17.0-1022-azure at the time) and has NOT run on the runner's
current 7.0 kernel — consistent with the 7.0 failure above.

### Fixture requirements discovered

(The requirements below are IMPLEMENTED and ACCEPTED LIVE as of
2026-11-01 — the T7 kernel slot (compose/slots/t7.yaml +
compose/t7.yaml), the actplane control plugin (plugins/actplane/: manifest
with the kernel-interference declaration, binding overlay, fixture
policy, entrypoint supervisor with config-at-load + singleton teardown,
and the match-event shim with raw_ref provenance). The live acceptance
pair (t7-actplane-t7-13/-14, kernel 6.17.0-1010-aws, pi harness): BOTH
runs status PASS, all R-checks green, identical outcome counts — 8
bypassed (the tool-call classes, invisible at the kernel's semantic
level), 6 checked-allowed (the effect classes: direct_network/spawn/
file_write/credential), 1 checked-denied (the a032 policy deny). One
honest finding recorded: a022 (unconnected udp sendto) has no decision
from the control — a REAL hook-coverage gap (the engine hooks
exec/open/write/unlink/connect; no sendmsg hook), the instance-level
refinement of the AAMAS derived T7 row. Kernel facts discovered live:
the loader must run in TRACEPOINT mode (enforce-mode's larger program
set exceeds the 6.17 verifier's limits); the connect events carry the numeric IP
without a port (the fixture pins static target addresses); docker-exec'd
harness processes are children of the container SHIM, so the engine
seeds the shim pid.)

1. Pin kernel 6.17.x. Three distinct, source-level verifier failure
   classes block 6.1, 6.8, and 7.0.
2. Write-sink rules (read/write/unlink/open) cannot be installed as
   `actplane run` runtime deltas (the pinned singleton loads with an
   empty config and reserves hooks but not file-sink matcher classes);
   they must be loaded at engine start via the config-loader path
   (`bpf/process --config <blob>`, the approach their own e2e driver
   uses). Exec/connect rules work fine via `run` deltas. This maps to
   guardscope's `configure(policy_descriptor)` at provision, with
   re-configure requiring an engine reload rather than a delta.
3. The singleton pin (/sys/fs/bpf/actplane/v1) persists after run exit:
   the T7 fixture needs explicit teardown between cells (R4/leftover
   discipline) and per-cell feature-profile control.
4. Block rules need BPF-LSM active. Ubuntu-family kernels: add `bpf` to
   the `lsm=` boot parameter in /etc/default/grub.d/
   50-cloudimg-settings.cfg and reboot (CONFIG_BPF_LSM=y is already set
   in -aws kernels). AL2023 comes with bpf active by default.
5. Commit bb89c77 (master, 2026-10-16) tested; crate 0.1.8 pinned binary
   re-verified on 6.17 — the existing target pin does not need a rebuild.

---

# Original incident (2026-10-07, preserved)

**Status (superseded): T7 is OUT OF REACH with ActPlane.** The prebuilt eBPF programs fail
the verifier on every host/kernel/arch combination provisioned (4 combos,
both the pinned 0.1.8 crate and git master). This file records the full
matrix so a future retry (new ActPlane release, or a from-source BPF rebuild
with a different clang) starts from the diagnosis, not from scratch.

## Compatibility matrix (all checked live)

| host arch | kernel | ActPlane 0.1.8 | ActPlane master |
|---|---|---|---|
| arm64 (Graviton) | 7.0.0-1013-aws | BPF too large: 1000001 insns (limit 1M) — taint-engine loop in `handle_exec` | BPF_PROG_LOAD E2BIG (`exec_tp_update_prefix`) |
| arm64 | 6.8.0-146-generic | combined stack 608 > 512 (`trace_openat_exit`) | missing `sys_enter_open` tracepoint (arm64 syscalls; x86-only reference) |
| x86_64 | 7.0.0-1014-aws | BPF too large: 1000001 insns (limit 1M) — same taint-engine loop | (not checked; same 7.0 verifier family as arm64) |
| x86_64 | 6.8.0-146-generic | combined stack 608 > 512 (`trace_openat_exit`) | combined stack 608 > 512, 6 calls (`trace_recvfrom_exit`) |

Two distinct failure classes:
- **Kernel 7.x**: the verifier explores the temporal-gate loop unbounded —
  1M-instruction complexity budget exceeded.
- **Kernel 6.8**: the program itself overflows the verifier's 512-byte
  combined call stack (openat/recvfrom handlers), on both arches.

Also confirmed: BPF-LSM is not active on our hosts (`/sys/kernel/security/lsm`
lacks `bpf`), so ActPlane `block` rules were out of scope regardless — the
v1 T7 measurement was to be notify-mode (kernel-level audit + corrective
feedback).

## Required container mounts / environment (recorded for the retry)

- `/sys/kernel/tracing` (tracefs hooks), `/sys/kernel/security`
  (the `/sys/kernel/security/lsm` check), `/sys/fs/bpf` (the
  `/sys/fs/bpf/actplane/v1` pin path — without it the singleton open fails
  with ENOENT). All three discovered by strace; plain `--privileged` does
  not provide them.
- `watch` rejects attaching to pid 1 — run under docker `--init` or a
  non-pid-1 parent.
- Policy grammar: `notify exec|read|write|unlink|open file PAT` /
  `connect endpoint PAT` (the `file`/`endpoint` keyword is required);
  `run` needs a `source AGENT = exec ...` declaration.
- On arm64, `sys_enter_open` does not exist as a tracepoint (6.8) — any BPF
  referencing it cannot attach; x86_64 has it.

## Path forward (pick one)

1. **From-source BPF rebuild with a different clang**: the stack-overflow
   frames are a property of the compiled binary; a rebuild with another
   clang may fit under 512 (uncertain). Needs the ActPlane source + clang/
   llvm + submodules (`ACTPLANE_REBUILD_BPF=1`), then a local image build.
2. **Wait for an upstream ActPlane release** whose prebuilt BPF compiles
   against 6.8/7.0 verifiers; re-check with the compatibility script below.
3. **Drop T7 from the v1 measurement scope**; the T7 column remains
   design-level and the exemplar compatibility is the reported empirical
   finding (it motivates the check criterion: deployable-from-docs is not
   sufficient — the enforcement engine must also LOAD on the host kernel).
