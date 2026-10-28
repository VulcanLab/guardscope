# ActPlane (T7 exemplar) — kernel/arch compatibility incident (final: 2026-10-07)

**Status: T7 is OUT OF REACH with ActPlane.** The prebuilt eBPF programs fail
the verifier on every host/kernel/arch combination provisioned (4 combos,
both the pinned 0.1.8 crate and git master). This file records the full
matrix so a future retry (new ActPlane release, or a from-source BPF rebuild
with a different clang) starts from the diagnosis, not from scratch.

## Compatibility matrix (all probed live)

| host arch | kernel | ActPlane 0.1.8 | ActPlane master |
|---|---|---|---|
| arm64 (Graviton) | 7.0.0-1013-aws | BPF too large: 1000001 insns (limit 1M) — taint-engine loop in `handle_exec` | BPF_PROG_LOAD E2BIG (`exec_tp_update_prefix`) |
| arm64 | 6.8.0-146-generic | combined stack 608 > 512 (`trace_openat_exit`) | missing `sys_enter_open` tracepoint (arm64 syscalls; x86-only reference) |
| x86_64 | 7.0.0-1014-aws | BPF too large: 1000001 insns (limit 1M) — same taint-engine loop | (not probed; same 7.0 verifier family as arm64) |
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
   against 6.8/7.0 verifiers; re-probe with the compatibility script below.
3. **Drop T7 from the v1 measurement scope**; the T7 column remains
   design-level and the exemplar compatibility is the reported empirical
   finding (it motivates the probe criterion: deployable-from-docs is not
   sufficient — the enforcement engine must also LOAD on the host kernel).
