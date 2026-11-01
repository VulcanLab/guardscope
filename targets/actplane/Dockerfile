# ActPlane (T7): kernel-level enforcement exemplar. Two binaries are built
# from the SAME pinned source (commit bb89c77, the ref the 2026-10-31 probe
# verified live on 6.17: kill + block + notify enforced, e2e 12+8 green):
#
#   actplane  the CLI (policy compile; engine teardown tooling)
#   process   the ebpf-ifc-engine config-at-load loader used by the control
#             supervisor — REQUIRED for the T7 fixture policy: its write-sink
#             rules cannot be installed as `actplane run` runtime deltas
#             (probe 2026-10-31; targets/actplane/README.md "Fixture
#             requirements"); the engine must LOAD with the compiled config
#             (DESIGN.md 3 configure: policy-at-provision).
#
# The prebuilt CO-RE eBPF object embedded in the crate loads on kernel 6.17.x
# (probe-verified; also verified for the crates.io 0.1.8 prebuilt) — NO clang
# rebuild is needed, and NO clang toolchain ships in this image. Kernel pin:
# 6.17.x; fails on 6.8 (verifier stack), 7.0 (verifier insn budget), <6.2
# (user-ringbuf helper). See targets/actplane/README.md.
FROM rust:1-slim

# libbpf-sys (vendored build) needs make/libelf/zlib at build time; git
# fetches the pinned source; the runtime needs none of them (CO-RE eBPF is
# embedded in the binaries).
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates gnupg wget curl git make libelf-dev zlib1g-dev \
      pkg-config python3 docker-cli procps \
    && rm -rf /var/lib/apt/lists/*
# Pin clang-18 (the toolchain the 2026-10-31 probe verified live on 6.17:
# its codegen produces an object whose every program loads, including the
# exec_tp_update_prefix the 1M-insn verifiers reject from other builds —
# the committed prebuilt object AND trixie's clang both fail there).
# The LLVM apt repo pins the exact version on any Debian base.
RUN wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor > /etc/apt/trusted.gpg.d/llvm.gpg \
    && echo "deb http://apt.llvm.org/trixie/ llvm-toolchain-trixie-18 main" > /etc/apt/sources.list.d/llvm.list \
    && apt-get update && apt-get install -y --no-install-recommends clang-18 \
    && rm -rf /var/lib/apt/lists/* && clang-18 --version | head -1
# python3: the match-event shim (plugins/actplane/shim) runs in-container.
# docker.io: the CLI only (the daemon is unused; the supervisor talks to
#   the HOST daemon over the mounted /var/run/docker.sock to find the
#   harness container's init pid for --seed-pid).
# procps: pgrep/pkill for the supervisor's teardown.

# Pinned source ref (probe-verified commit; matches crates.io 0.1.8).
ARG ACTPLANE_REF=bb89c77bcb29cfa81ba1fb212b5634c353c7352b
RUN git clone --recurse-submodules --depth 1 \
      https://github.com/eunomia-bpf/ActPlane /src/ActPlane && \
    cd /src/ActPlane && \
    git fetch --depth 1 origin ${ACTPLANE_REF} && \
    git checkout ${ACTPLANE_REF}

# The CLI from the checkout (one source of truth with the loader).
RUN cd /src/ActPlane && cargo install --path crates/actplane-cli --root /usr/local

# The config-at-load loader (bpf/process): the CI-identical `make -C bpf`
# (libbpf + bpftool submodules, the BPF object compiled by the PINNED
# clang-18 — the exact toolchain the probe's e2e 12+8 passed with on
# 6.17; the libbpf skeleton loads EVERY program in the object, so the
# object must be one that verifies whole — the CLI's aya loader is
# selective, which is why actplane run worked while the skeleton did not).
RUN cd /src/ActPlane/bpf && CLANG=clang-18 make process && \
    cp process /usr/local/bin/actplane-process

# The control supervisor invokes the loader at /opt/actplane/process.
RUN mkdir -p /opt/actplane && \
    ln -s /usr/local/bin/actplane-process /opt/actplane/process && \
    ln -s /usr/local/bin/actplane /usr/local/cargo/bin/actplane 2>/dev/null || true; \
    actplane --version && actplane-process --help 2>&1 | head -1 || true

WORKDIR /src/ActPlane
