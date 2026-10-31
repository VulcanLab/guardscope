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
      ca-certificates git make libelf-dev zlib1g-dev pkg-config \
      python3 docker.io procps \
    && rm -rf /var/lib/apt/lists/*
# python3: the match-event shim (plugins/actplane/shim) runs in-container.
# docker.io: the CLI only (the daemon is unused; the supervisor talks to
#   the HOST daemon over the mounted /var/run/docker.sock to find the
#   harness container's init pid for --seed-pid).
# procps: pgrep/pkill for the supervisor's teardown.

# Pinned source ref (probe-verified commit; matches crates.io 0.1.8).
ARG ACTPLANE_REF=bb89c77
RUN git clone --recurse-submodules --depth 1 \
      https://github.com/eunomia-bpf/ActPlane /src/ActPlane && \
    cd /src/ActPlane && \
    git fetch --depth 1 origin ${ACTPLANE_REF} && \
    git checkout ${ACTPLANE_REF}

# The CLI from the checkout (one source of truth with the loader).
RUN cd /src/ActPlane && cargo install --path crates/actplane-cli --root /usr/local

# The config-at-load loader: the ebpf-ifc-engine crate under bpf/ (its
# embedded prebuilt object is the probe-verified binary; NO clang rebuild).
# The bin lands in bpf/target/release/process (bpf/ is its own cargo
# workspace root).
RUN cd /src/ActPlane/bpf && cargo build --release && \
    find . target -maxdepth 3 -name process -type f -exec cp {} /usr/local/bin/actplane-process \;

# The control supervisor invokes the loader at /opt/actplane/process.
RUN mkdir -p /opt/actplane && \
    ln -s /usr/local/bin/actplane-process /opt/actplane/process && \
    ln -s /usr/local/bin/actplane /usr/local/cargo/bin/actplane 2>/dev/null || true; \
    actplane --version && actplane-process --help 2>&1 | head -1 || true

WORKDIR /src/ActPlane
