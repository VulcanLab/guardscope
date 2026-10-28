# ActPlane (T7): kernel-level enforcement exemplar. The actplane binary is
# compiled from the pinned crate (env/versions.env ACTPLANE_VERSION) — no
# clang/llvm needed at runtime (CO-RE eBPF embedded). Runs INSIDE the
# harness container composition with CAP_BPF/CAP_SYS_ADMIN (eBPF engine
# load); the wrapped command drops back to the container user.
FROM rust:1-slim
# libbpf-sys (vendored build) needs make/libelf/zlib even though the RUNTIME
# needs no toolchain (CO-RE eBPF is embedded in the binary).
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates python3 make build-essential libelf-dev zlib1g-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
# Pinned via build arg (compose passes ACTPLANE_VERSION).
ARG ACTPLANE_VERSION=0.1.8
ARG ACTPLANE_GIT=""
# Build from the pinned crate (default) or from a git ref (ACTPLANE_GIT) —
# used when the pinned prebuilt BPF fails the running kernel's verifier.
RUN if [ -n "$ACTPLANE_GIT" ]; then \
      cargo install --locked --git $ACTPLANE_GIT actplane; \
    else \
      cargo install actplane --version ${ACTPLANE_VERSION} --locked; \
    fi
ENTRYPOINT ["/usr/local/cargo/bin/actplane"]
