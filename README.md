# guardscope

guardscope is a measurement framework for runtime controls in LLM-agent
systems: it measures how much of an agent's action surface an inspection
layer (gateway, policy engine, sandbox) actually sees and decides on, and
at what latency and fidelity cost. The design is in `docs/DESIGN.md`.

The repository currently contains the core measurement components
(`compose/`, `env/`, `exerciser/`, `gateway/`, `harnesses/`,
`runner/`, `sensor/`, `targets/`, `tests/`, `trace/`) in its original
layout; the testbed's own documentation lives at `(no longer included)`.
