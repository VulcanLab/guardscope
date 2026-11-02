"""Plugin contracts (DESIGN.md 3): the control contract and the harness
adapter contract, plus the reference in-process control lifecycle and the
plugin capability-manifest loader.

No module here may behave differently depending on a plugin's identity
(DESIGN.md 2): the contracts are the public surface every plugin uses, and
the runner statically compares describe() output rather than negotiating.

Docker provisioning is NOT implemented in this pass: InProcessControl is the
reference lifecycle over a plain in-memory object so unit tests can drive a
control without a container.
"""

import hashlib
import json
from pathlib import Path
from typing import Callable, Protocol, runtime_checkable

import jsonschema

from framework.records import (
    RecordValidationError, make_decision_record, new_ulid, now_rfc3339_ms,
)
from framework.schemas import load_schema

REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGINS_DIR = REPO_ROOT / "plugins"

# The control-contract line this framework verifies (DESIGN.md 11 "Contract
# versioning": additive optional fields are a minor bump; record schema,
# reconciliation semantics, and evidence classes are major, with a two-release
# deprecation window). The six-operation contract of DESIGN.md 3, line 1;
# a recorded conformance verdict is keyed by this and expires when it bumps.
CONTROL_CONTRACT_VERSION = "1"

_MANIFEST_VALIDATOR = jsonschema.Draft202012Validator(
    load_schema("capabilities-manifest"))


class ContractError(ValueError):
    """A plugin violated its contract or its manifest is invalid."""


# --- the contracts (DESIGN.md 3 tables) ----------------------------------------

@runtime_checkable
class ControlContract(Protocol):
    """The control contract: six operations, one contract, capabilities
    declared per plugin (DESIGN.md 3). Verbatim semantics per operation:

    describe()
        Static manifest: slot kinds supported; record_source: native |
        ingested; correlation capability claims (echoes_meta, echoes_header,
        verified by the fidelity check, never trusted); observable action
        classes; can_enforce: enforce | observe (an observe-only control can
        never issue a deny, so it can never yield a checked-denied outcome;
        'prevented' never originates from a control record — it is blocking
        outside the policy with no decision record at all); supported
        schema versions.

    provision(slot)
        Slot-typed: 'container' (image + compose service), 'attached_process'
        (configure an existing host/process), 'log_ingest' (register a vendor
        log source; the shim case). Returns {handle, attach}; the attach
        descriptor is per-slot and carries the runner-assigned stream_id plus
        typed env. No global singleton env.

    configure(policy_descriptor)
        Idempotent, reversible; returns a policy fingerprint that must match
        policy.policy_hash in emitted records.

    ready()
        Readiness must prove that enforcement works, not just that the
        container is running: it passes only when a runner-issued test action
        (one the loaded policy must deny) produces its decision record. A
        started container is not ready; opening the capture window too
        early silently produces false 'bypassed' results. The runner-side
        gate over this operation is enforcement_ready() below.

    collect()
        Flush-then-report: {stream_locator, record_count, seq_range,
        flush_ack}. One record per decision even when the control batches
        internally. Records arriving after the window closes with a valid
        run_id are accepted and flagged late; they are never dropped or
        counted silently.

    teardown()
        Crash-safe, idempotent, removes volumes. A leftover decisions.jsonl
        from a previous run must be impossible; returning success means the
        records were durably written.
    """

    def describe(self) -> dict: ...
    def provision(self, slot: dict) -> dict: ...
    def configure(self, policy_descriptor: dict) -> str: ...
    def ready(self) -> bool: ...
    def collect(self) -> dict: ...
    def teardown(self) -> None: ...


@runtime_checkable
class HarnessAdapterContract(Protocol):
    """The harness adapter contract: six operations (DESIGN.md 3). Verbatim
    semantics per operation:

    describe()
        Harness version; hostable enforcement points; supported T-modes;
        retry policy.

    configure(enforcement_config)
        T4/T6 permission chains per run, from the same policy-descriptor
        form as controls; deterministic, no leftover state from earlier
        runs; returns config hashes.

    ready()
        Dispatch loop running (readiness confirmed by a signal, not by a
        fixed sleep delay); gateway endpoint responding; replay injection
        confirmed.

    inject(trace)
        Single-pass, ordered, no retries by contract default; if the
        adapter cannot disable internal retries it emits one dispatch
        record per attempt and the run is flagged; sets correlation
        carriers wherever the transport allows.

    collect()
        Dispatch-record flush.

    teardown()
        State isolation between grid cells; permission state must not carry over.
    """

    def describe(self) -> dict: ...
    def configure(self, enforcement_config: dict) -> dict: ...
    def ready(self) -> bool: ...
    def inject(self, trace: dict) -> None: ...
    def collect(self) -> dict: ...
    def teardown(self) -> None: ...


# --- readiness: enforcement must be proven, not assumed (DESIGN.md 3) --------

# The reference lifecycle reserves this tool name: the loaded reference
# policy always denies it, so a readiness check action the policy must deny
# always exists. A runner may pass its own test action instead (one its
# loaded policy denies).
READINESS_TOOL = "__readiness_check__"


def readiness_test_action() -> dict:
    """A runner-issued test action the configured policy must deny
    (DESIGN.md 3 ready(): readiness must prove that enforcement works)."""
    return {
        "action_id": f"readiness-{new_ulid()}",
        "tool": READINESS_TOOL,
        "class": "stdio_tool_call",
        "parameters": {},
    }


def enforcement_ready(control, issue_test_action: Callable[[dict], object] | None,
                      test_action: dict | None = None) -> bool:
    """The runner-side readiness gate over a control (DESIGN.md 3).

    `issue_test_action(action)` is the runner's callable that drives one
    test action through the topology so the enforcement point evaluates it.
    The check passes only when the action's decision record appears in
    collect() and is a deny: a started container is not ready, and opening
    the capture window before enforcement works silently produces false
    'bypassed' results. A missing record (enforcement did not run, or the
    control dropped it) fails the check.
    """
    action = test_action or readiness_test_action()
    if issue_test_action is None:
        if not hasattr(control, "evaluate"):
            raise ContractError(
                "issue_test_action is required unless the control is an "
                "InProcessControl (no evaluate() to route through)")
        issue_test_action = control.evaluate
    issue_test_action(action)
    report = control.collect()
    records = report.get("records") or []
    hits = [r for r in records
            if r.get("action_id") == action["action_id"]]
    return bool(hits) and all(h["decision"] == "deny" for h in hits)


# --- the reference in-process lifecycle (no Docker this pass) -------------------

# lifecycle states (DESIGN.md 9: provision -> configure -> ready-gate -> ... )
STATES = ("created", "provisioned", "configured", "ready", "torn_down")


class InProcessControl:
    """Reference implementation of the control contract over a plain
    in-memory object, so unit tests can drive the lifecycle without Docker
    (DESIGN.md 3). Docker provisioning is a later pass.

    The policy engine is the reference one: a policy_descriptor of the form
    {"policy_id", "policy_version", "deny_tools": [...]} denies any action
    whose tool is listed (and always the reserved readiness tool), allows
    everything else. Every evaluate() call produces exactly one
    decision-record/1 record (native record source) whose policy.policy_hash
    is the configure() fingerprint, buffered for collect().

    The state machine: created -> provision -> configured -> ready ->
    torn_down; configure() is idempotent and reversible (re-configuring
    replaces the policy and resets the buffer); teardown() is idempotent
    and leaves nothing behind (records live only in memory, so a leftover
    decisions.jsonl is impossible by construction).
    """

    def __init__(self, plugin_id: str = "inprocess-control",
                 plugin_version: str = "1", product: str = "inprocess-control",
                 product_version: str = "1"):
        self.plugin_id = plugin_id
        self.plugin_version = plugin_version
        self.product = product
        self.product_version = product_version
        self.state = "created"
        self.slot = None
        self.stream_id = None
        self.policy_descriptor = None
        self.policy_hash = None
        self._records: list[dict] = []
        self._seq = 0

    # -- describe (DESIGN.md 3) -------------------------------------------

    def describe(self) -> dict:
        return {
            "plugin": self.plugin_id,
            "plugin_version": self.plugin_version,
            "slot_kinds": ["embedded"],
            "record_source": "native",
            "correlation": {"echoes_meta": False, "echoes_header": False},
            "observable_action_classes": ["stdio_tool_call", "http_tool_call"],
            "can_enforce": "enforce",
            "emitted_schema_versions": ["decision-record/1"],
        }

    # -- provision (DESIGN.md 3) -------------------------------------------

    def provision(self, slot: dict) -> dict:
        if self.state == "torn_down":
            raise ContractError("cannot provision a torn-down control")
        if not isinstance(slot, dict) or not slot.get("id") \
                or not slot.get("stream_id"):
            raise ContractError(
                "slot must carry at least {id, stream_id} (the "
                "runner-assigned per-slot stream id, DESIGN.md 3)")
        self.slot = slot
        self.stream_id = slot["stream_id"]
        self.state = "provisioned"
        return {
            "handle": f"inprocess:{slot['id']}",
            "attach": {"stream_id": slot["stream_id"]},
        }

    # -- configure (DESIGN.md 3) -------------------------------------------

    def configure(self, policy_descriptor: dict) -> str:
        if self.state not in ("provisioned", "configured"):
            raise ContractError(
                f"configure() requires a provisioned control (state "
                f"{self.state!r})")
        for key in ("policy_id", "policy_version"):
            if not policy_descriptor.get(key):
                raise ContractError(f"policy_descriptor missing {key!r}")
        deny_tools = policy_descriptor.get("deny_tools")
        if not isinstance(deny_tools, list) \
                or any(not isinstance(t, str) for t in deny_tools):
            raise ContractError("policy_descriptor.deny_tools must be [str]")
        # idempotent + reversible: same descriptor -> same fingerprint
        self.policy_descriptor = dict(policy_descriptor)
        self.policy_hash = hashlib.sha256(json.dumps(
            policy_descriptor, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        self.state = "configured"
        return self.policy_hash

    # -- the in-process enforcement point (not a contract operation) ------

    def evaluate(self, action: dict) -> dict:
        """Evaluate one action at the enforcement point and buffer exactly
        one decision record (DESIGN.md 3 collect(): one record per decision)."""
        if self.state not in ("configured", "ready"):
            raise ContractError(
                f"evaluate() requires a configured control (state "
                f"{self.state!r})")
        denied = (action.get("tool") in
                  (self.policy_descriptor.get("deny_tools") or [])
                  or action.get("tool") == READINESS_TOOL)
        record = make_decision_record(
            run_id=self.slot.get("run_id", "unassigned-run"),
            stream_id=self.stream_id,
            seq=self._seq,
            ts=now_rfc3339_ms(),
            enforcement_point={
                "slot_id": self.slot["id"],
                "product": self.product,
                "product_version": self.product_version,
            },
            producer={
                "plugin": self.plugin_id,
                "plugin_version": self.plugin_version,
                "record_source": "native",
            },
            action_class=action.get("class", "stdio_tool_call"),
            protocol=action.get("protocol", "stdio"),
            tool=action["tool"],
            target=action.get("target", {"kind": "unknown"}),
            parameters_digest=hashlib.sha256(json.dumps(
                action.get("parameters", {}), sort_keys=True,
                separators=(",", ":")).encode()).hexdigest(),
            action_id=action.get("action_id"),
            correlation_transport="none",
            decision="deny" if denied else "allow",
            policy={
                "policy_id": self.policy_descriptor["policy_id"],
                "policy_version": self.policy_descriptor["policy_version"],
                # must match the configure() fingerprint (DESIGN.md 3)
                "policy_hash": self.policy_hash,
            },
            parameters=action.get("parameters", {}),
            **({"evidence": [{"kind": "test-action",
                               "locator": {"source": "inprocess"}}]}
               if denied else {}),
        )
        self._seq += 1
        self._records.append(record)
        return record

    # -- ready (DESIGN.md 3) ------------------------------------------------

    def ready(self) -> bool:
        """Readiness must prove enforcement works (DESIGN.md 3): the default
        test action (the reserved tool the reference policy always denies)
        must produce a deny record in collect()."""
        if self.state == "ready":
            return True
        if self.state != "configured":
            return False
        ok = enforcement_ready(self, None)
        if ok:
            self.state = "ready"
        return ok

    # -- collect (DESIGN.md 3) -----------------------------------------------

    def collect(self) -> dict:
        """Flush-then-report (DESIGN.md 3): returns the buffered records and
        clears the buffer (the flush ack). seq_range is None when empty."""
        records = self._records
        self._records = []
        seqs = [r["seq"] for r in records]
        return {
            "stream_locator": f"inmemory://{self.stream_id}",
            "record_count": len(records),
            "seq_range": [min(seqs), max(seqs)] if seqs else None,
            "flush_ack": True,
            "records": records,
        }

    # -- teardown (DESIGN.md 3) -----------------------------------------------

    def teardown(self) -> None:
        """Idempotent, crash-safe, leaves nothing behind: records live only
        in memory, so there is no volume to remove and no leftover
        decisions.jsonl is possible (DESIGN.md 3)."""
        self._records = []
        self.policy_descriptor = None
        self.policy_hash = None
        self.slot = None
        self.stream_id = None
        self.state = "torn_down"


# --- plugin manifests + registry directory (DESIGN.md 2, 11) -------------------

def manifest_path(plugin_id: str) -> Path:
    return PLUGINS_DIR / plugin_id / "manifest.json"


def load_capabilities(plugin_id: str, version: str | None = None) -> dict:
    """Load and validate a plugin capability manifest from
    plugins/<plugin_id>/manifest.json (DESIGN.md 11: the plugin manifest
    layer: claims, immutable per version).

    Validates against capabilities-manifest/1, then checks the fields the
    declared kind must carry. `version`, when given, must match the
    manifest (the runner refuses version mismatches rather than guessing,
    DESIGN.md 11 'Contract versioning').
    """
    path = manifest_path(plugin_id)
    if not path.is_file():
        raise ContractError(f"no plugin manifest at {path}")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    try:
        _check_outcome_keys(manifest)
    except RecordValidationError as exc:
        raise ContractError(f"manifest {plugin_id}: {exc}") from exc
    error = jsonschema.exceptions.best_match(
        _MANIFEST_VALIDATOR.iter_errors(manifest))
    if error is not None:
        raise ContractError(f"manifest {plugin_id}: {error.message}")
    kind = manifest["kind"]
    if manifest["id"] != plugin_id:
        raise ContractError(
            f"manifest {plugin_id}: id field is {manifest['id']!r}")
    if version is not None and manifest["version"] != version:
        raise ContractError(
            f"manifest {plugin_id}: version {manifest['version']!r} != "
            f"requested {version!r}")
    if kind == "control":
        for field in ("slot_kinds", "record_source", "can_enforce",
                      "observable_action_classes", "supported_designs"):
            if field not in manifest:
                raise ContractError(
                    f"manifest {plugin_id}: control kind requires "
                    f"{field!r} (DESIGN.md 3 describe())")
        # DESIGN.md 3 'eBPF-enforcing controls': a control that binds a
        # kernel slot must declare its kernel interference (the claim the
        # run's pre-/post-provision sensor checks verify)
        if "kernel" in (manifest.get("slot_kinds") or []):
            ki = manifest.get("kernel_interference") or {}
            for field in ("declared", "mechanism", "sensor_impact"):
                if field not in ki:
                    raise ContractError(
                        f"manifest {plugin_id}: kernel slot kinds require a "
                        f"kernel_interference declaration with {field!r} "
                        f"(DESIGN.md 3 eBPF-enforcing controls)")
        for position in manifest.get("positions", []):
            missing = [d for d in position.get("designs", [])
                      if d not in manifest["supported_designs"]]
            if missing:
                raise ContractError(
                    f"manifest {plugin_id}: position {position['id']!r} "
                    f"declares designs {missing} outside supported_designs")
    elif kind == "harness-adapter":
        if "supported_designs" not in manifest:
            raise ContractError(
                f"manifest {plugin_id}: harness-adapter kind requires "
                f"'supported_designs' (DESIGN.md 3 describe(): supported "
                f"T-modes)")
    # workload kind carries no enforcement fields (DESIGN.md 8: no
    # enforcement points, no decision records)
    return manifest


def _check_outcome_keys(node) -> None:
    """Manifests carry capability claims only; outcome-shaped keys are
    rejected the same way as in records (DESIGN.md 1, 4)."""
    from framework.records import _check_outcome_keys as check
    check(node)
