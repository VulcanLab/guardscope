"""Experiment-file loading, semantic validation, and run-plan expansion
(DESIGN.md 6).

The experiment file is the only user-facing configuration format. Four
user-facing fields: control (required, nullable), designs (required,
explicit), harness, workload. Anything omitted is filled with a prepared
default and recorded as a fact in the resolved plan rather than requested as
a choice. Semantic validation happens at load time, before any topology is
provisioned: every inapplicable pairing is a hard error naming the conflict.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

import jsonschema
import yaml

from framework.contracts import (  # noqa: E402
    ContractError, load_capabilities, manifest_path,
)
from framework.schemas import load_schema

_EXPERIMENT_VALIDATOR = jsonschema.Draft202012Validator(
    load_schema("experiment"))


class ExperimentError(ValueError):
    """The experiment file is invalid (schema or semantic)."""


# Prepared defaults (DESIGN.md 6: "the prepared default harness" / "the
# prepared default pack (baseline-15)"). Constants for now: they come from
# the prepared default set and move to the registry when the registry lands
# (M2, DESIGN.md 12).
DEFAULT_HARNESS = "pi"
DEFAULT_WORKLOAD = "baseline-15"

# The reference designs (DESIGN.md 7). Designs that place the selected
# control in the gateway slot; with control:null there is nothing in that
# slot, so these are load-time errors. T2/T5 are gateway placements exactly
# like T1/T3 (DESIGN.md 7 table: T2 is T1 + forced egress; T5 is the
# harness chain plus the gateway), so they are gated the same way.
GATEWAY_SLOT_DESIGNS = frozenset({"t1", "t2", "t3", "t5"})
# Designs whose enforcement is intrinsic to the harness (DESIGN.md 6:
# "control: null with an enforcement-capable harness is the natural
# expression of the T4/T6 configurations").
HARNESS_INTRINSIC_DESIGNS = frozenset({"t4", "t6"})
# Designs valid with no selected control and no harness enforcement.
NO_CONTROL_DESIGNS = frozenset({"t0", "t7"})
ALL_DESIGNS = tuple(f"t{i}" for i in range(8))

# Reference-rig fixture ids per design (DESIGN.md 6 recorded defaults:
# "fixture: the reference rig matching each requested design"; the rigs are
# the compose/t<n>.yaml topologies). t7 is the kernel-level observation row
# (DESIGN.md 7) and is flagged observation-only; its reference fixture is
# not materialized in this pass (env/versions.env: no compatible host yet).
def reference_rig_id(design: str) -> str:
    return f"reference-rig/{design}"


@dataclass
class ResolvedExperiment:
    """The experiment after schema + semantic validation, with every
    omitted field resolved and the resolution recorded as a fact
    (DESIGN.md 6). No global state: everything lives here."""
    control: str | None
    designs: list[str]
    harness: str
    workload: str
    fixture: dict | None
    off_matrix: bool
    defaults_applied: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "control": self.control,
            "designs": list(self.designs),
            "harness": self.harness,
            "workload": self.workload,
            "fixture": self.fixture,
            "off_matrix": self.off_matrix,
            "defaults_applied": dict(self.defaults_applied),
        }


@dataclass
class RunDescriptor:
    """One single-design run of the expanded plan (DESIGN.md 6: one run per
    requested design; DESIGN.md 10: grids are batch loops over these)."""
    design: str
    fixture: str
    control: str | None
    control_binding: str   # selected | harness-intrinsic | none (DESIGN.md 3)
    harness: str
    workload: str
    off_matrix: bool
    observation_only: bool  # t7: the kernel-observation row (DESIGN.md 7)

    def to_dict(self) -> dict:
        return {
            "design": self.design,
            "fixture": self.fixture,
            "control": self.control,
            "control_binding": self.control_binding,
            "harness": self.harness,
            "workload": self.workload,
            "off_matrix": self.off_matrix,
            "observation_only": self.observation_only,
        }


@dataclass
class Plan:
    experiment: ResolvedExperiment
    runs: list[RunDescriptor]

    def to_dict(self) -> dict:
        return {"experiment": self.experiment.to_dict(),
                "runs": [r.to_dict() for r in self.runs]}


# --- loading --------------------------------------------------------------------

def _read_document(path: Path) -> dict:
    text = Path(path).read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        doc = yaml.safe_load(text)
    else:
        doc = json.loads(text)
    if not isinstance(doc, dict):
        raise ExperimentError(f"{path}: not an object at the top level")
    return doc


def _design_conflict_reason(design: str, manifest: dict) -> str:
    """The reason a design does not apply to a control, for the load-time
    error (DESIGN.md 6: the error names the conflict)."""
    supported = set(manifest.get("supported_designs") or [])
    if design == "t0":
        return "the bare-harness design selects no control"
    if design == "t7":
        return "kernel-level enforcement is not a control placement " \
               "(t7 is the observation row)"
    if design in HARNESS_INTRINSIC_DESIGNS and supported <= GATEWAY_SLOT_DESIGNS:
        return "requires harness-intrinsic enforcement; this control " \
               "occupies gateway slots"
    return f"not declared by this control's capability manifest " \
           f"(supported: {sorted(supported)})"


def load_experiment(path) -> ResolvedExperiment:
    """Load and validate an experiment file (DESIGN.md 6).

    jsonschema validation against experiment/1 first, then semantic
    validation; every inapplicable pairing raises ExperimentError naming
    the conflict. Returns the resolved experiment with omitted fields
    filled from the prepared defaults and the fill recorded.
    """
    path = Path(path)
    doc = _read_document(path)

    # bare stamp first (DESIGN.md 4): a clearer error than the schema's const
    if doc.get("schema") != 1:
        raise ExperimentError(
            f"{path}: the schema stamp is the bare literal 1 (DESIGN.md 4; "
            f"no type names inside data files); got {doc.get('schema')!r}")

    error = jsonschema.exceptions.best_match(
        _EXPERIMENT_VALIDATOR.iter_errors(doc))
    if error is not None:
        raise ExperimentError(f"{path}: {error.message}")

    control = doc["control"]
    designs = list(doc["designs"])
    harness = doc.get("harness")
    workload = doc.get("workload")
    fixture = doc.get("fixture")
    defaults_applied: dict[str, str] = {}
    if harness is None:
        harness = DEFAULT_HARNESS
        defaults_applied["harness"] = DEFAULT_HARNESS
    if workload is None:
        workload = DEFAULT_WORKLOAD
        defaults_applied["workload"] = DEFAULT_WORKLOAD

    # --- plugin resolution (DESIGN.md 11: declaring is not conforming;
    # the manifest is the claim checked here, not a conformance verdict) ---
    control_manifest = None
    if control is not None:
        try:
            control_manifest = load_capabilities(control)
        except ContractError as exc:
            raise ExperimentError(f"control {control!r}: {exc}") from exc
        if control_manifest["kind"] != "control":
            raise ExperimentError(
                f"control {control!r}: kind is "
                f"{control_manifest['kind']!r}, not 'control'")
    try:
        harness_manifest = load_capabilities(harness)
    except ContractError as exc:
        raise ExperimentError(f"harness {harness!r}: {exc}") from exc
    if harness_manifest["kind"] != "harness-adapter":
        raise ExperimentError(
            f"harness {harness!r}: kind is {harness_manifest['kind']!r}, "
            f"not 'harness-adapter'")
    if workload is not None:
        wp = manifest_path(workload)
        if wp.is_file():
            try:
                workload_manifest = load_capabilities(workload)
            except ContractError as exc:
                raise ExperimentError(f"workload {workload!r}: {exc}") from exc
            if workload_manifest["kind"] != "workload":
                raise ExperimentError(
                    f"workload {workload!r}: kind is "
                    f"{workload_manifest['kind']!r}, not 'workload'")
        # no workload manifests exist yet (baseline-15 registers with the
        # registry in M2); an unknown id is accepted until then

    # --- composition gating (DESIGN.md 6: a composition block may never
    # appear alongside a non-null control; it auto-sets off_matrix) -------
    composition = (fixture or {}).get("composition")
    if composition and control is not None:
        raise ExperimentError(
            "fixture.composition declares two controls and requires "
            f"control: null (got {control!r}); two controls run only as "
            "off-matrix composition fixtures (DESIGN.md 6, 7)")
    if composition:
        for item in composition:
            try:
                comp_manifest = load_capabilities(item["plugin"])
            except ContractError as exc:
                raise ExperimentError(
                    f"composition plugin {item['plugin']!r}: {exc}") from exc
            if comp_manifest["kind"] != "control":
                raise ExperimentError(
                    f"composition plugin {item['plugin']!r}: kind is "
                    f"{comp_manifest['kind']!r}, not 'control'")

    # --- design applicability (DESIGN.md 6: checked at load time against
    # the control's capability manifest and the harness's supported t-modes;
    # an inapplicable design is a hard error naming the conflict) ---------
    conflicts = []
    harness_modes = set(harness_manifest.get("supported_designs") or [])
    for design in designs:
        if design not in harness_modes:
            conflicts.append(
                f"design {design} not supported by harness {harness!r}: "
                f"supported t-modes are {sorted(harness_modes)}")
            continue
        if control_manifest is not None:
            if design not in (control_manifest.get("supported_designs") or []):
                conflicts.append(
                    f"design {design} not applicable to {control!r}: "
                    f"{_design_conflict_reason(design, control_manifest)}")
        else:  # control: null (DESIGN.md 6)
            if design in GATEWAY_SLOT_DESIGNS and not composition:
                conflicts.append(
                    f"design {design} with control: null: no control "
                    f"occupies the gateway slot (select a control; "
                    f"t4/t6 are the intrinsic-enforcement designs)")
            elif design in HARNESS_INTRINSIC_DESIGNS:
                hostable = harness_manifest.get("hostable_enforcement_points")
                if not hostable:
                    conflicts.append(
                        f"design {design} with control: null requires a "
                        f"harness manifest declaring hostable enforcement "
                        f"points; harness {harness!r} declares none")
    if conflicts:
        raise ExperimentError("; ".join(conflicts))

    # --- off_matrix (DESIGN.md 6: composition auto-sets it; DESIGN.md 7:
    # custom fixtures run off-matrix with full measurement fidelity) -----
    off_matrix = bool(composition) or fixture is not None

    return ResolvedExperiment(
        control=control,
        designs=designs,
        harness=harness,
        workload=workload,
        fixture=fixture,
        off_matrix=off_matrix,
        defaults_applied=defaults_applied,
    )


# --- plan expansion ---------------------------------------------------------------

def resolve(experiment: ResolvedExperiment) -> Plan:
    """Expand to one run descriptor per requested design (DESIGN.md 6:
    the user lists designs; one run per design)."""
    if not isinstance(experiment, ResolvedExperiment):
        raise TypeError("resolve() takes the ResolvedExperiment from "
                        "load_experiment()")
    runs = []
    for design in experiment.designs:
        if experiment.fixture is not None:
            fixture = experiment.fixture["name"]
        else:
            fixture = reference_rig_id(design)
        if experiment.control is not None:
            binding = "selected"                    # DESIGN.md 3 emission test
        elif design in HARNESS_INTRINSIC_DESIGNS:
            binding = "harness-intrinsic"
        else:
            binding = "none"
        runs.append(RunDescriptor(
            design=design,
            fixture=fixture,
            control=experiment.control,
            control_binding=binding,
            harness=experiment.harness,
            workload=experiment.workload,
            off_matrix=experiment.off_matrix,
            # t7: the kernel-level observation row (DESIGN.md 7)
            observation_only=(design == "t7"),
        ))
    return Plan(experiment=experiment, runs=runs)
