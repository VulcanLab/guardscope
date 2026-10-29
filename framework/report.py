"""Report-level merge of single-control run columns (DESIGN.md 10, the full
specification).

"A single-control run produces one design column of the shared path x
design matrix ... Grids are report-level merges of single-control run
columns. There is no grid schema and no grid run mode." This module loads
execution.json manifests (framework/execute.py output), pulls each run's
side artifacts (outcomes.json, the run manifest, the run record), groups
the runs into grids by the comparability key, and assembles the cells.

Comparability key (DESIGN.md 10, all must match to compose into one grid):
  workload hash; fixture fingerprint including enforcement_config; harness
  id + major version; kernel-sensor version; reconciliation profile id +
  version; classification-semantics version.

Implementation note on the fixture fingerprint: fixture identity is
per-design (each design column is its own reference rig), so it cannot be
part of the grid-level grouping key; it is carried per column instead
(within a grid, each design column carries its own fixture fingerprint),
and runs of the SAME (control, design) column whose fixture fingerprints
disagree are marked non-comparable per cell (visible, never averaged, and
a hard failure under --strict).

Merge guarantees implemented here (DESIGN.md 10):
  - evidence classes are preserved per cell and NEVER upgraded at report
    level (a self-reported run stays self-reported);
  - cell collisions (two runs covering the same control x design cell):
    keep both as distinct evidence rows with provenance, recency-mark one
    current, never average;
  - untested designs (the control's manifest supports them but no run
    covered them) are listed untested, not omitted, not derived;
  - run manifests are embedded (provenance is never dropped);
  - vendor-overlap flags: DESIGN.md 10 wants harness vendor == control
    vendor shown. LIMITATION: there are no vendor ids beyond plugin ids
    today, so a grid is flagged only when the control's and the harness's
    PLUGIN IDS are equal; a real vendor registry replaces this check.
  - origin labels (selected / harness-intrinsic / fixture-intrinsic) are
    shown on every grid position, from the design's enforcement-point
    structure (DESIGN.md 7 reference table; v1: the gateway designs select
    the control, t4/t6 run the harness permission chain, t5 has both
    points, t0 has none).
"""

import json
from pathlib import Path

import yaml

from framework.records import now_rfc3339_ms

REPO_ROOT = Path(__file__).resolve().parent.parent

# The outcome vocabulary + derivation version (runner/outcomes.py SCHEMA):
# the classification-semantics component of the comparability key. A run's
# outcomes.json carries its own schema stamp; this is the fallback when the
# run dir (or the outcomes file) is unavailable.
CLASSIFICATION_SEMANTICS = "inspection-outcomes/1"

# Origin labels per design (DESIGN.md 7 reference table): which enforcement
# points the design places and with what origin. v1 placement: the gateway
# designs select the control (selected); t4/t6's chain is harness-intrinsic;
# t5 has both points; t0 places none. (A harness-embedded control in t4/t6
# would be selected — not expressible in v1's experiment file.)
ORIGIN_LABELS = {
    "t0": [],
    "t1": ["selected"],
    "t2": ["selected"],
    "t3": ["selected"],
    "t4": ["harness-intrinsic"],
    "t5": ["selected", "harness-intrinsic"],
    "t6": ["harness-intrinsic"],
}

# Designs a control:null experiment can run (framework/experiment.py):
# the bare-harness row, the harness-intrinsic designs, and the t7
# observation row. The untested list for a null-control grid is built from
# these (the harness manifest's supported t-modes further constrain it).
NULL_CONTROL_DESIGNS = ("t0", "t4", "t6", "t7")

KEY_COMPONENTS = ("workload_sha256", "harness", "harness_major_version",
                   "kernel_sensor_version", "reconciliation_profile",
                   "classification_semantics")


class MergeError(ValueError):
    """A merge cannot be produced under the requested strictness
    (a comparability-key mismatch under --strict)."""


# --- loading ---------------------------------------------------------------------


def _load_json(path: Path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _resolve_run_dir(run_dir: str, manifest_path: Path) -> Path | None:
    """Resolve a run entry's recorded run_dir onto disk. The recorded path
    is out_root-relative at execution time; a results tree may have been
    moved, so the ladder tries: the path as recorded, out_root (the
    manifest's parent's parent) + the path, out_root + the run dir's name,
    and the manifest's own dir + the name. None when nothing resolves —
    the cell keeps its provenance with a note, never silently dropped."""
    p = Path(run_dir)
    candidates = [p] if p.is_absolute() else [
        p,
        manifest_path.parent.parent / p,
        manifest_path.parent.parent / p.name,
        manifest_path.parent / p.name,
    ]
    for c in candidates:
        if c.is_dir():
            return c
    return None


def _harness_major_version(manifest: dict, harness: str) -> str:
    version = ((manifest.get("plugin_versions") or {}).get(harness)
               or {}).get("version") or "unknown"
    return str(version).split(".")[0]


def _reconciliation_profile(run: dict, run_dir: Path | None,
                            harness: str) -> tuple[str, str]:
    """The profile id + version the run reconciled under: the run record's
    `profile` field when the run dir resolves, else the repo's pinned
    profile for the harness (runner/profiles/<harness>.yaml — the only
    registered profile, deterministic for a moved/absent run dir)."""
    if run_dir is not None:
        record = _load_json(run_dir / "run-record.json")
        if isinstance(record, dict) and record.get("profile"):
            return str(record["profile"]), "run-record"
    profile_path = REPO_ROOT / "runner" / "profiles" / f"{harness}.yaml"
    try:
        profile = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
        return str(profile.get("profile", "unknown")), "repo-profile"
    except OSError:
        return "unknown", "unavailable"


def _load_capabilities(plugin_id: str) -> dict | None:
    path = REPO_ROOT / "plugins" / plugin_id / "manifest.json"
    doc = _load_json(path)
    return doc if isinstance(doc, dict) else None


# --- per-run assembly ---------------------------------------------------------------


# DESIGN.md 10: "summary rows are recomputed at report level and labeled
# derived; summary rows and aggregate badges take the worst contributing
# class". Worst-first ranking of the evidence classes (DESIGN.md 9): derived
# (a claim-based recomputation with no kernel corroboration) is weakest, then
# self-reported (the degraded mode), then exerciser-run, then harness-run.
# An unknown class ranks worst (conservative: never upgrade what is not
# understood).
EVIDENCE_CLASS_WORST_FIRST = ("derived", "self-reported", "exerciser-run",
                              "harness-run")


def _worst_evidence_class(classes) -> str | None:
    """The worst contributing evidence class (DESIGN.md 10)."""
    def rank(cls):
        try:
            return EVIDENCE_CLASS_WORST_FIRST.index(cls)
        except ValueError:
            return -1   # unknown classes rank worst, conservatively
    present = [c for c in classes if c]
    return min(present, key=rank) if present else None


def _summary_rows(columns) -> list[dict]:
    """One derived summary row per design of a grid (DESIGN.md 10): sums of
    the contributing rows' outcome counts only — never averaging, never
    upgrading an evidence class — with the worst contributing class as the
    row's evidence class and the derived label. Off-matrix columns never
    contribute (they render in the extension section only); a design with
    no on-matrix column stays untested (untested cells are marked untested,
    not derived)."""
    by_design: dict[str, list] = {}
    for col in columns:
        by_design.setdefault(col["design"], []).append(col)
    rows = []
    for design, cols in by_design.items():
        counts: dict[str, int] = {}
        per_class: dict[str, dict[str, int]] = {}
        contributing = []
        classes = []
        for col in cols:
            for row in col["rows"]:
                cls = row.get("evidence_class")
                classes.append(cls)
                contributing.append({"control": col["control"],
                                     "design": design,
                                     "run_id": row.get("run_id"),
                                     "evidence_class": cls})
                oc = row.get("outcome_counts") or {}
                for outcome, n in (oc.get("counts") or {}).items():
                    counts[outcome] = counts.get(outcome, 0) + (n or 0)
                for action_class, outcomes in (oc.get("per_class")
                                              or {}).items():
                    tgt = per_class.setdefault(action_class, {})
                    for outcome, n in outcomes.items():
                        tgt[outcome] = tgt.get(outcome, 0) + (n or 0)
        rows.append({
            "design": design,
            "derived": True,
            "label": "derived",
            "evidence_class": _worst_evidence_class(classes),
            "outcome_counts": {"counts": counts, "per_class": per_class},
            "contributing": contributing,
            "note": ("report-level recomputation (DESIGN.md 10): sums of "
                      "the contributing rows' outcome counts only (never "
                      "averaged, never upgraded); the evidence class is "
                      "the worst contributing class"),
        })
    return rows


def _run_key(run: dict, manifest: dict, run_dir: Path | None,
             semantics: str, profile: str) -> dict:
    return {
        "workload_sha256": run.get("spec_sha256"),
        "harness": run.get("harness"),
        "harness_major_version": _harness_major_version(
            manifest, run.get("harness")),
        "kernel_sensor_version": (manifest.get("sensor") or {}).get("version"),
        "reconciliation_profile": profile,
        "classification_semantics": semantics,
    }


def _outcome_counts(run: dict, outcomes: dict | None) -> dict | None:
    """Per-action-class outcome counts + totals for one cell. Derived from
    the run's outcomes.json (never recomputed beyond counting), with the
    run summary's recorded claim-preserving fields (verified /
    prevented_unverified, DESIGN.md 9) overlaid unchanged — a
    self-reported run's claimed-only marking is preserved at report
    level, never upgraded and never dropped."""
    result: dict = {}
    if isinstance(outcomes, dict):
        per_class: dict[str, dict[str, int]] = {}
        for row in outcomes.get("per_action") or []:
            per_class.setdefault(row.get("class", "?"), {}).setdefault(
                row.get("outcome", "?"), 0)
            per_class[row.get("class", "?")][row.get("outcome", "?")] += 1
        result = {"schema": outcomes.get("schema"),
                  "counts": outcomes.get("counts"),
                  "per_class": per_class}
    recorded = run.get("outcome_counts")
    if isinstance(recorded, dict):
        for key in ("counts", "schema", "verified", "per_class",
                    "prevented_unverified"):
            if key in recorded:
                result[key] = recorded[key]
    return result or None


def _untested_designs(control, covered: set, harness: str) -> dict:
    """Designs the control's (or, for control:null, the harness's intrinsic
    surface's) manifest supports that no run in this grid covered — listed
    untested, not omitted, not derived (DESIGN.md 10)."""
    if control is None:
        harness_manifest = _load_capabilities(harness) or {}
        supported = {d for d in (harness_manifest.get("supported_designs") or [])
                     if d in NULL_CONTROL_DESIGNS}
        source = f"harness {harness!r} supported t-modes (control: null)"
    else:
        manifest = _load_capabilities(control) or {}
        supported = set(manifest.get("supported_designs") or [])
        source = f"control {control!r} capability manifest"
    return {"source": source,
            "supported": sorted(supported),
            "covered": sorted(covered),
            "untested": sorted(supported - covered)}


# --- the merge ---------------------------------------------------------------------


def merge_reports(execution_manifest_paths, *, strict: bool = False,
                  allow_incomparable: bool = False) -> dict:
    """Merge execution.json manifests into report-level grids (DESIGN.md 10).

    execution_manifest_paths: paths to <out-root>/<experiment-id>/
    execution.json (each contributes its runs). strict: hard-fail (raise
    MergeError) on any comparability-key or fixture-fingerprint mismatch.
    allow_incomparable: force a single grid even on key mismatch, marking
    the affected cells non-comparable (visible per cell); without it, runs
    whose keys mismatch form separate grid sections.

    Returns the merged report (JSON contract, schema 1): grids -> columns
    (one per control x design) -> evidence rows (one per run; collisions
    keep all rows with a recency mark), with per-class outcome counts,
    preserved evidence classes, degraded reasons, origin labels, untested
    designs, embedded manifests, and warnings. Never averages, never
    upgrades an evidence class, never drops provenance.
    """
    paths = [Path(p) for p in execution_manifest_paths]
    warnings: list[str] = []

    # --- collect runs ----------------------------------------------------------------
    collected = []   # (manifest_path, manifest, run entry, extras)
    for mp in paths:
        manifest = _load_json(mp)
        if not isinstance(manifest, dict) or not manifest.get("runs"):
            warnings.append(f"{mp}: no execution manifest or no runs; skipped")
            continue
        for run in manifest["runs"]:
            run_dir = _resolve_run_dir(run.get("run_dir", ""), mp)
            if run_dir is None:
                warnings.append(
                    f"{mp.name}: run {run.get('run_id')!r}: run dir "
                    f"{run.get('run_dir')!r} does not resolve; the cell keeps "
                    f"its provenance with outcome/run-manifest fields absent")
            outcomes = (_load_json(run_dir / "outcomes.json")
                        if run_dir is not None else None)
            run_manifest = (_load_json(run_dir / "manifest.json")
                            if run_dir is not None else None)
            semantics = ((outcomes or {}).get("schema")
                         or CLASSIFICATION_SEMANTICS)
            if run_dir is not None and outcomes is None:
                warnings.append(
                    f"{mp.name}: run {run.get('run_id')!r}: no outcomes.json "
                    f"under {run_dir}; outcome counts absent (not derived)")
            profile, profile_source = _reconciliation_profile(
                run, run_dir, run.get("harness"))
            collected.append({
                "manifest_path": mp,
                "manifest": manifest,
                "run": run,
                "run_dir": run_dir,
                "outcomes": outcomes,
                "run_manifest": run_manifest,
                "semantics": semantics,
                "profile": profile,
                "profile_source": profile_source,
            })

    # --- group by the comparability key ------------------------------------------------
    groups: dict[tuple, list] = {}
    for item in collected:
        key = _run_key(item["run"], item["manifest"], item["run_dir"],
                       item["semantics"], item["profile"])
        groups.setdefault(_key_tuple(key), []).append((key, item))

    grid_keys = list(groups)
    if strict and len(grid_keys) > 1:
        mismatched = [c for c in KEY_COMPONENTS
                      if len({dict(zip(KEY_COMPONENTS, gt))[c]
                              for gt in grid_keys}) > 1]
        raise MergeError(
            f"strict merge: the inputs split into {len(grid_keys)} grids on "
            f"the comparability key (DESIGN.md 10); mismatching "
            f"components: {mismatched}")

    # forced single grid (allow_incomparable): rows whose key differs from
    # the first grid's key are marked non-comparable per cell (visible)
    if allow_incomparable and len(grid_keys) > 1:
        reference_key = groups[grid_keys[0]][0][0]
        for gt in list(grid_keys[1:]):
            for key, item in groups[gt]:
                reasons = [f"{c}: {key[c]} != {reference_key[c]}"
                           for c in KEY_COMPONENTS if key[c] != reference_key[c]]
                item["_non_comparable"] = reasons
                groups[grid_keys[0]].append((key, item))
            del groups[gt]
        grid_keys = [grid_keys[0]]

    # --- grids -----------------------------------------------------------------------
    grids = []
    for gt in grid_keys:
        entries = groups[gt]
        grid_key = dict(entries[0][0])
        columns: dict[tuple, dict] = {}
        order: list[tuple] = []
        for _, item in entries:
            run = item["run"]
            col_key = (run.get("control"), run.get("design"))
            if col_key not in columns:
                columns[col_key] = {"control": run.get("control"),
                                    "design": run.get("design"),
                                    "control_binding": run.get(
                                        "control_binding"),
                                    "origin_labels": ORIGIN_LABELS.get(
                                        run.get("design"), []),
                                    "off_matrix": bool(run.get("off_matrix")),
                                    "fixture_fingerprint": run.get(
                                        "fixture_fingerprint"),
                                    "rows": []}
                order.append(col_key)
            columns[col_key]["rows"].append(item)

        # Fixture fingerprints must agree WITHIN a column and ACROSS the
        # columns of one design (DESIGN.md 10: the comparability key includes
        # the fixture fingerprint incl. enforcement_config — "without it,
        # comparisons between controls are unreliable"; fixture identity is
        # per-design, so the check is per design).
        by_design: dict[str, list[tuple[str, list]]] = {}
        for col in columns.values():
            prints = {json.dumps(r["run"].get("fixture_fingerprint"),
                                 sort_keys=True) for r in col["rows"]}
            by_design.setdefault(col["design"], []).append(
                (col["control"], prints, col["rows"]))
            if len(prints) > 1:
                if strict:
                    raise MergeError(
                        f"strict merge: column control="
                        f"{col['control']!r} design={col['design']!r} has "
                        f"runs with differing fixture fingerprints "
                        f"(DESIGN.md 10 comparability key)")
                for row in col["rows"]:
                    row.setdefault("_non_comparable", []).append(
                        "fixture-fingerprint-mismatch (the column's runs "
                        "disagree on fixture identity incl. "
                        "enforcement_config; DESIGN.md 10)")
        for design, cols in by_design.items():
            union = set().union(*(p_ for _, p_, _ in cols))
            if len(union) > 1:
                reason = ("cross-control fixture mismatch: design "
                          f"{design!r} columns disagree on fixture identity "
                          "(different reference rigs or enforcement_config; "
                          "DESIGN.md 10: comparisons between controls are "
                          "unreliable)")
                if strict:
                    raise MergeError(f"strict merge: {reason}")
                for _, _, rows in cols:
                    for row in rows:
                        row.setdefault("_non_comparable", []).append(reason)

        # collisions keep every row, recency-mark one current; never average
        for col in columns.values():
            ranked = sorted(
                col["rows"],
                key=lambda it: (executed_at(it),))
            newest = max(range(len(ranked)),
                         key=lambda i: (executed_at(ranked[i]), i))
            for i, row in enumerate(ranked):
                row["_current"] = (i == newest)

        # the column context: designs the manifest supports but no run
        # covered, listed untested (never omitted, never derived)
        untested = {}
        for col in columns.values():
            untested_key = (col["control"]
                             or f"null:{grid_key['harness']}")
            covered = {c["design"] for c in columns.values()
                       if c["control"] == col["control"]}
            if untested_key not in untested:
                untested[untested_key] = _untested_designs(
                    col["control"], covered, grid_key["harness"])

        # vendor-overlap flags (DESIGN.md 10). LIMITATION: there are no
        # vendor ids beyond plugin ids today — flag only the same-plugin-id
        # case (control and harness plugin ids equal); a real vendor
        # registry replaces this check.
        vendor_overlap = [
            {"control": c["control"], "harness": grid_key["harness"],
             "flag": "same-plugin-id (vendor ids beyond plugin ids do not "
                     "exist yet; see framework/report.py)"}
            for c in columns.values()
            if c["control"] is not None and c["control"] == grid_key["harness"]]

        grid_columns = []
        extension_columns = []
        for col_key in order:
            col = columns[col_key]
            rows = [_evidence_row(item) for item in col["rows"]]
            column = {"control": col["control"],
                      "design": col["design"],
                      "control_binding": col["control_binding"],
                      "origin_labels": col["origin_labels"],
                      "off_matrix": col["off_matrix"],
                      "fixture_fingerprint": col["fixture_fingerprint"],
                      "rows": rows}
            # DESIGN.md 10: off-matrix columns render in an extension
            # section (labels preserved); they never enter rollups (none
            # are computed at report level in this pass)
            (extension_columns if col["off_matrix"] else grid_columns
             ).append(column)
        grids.append({"key": grid_key, "_entry_keys": [e[0] for e in entries],
                      "columns": grid_columns,
                      "summary_rows": _summary_rows(grid_columns),
                      "extension_columns": extension_columns,
                      "untested": untested,
                      "vendor_overlap": vendor_overlap})

    if len(grids) > 1:
        all_keys = [k for g in grids for k in g.get("_entry_keys", [])]
        split_reasons = sorted({
            c for c in KEY_COMPONENTS
            if len({json.dumps(dict(k).get(c), sort_keys=True,
                                default=str)
                    for k in all_keys}) > 1
        })
        warnings.append(
            "runs split into "
            f"{len(grids)} grids on the comparability key "
            f"(differing components: {', '.join(split_reasons)}; DESIGN.md "
            "10: cross-version merges are allowed when the "
            "classification-semantics version matches, marked otherwise)")

    return {
        "schema": 1,
        "created": now_rfc3339_ms(),
        "comparability_key_components": list(KEY_COMPONENTS),
        "inputs": [{"path": str(mp),
                    "manifest": (next(i["manifest"] for i in collected
                                      if i["manifest_path"] == mp)
                                 if any(i["manifest_path"] == mp
                                        for i in collected) else None)}
                   for mp in paths],
        "grids": grids,
        "warnings": warnings,
    }


def _key_tuple(key: dict) -> tuple:
    return tuple(key[c] for c in KEY_COMPONENTS)


def executed_at(item: dict) -> str:
    """Row recency input: the run's own manifest creation time, falling
    back to its execution manifest's (ties are broken deterministically by
    input order in the collision handling)."""
    if isinstance(item.get("run_manifest"), dict):
        created = item["run_manifest"].get("created")
        if created:
            return str(created)
    return str((item["manifest"] or {}).get("created") or "")


def _evidence_row(item: dict) -> dict:
    """One run's evidence row: provenance (never dropped), preserved
    evidence class (never upgraded at report level), degraded reasons,
    decision-record count, outcome counts, and the non-comparable /
    recency marks (DESIGN.md 10)."""
    run = item["run"]
    row = {
        "run_id": run.get("run_id"),
        "run_dir": run.get("run_dir"),
        "executed_at": executed_at(item),
        "status": run.get("status"),
        "coverage": run.get("coverage", {}).get("status")
        if isinstance(run.get("coverage"), dict) else run.get("coverage"),
        "coverage_consistent": run.get("coverage_consistent"),
        "decision_record_count": (run.get("decision_records") or {}).get(
            "count"),
        # evidence class is preserved per cell, never upgraded
        "evidence_class": run.get("evidence_class"),
        "degraded": run.get("degraded") or [],
        "outcome_counts": _outcome_counts(run, item["outcomes"]),
        # provenance: the run's own manifest is embedded when it resolved
        "provenance": {
            "execution_manifest": str(item["manifest_path"]),
            "run_manifest": item["run_manifest"],
            "run_record": (str(item["run_dir"] / "run-record.json")
                           if item["run_dir"] is not None else None),
            "profile_source": item["profile_source"],
        },
        "findings": [f.get("id") for f in run.get("findings") or []],
        "current": item.get("_current", True),
    }
    if item.get("_non_comparable"):
        row["non_comparable"] = item["_non_comparable"]
    return row


# --- the human summary ----------------------------------------------------------------


def render_summary(report: dict) -> str:
    """A short human summary of the merged report: sections found, the
    per-grid column count, untested cells, non-comparable warnings
    (DESIGN.md 10; the JSON report remains the contract)."""
    grids = report.get("grids") or []
    lines = [f"merged report: {len(report.get('inputs') or [])} input "
             f"manifest(s), {len(grids)} grid section(s)"]
    total_untested = 0
    total_non_comparable = 0
    for i, grid in enumerate(grids, 1):
        key = grid.get("key") or {}
        lines.append(
            f"grid {i}: workload={str(key.get('workload_sha256'))[:12]}… "
            f"harness={key.get('harness')}/v{key.get('harness_major_version')} "
            f"sensor={key.get('kernel_sensor_version')} "
            f"profile={key.get('reconciliation_profile')} "
            f"semantics={key.get('classification_semantics')}")
        columns = grid.get("columns") or []
        lines.append(f"  columns: {len(columns)}")
        for col in columns:
            current = [r["run_id"] for r in col["rows"] if r.get("current")]
            lines.append(
                f"    - control={col['control']!r} design={col['design']} "
                f"origins={col['origin_labels']} rows={len(col['rows'])} "
                f"(current: {', '.join(current)})")
        for row in grid.get("summary_rows") or []:
            oc = row.get("outcome_counts") or {}
            counts = ", ".join(f"{k}={v}" for k, v in
                               sorted((oc.get("counts") or {}).items()))
            lines.append(
                f"    - [derived summary] design={row['design']} "
                f"evidence_class={row.get('evidence_class')} "
                f"counts: {counts or 'none'}")
        for col in grid.get("extension_columns") or []:
            lines.append(
                f"    - [off-matrix extension] control={col['control']!r} "
                f"design={col['design']} rows={len(col['rows'])}")
        for who, entry in (grid.get("untested") or {}).items():
            if entry.get("untested"):
                total_untested += len(entry["untested"])
                lines.append(f"  untested ({who}): "
                              f"{', '.join(entry['untested'])}")
        for col in columns + (grid.get("extension_columns") or []):
            for row in col["rows"]:
                if row.get("non_comparable"):
                    total_non_comparable += 1
                    lines.append(f"  non-comparable: run {row['run_id']} "
                                 f"({'; '.join(row['non_comparable'])})")
        for flag in grid.get("vendor_overlap") or []:
            lines.append(f"  vendor-overlap flag: control "
                         f"{flag['control']!r} == harness "
                         f"{flag['harness']!r} ({flag['flag']})")
    for warning in report.get("warnings") or []:
        lines.append(f"warning: {warning}")
    lines.append(f"totals: untested cells={total_untested}, "
                 f"non-comparable rows={total_non_comparable}")
    return "\n".join(lines)
