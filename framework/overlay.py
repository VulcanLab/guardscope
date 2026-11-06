"""Slot descriptors and control-binding overlays (DESIGN.md 7: fixtures
bind plugins by capability into slots; a fixture with a control slot is a
placeholder base + a control-binding overlay).

Mechanism, per design:

- The BASE (compose/<design>.yaml, or compose/<design>-mock.yaml on the
  mock harness) carries the full design structure — networks, targets,
  harness services, sensor profile, the forced-egress jail where the
  design has one, the log volumes — with the slot DECLARED but the control
  service ABSENT. A base alone is not a validatable unit: its harness
  services `depends_on` the slot service, so `docker compose -f <base>
  config` fails loudly. Compose files stay pure compose: this compose
  version rejects unknown top-level keys (verified), so no `slots:` key.

- The SLOT DECLARATION lives in a framework-side sidecar the overlay
  validator reads: compose/slots/<design>.yaml (slot name, the compose
  service name the overlay must define, the slot's network, the env the
  base's harness services use to reach the slot, the decision-log volume,
  the deployed policy artifact). One descriptor per design; the mock
  fixture realizes the same slot on its own compose project.

- The OVERLAY is the control's binding bundle under the PLUGIN directory:
  plugins/<control>/overlay/<design>.yaml (or <design>-mock.yaml on the
  mock harness) — the service definition for the slot (image/build, env,
  log volume wiring) plus the binding files it references. The shipped
  AGT binding is expressed exactly this way; nothing in the framework is
  special-cased for it (DESIGN.md 2: no core code may behave differently
  depending on a plugin's identity).

- Merged bring-up is plain compose file merge (base FIRST — the overlay's
  relative build context resolves against the FIRST compose file's
  directory, so the base must precede the overlay):
    docker compose -f compose/t1.yaml -f plugins/agt-gateway/overlay/t1.yaml up -d

On-matrix rule (the structural check behind the off-matrix flag,
DESIGN.md 7: a structural change is a custom fixture): a control-binding
overlay (a) defines exactly the declared slot service, (b) may override
fields of that service, (c) may ADD auxiliary services only named
`control-*` attached to the slot's network or the slot service's netns,
and (d) must not remove or modify any base service. Violations are not
load-time errors: the run is flagged off_matrix (a custom fixture,
measured at full fidelity), with the problems recorded.
"""

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
COMPOSE_DIR = REPO_ROOT / "compose"
SLOTS_DIR = COMPOSE_DIR / "slots"

# DESIGN.md 8: the harness whose fixtures are compose/<design>-mock.yaml
# (their own compose projects, distinct container prefixes).
MOCK_HARNESS_ID = "mock-harness"

# The slot descriptor fields every declaration must carry; `policy` is
# nullable (t5 pins no separate gateway policy file).
_REQUIRED_SLOT_FIELDS = ("design", "slot", "kind", "service", "network",
                          "log_volume")


class OverlayError(ValueError):
    """A slot descriptor is missing or malformed (framework-side data)."""


class Slot:
    """The declared control slot of a design (compose/slots/<design>.yaml)."""

    def __init__(self, doc: dict, path: Path):
        self.doc = doc
        self.path = path

    @property
    def design(self) -> str:
        return self.doc["design"]

    @property
    def name(self) -> str:
        return self.doc["slot"]

    @property
    def service(self) -> str:
        return self.doc["service"]

    @property
    def network(self) -> str:
        return self.doc["network"]

    @property
    def log_volume(self) -> str:
        return self.doc["log_volume"]


def load_slot(design: str) -> Slot:
    """Load the design's slot descriptor (framework-side sidecar data; the
    compose bases stay pure compose). Raises OverlayError when the design
    has no descriptor (no control slot, or the sidecar is missing)."""
    path = SLOTS_DIR / f"{design}.yaml"
    if not path.is_file():
        raise OverlayError(
            f"no slot descriptor for design {design!r} at {path} (the "
            f"design declares no control slot, or the sidecar is missing)")
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(doc, dict):
        raise OverlayError(f"{path}: not a mapping at the top level")
    missing = [f for f in _REQUIRED_SLOT_FIELDS if f not in doc]
    if missing:
        raise OverlayError(f"{path}: missing slot fields {missing}")
    if doc.get("design") != design:
        raise OverlayError(
            f"{path}: declares design {doc.get('design')!r}, not {design!r}")
    return Slot(doc, path)


def has_slot(design: str) -> bool:
    """Whether the design declares a control slot (a slot descriptor
    exists under compose/slots/)."""
    try:
        load_slot(design)
        return True
    except OverlayError:
        return False


def base_compose_name(design: str, harness: str) -> str:
    """The base compose file realizing the design for this harness: the
    mock harness runs compose/<design>-mock.yaml (its own project), the
    real harnesses run compose/<design>.yaml."""
    return (f"{design}-mock.yaml" if harness == MOCK_HARNESS_ID
            else f"{design}.yaml")


def base_compose_path(design: str, harness: str) -> Path:
    return COMPOSE_DIR / base_compose_name(design, harness)


def overlay_rel_path(control: str, design: str, harness: str) -> str:
    """The repo-relative path of the control's binding overlay for this
    design+harness (the overlay bundle lives under the plugin directory).
    The mock fixture's overlay is the <design>-mock variant."""
    name = base_compose_name(design, harness)
    return f"plugins/{control}/overlay/{name}"


def overlay_abs_path(rel_path: str):
    """Resolve a repo-relative `plugins/<id>/...` path against the plugin
    directory (framework/contracts.PLUGINS_DIR — the single source of truth
    the manifest loader uses, so tests can point it at a scratch tree)."""
    from framework import contracts
    if not rel_path.startswith("plugins/"):
        raise OverlayError(f"not a plugin-relative path: {rel_path!r}")
    return contracts.PLUGINS_DIR / rel_path[len("plugins/"):]


def validate_overlay(design: str, overlay_path,
                     base_path=None, harness: str | None = None
                     ) -> tuple[bool, list[str]]:
    """The on-matrix rule (DESIGN.md 7), as a structural check of one
    control-binding overlay against the design's slot declaration:

    (a) the overlay defines exactly the declared slot service (it may
        override fields of that service — the base defines none of them);
    (b) auxiliary services are allowed only under the name `control-*`,
        and only attached to the slot's network or the slot service's
        netns;
    (c) the overlay must not remove or modify any base service (compose
        merge cannot remove a service; redeclaring a base service here is
        the modification);
    (d) the overlay carries no other top-level structure (the base owns
        networks, volumes, and the rest).

    Returns (ok, problems). Violations are NOT raised: the caller flags
    the run off_matrix (a custom fixture, DESIGN.md 7: the flag controls
    grid placement, not measurement or publication).
    """
    problems: list[str] = []
    path = Path(overlay_path)
    if not path.is_file():
        return False, [f"no overlay file at {path}"]
    try:
        slot = load_slot(design)
    except OverlayError as exc:
        return False, [str(exc)]

    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return False, [f"{path}: not parseable YAML: {exc}"]
    if not isinstance(doc, dict):
        return False, [f"{path}: not a compose document (top-level "
                       f"mapping expected)"]

    # (d) the base owns every top-level key except services
    extra = sorted(k for k in doc if k != "services")
    if extra:
        problems.append(
            f"modifies base structure: top-level key(s) {extra} (the "
            f"overlay may only add services)")
    services = doc.get("services") or {}
    if not isinstance(services, dict):
        return False, problems + [
            f"{path}: 'services' is not a mapping"]

    # (a) the declared slot service
    if slot.service not in services:
        problems.append(
            f"does not define the declared slot service {slot.service!r} "
            f"(slot {slot.name!r} of design {design}; declared in "
            f"{slot.path})")
    else:
        svc = services[slot.service] or {}
        if "image" not in svc and "build" not in svc:
            problems.append(
                f"slot service {slot.service!r} defines neither image nor "
                f"build")
        # kernel slots (DESIGN.md 3 'eBPF-enforcing controls'; slot kind
        # introduced with the T7 fixture): the control enforces
        # from the HOST KERNEL, so the slot service must be privileged and
        # share the host pid namespace — anything less cannot reach the
        # kernel enforcement surface, and the violation is a custom-fixture
        # problem, not a load error
        if (slot.doc.get("kind") == "kernel"
                and not svc.get("privileged")):
            problems.append(
                f"kernel slot service {slot.service!r} must set "
                f"privileged: true (host-kernel enforcement surface)")
        if (slot.doc.get("kind") == "kernel"
                and svc.get("pid") != "host"):
            problems.append(
                f"kernel slot service {slot.service!r} must set pid: host "
                f"(it watches the harness containers' host-side process "
                f"trees)")

    # (b)/(c) every other service: auxiliary control-* on the slot's
    # network/netns, or a violation
    for name in sorted(services):
        if name == slot.service:
            continue
        svc = services[name] or {}
        if name.startswith("control-"):
            nets = svc.get("networks") or []
            if slot.network not in nets and \
                    svc.get("network_mode") != f"service:{slot.service}":
                problems.append(
                    f"auxiliary service {name!r} must attach to the slot's "
                    f"network {slot.network!r} or the slot service's netns "
                    f"(service:{slot.service})")
        else:
            problems.append(
                f"undeclared service {name!r}: only the slot service "
                f"{slot.service!r} and auxiliary 'control-*' services are "
                f"allowed")

    # (c) no base service may be touched
    if base_path is None:
        base_path = base_compose_path(design, harness or "pi")
    base_path = Path(base_path)
    if base_path.is_file():
        base_doc = yaml.safe_load(base_path.read_text(encoding="utf-8")) or {}
        touched = sorted(set(services) & set(base_doc.get("services") or {}))
        if touched:
            problems.append(
                f"modifies base service(s) {touched}: the overlay must not "
                f"remove or modify any base service")

    return (not problems), problems
