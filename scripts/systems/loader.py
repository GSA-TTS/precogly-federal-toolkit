"""System Directory Contract loader.

Discovers systems under ``data/systems/<slug>/system.yaml`` and exposes a
resolved :class:`SystemPaths` mapping every optional subtree to either a real
path on disk or ``None``.  All Example System sources now live in the per-system
directory (Phase B, PR #175); the loader therefore treats
``data/systems/<slug>/`` as the sole source of truth.  The only legacy
fallback preserved is the flat ``data/systems/<slug>.yaml`` sidecar shape,
because a handful of vault-imported systems still ship in that form.

Contract described in ``docs/IMPLEMENTATION_PLAN_generic_sspp_submodule.md``.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
DATA = ROOT / "data"
SYSTEMS_DIR = DATA / "systems"
SCHEMA_PATH = ROOT / "schemas-local" / "system-directory.schema.json"

# System that Phase A keeps as the implicit default so existing invocations of
# ``make generate`` / ``python scripts/generate.py`` stay byte-identical.
DEFAULT_SYSTEM = "example-system"


@dataclasses.dataclass(frozen=True)
class SystemPaths:
    """Fully-resolved on-disk paths for a system.

    Each field is either an existing :class:`Path` or ``None``.  Callers that
    strictly require a subtree should check for ``None`` and raise their own
    domain-specific error.
    """

    slug: str
    root: Path
    manifest: Path | None
    sidecar: Path | None
    leverage: Path | None
    crm_index: Path | None
    countermeasures: Path | None
    model_dfd: Path | None
    model_architecture: Path | None
    model_evidence: Path | None
    ideal_overlay: Path | None
    frr: Path | None
    ksi: Path | None
    seed: Path | None
    responses: Path | None
    redaction: Path | None

    def crm_source(self, name: str) -> Path | None:
        """Resolve a per-source CRM YAML (e.g. ``managed-cloud-service``, ``data-platform``)."""
        p = self.root / "crm" / f"{name}.yaml"
        return p if p.is_file() else None


def _first_existing(*candidates: Path) -> Path | None:
    for c in candidates:
        if c and c.is_file():
            return c
    return None


def _manifest_path(slug: str) -> Path:
    return SYSTEMS_DIR / slug / "system.yaml"


def load_system(slug: str) -> SystemPaths:
    """Return resolved paths for *slug*.

    Requires either a Phase-B per-system directory
    (``data/systems/<slug>/system.yaml``) or a legacy flat sidecar
    (``data/systems/<slug>.yaml``); otherwise :class:`FileNotFoundError` is
    raised.  Individual subtrees inside a resolved directory may still be
    absent — those fields simply resolve to ``None``.
    """

    root = SYSTEMS_DIR / slug
    manifest = _manifest_path(slug)

    # Sidecar can live at either the new per-system-directory path or as the
    # legacy flat file ``data/systems/<slug>.yaml``.
    sidecar = _first_existing(root / "sidecar.yaml", SYSTEMS_DIR / f"{slug}.yaml")
    leverage = _first_existing(
        root / "leverage.yaml", SYSTEMS_DIR / f"{slug}.leverage.yaml"
    )

    if not manifest.is_file() and not sidecar and slug != DEFAULT_SYSTEM:
        raise FileNotFoundError(
            f"Unknown system '{slug}': no manifest at {manifest} and no legacy "
            f"sidecar at {SYSTEMS_DIR / (slug + '.yaml')}"
        )

    crm_index = _first_existing(root / "crm" / "index.yaml")
    countermeasures = _first_existing(root / "countermeasures.yaml")
    model_dfd = _first_existing(root / "model" / "base-dfd.cdx.json")
    model_architecture = _first_existing(root / "model" / "architecture.yaml")
    model_evidence = _first_existing(root / "model" / "evidence.yaml")
    ideal_overlay = _first_existing(root / "ideal-state" / "overlay.yaml")
    frr = _first_existing(root / "frr.yaml")
    ksi = _first_existing(root / "ksi.yaml")
    seed = _first_existing(root / "seed.yaml")
    responses = _first_existing(root / "responses.yaml")
    redaction = _first_existing(root / "redaction.yaml")

    return SystemPaths(
        slug=slug,
        root=root,
        manifest=manifest if manifest.is_file() else None,
        sidecar=sidecar,
        leverage=leverage,
        crm_index=crm_index,
        countermeasures=countermeasures,
        model_dfd=model_dfd,
        model_architecture=model_architecture,
        model_evidence=model_evidence,
        ideal_overlay=ideal_overlay,
        frr=frr,
        ksi=ksi,
        seed=seed,
        responses=responses,
        redaction=redaction,
    )


def discover_systems() -> list[str]:
    """Return every slug that has a Phase-A manifest at data/systems/<slug>/system.yaml."""
    if not SYSTEMS_DIR.is_dir():
        return []
    slugs = []
    for entry in sorted(SYSTEMS_DIR.iterdir()):
        if entry.is_dir() and (entry / "system.yaml").is_file():
            slugs.append(entry.name)
    return slugs


def load_manifest(slug: str) -> dict[str, Any]:
    """Read a manifest and validate it if ``jsonschema`` is importable.

    Kept tolerant of missing ``jsonschema``: this module is imported by
    ``scripts/generate.py`` which runs under the plain ``uv run python``
    invocation without extras, and we do not want to force that runtime to grow
    a validation dependency just because callers happen to import the loader.
    """
    p = _manifest_path(slug)
    with p.open("r", encoding="utf-8") as f:
        manifest = yaml.safe_load(f) or {}
    _validate_manifest(manifest, source=p)
    return manifest


def _validate_manifest(manifest: dict[str, Any], *, source: Path) -> None:
    slug = manifest.get("slug")
    if slug and source.parent.name != slug:
        raise ValueError(
            f"manifest slug '{slug}' does not match directory '{source.parent.name}' "
            f"(source={source})"
        )
    if not SCHEMA_PATH.is_file():
        return
    try:
        import jsonschema  # type: ignore[import-not-found]
    except ImportError:
        return
    with SCHEMA_PATH.open("r", encoding="utf-8") as f:
        schema = json.load(f)
    jsonschema.validate(manifest, schema)


def _cli(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List systems that have a system.yaml manifest.")

    resolve = sub.add_parser(
        "resolve", help="Print resolved paths for one system as JSON."
    )
    resolve.add_argument("slug")

    validate = sub.add_parser(
        "validate", help="Validate one or all manifests against the schema."
    )
    validate.add_argument("slug", nargs="?")

    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.cmd == "list":
        for slug in discover_systems():
            print(slug)
        return 0

    if args.cmd == "resolve":
        paths = load_system(args.slug)
        out = {
            k: (str(v.relative_to(ROOT)) if isinstance(v, Path) and v else v)
            for k, v in dataclasses.asdict(paths).items()
        }
        json.dump(out, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0

    if args.cmd == "validate":
        slugs = [args.slug] if args.slug else discover_systems()
        errors = 0
        for slug in slugs:
            try:
                load_manifest(slug)
                print(f"OK    {slug}")
            except Exception as exc:
                errors += 1
                print(f"FAIL  {slug}: {exc}", file=sys.stderr)
        return 1 if errors else 0

    return 2


if __name__ == "__main__":
    raise SystemExit(_cli())
