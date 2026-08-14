#!/usr/bin/env python3
"""Validate every `build/systems/*/fedramp-*.json` against the local CR26
schemas in `schemas/`.

Uses `referencing` to resolve the `https://fedramp.gov/schemas/…` cross-schema
`$ref`s off-line by mapping them to the local file paths.

Exit non-zero on any failure. Prints one line per artifact.

Usage:
    uv run --with jsonschema,referencing python scripts/validate_fedramp.py
    uv run --with jsonschema,referencing python scripts/validate_fedramp.py --strict
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012
except ImportError:  # pragma: no cover
    sys.exit(
        "jsonschema+referencing not installed — run:\n"
        "  uv run --with jsonschema,referencing python scripts/validate_fedramp.py"
    )

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMAS_DIR = REPO_ROOT / "schemas"
BUILD_SYSTEMS = REPO_ROOT / "build" / "systems"

SENTINEL_RE = re.compile(r"\bTBD\b|tbd\.example\.gov|555-555-5555", re.IGNORECASE)

# Map filename stem prefix → FedRAMP schema filename in schemas/.
DISPATCH = {
    "fedramp-cpo": "fedramp-certification-package-overview-schema-2026-06-24.json",
    "fedramp-sdr": "fedramp-security-decision-record-schema-2026-06-24.json",
    "fedramp-ocr": "fedramp-ongoing-certification-report-schema-2026-06-24.json",
    "fedramp-incident": "fedramp-incident-report-schema-2026-06-24.json",
    "fedramp-scn": "fedramp-significant-change-notifications-schema-2026-06-24.json",
    "fedramp-vdr": "fedramp-vulnerability-detail-report-schema-2026-06-24.json",
    "fedramp-avi": "fedramp-accepted-vulnerability-info-schema-2026-06-24.json",
    "fedramp-mrh": "fedramp-historical-ver-activity-schema-2026-06-24.json",
}


def build_registry() -> Registry:
    resources = []
    for path in sorted(SCHEMAS_DIR.glob("fedramp-*.json")):
        with path.open() as fh:
            schema = json.load(fh)
        uri = schema.get("$id") or f"https://fedramp.gov/schemas/{path.name}"
        resources.append((uri, Resource(contents=schema, specification=DRAFT202012)))
    return Registry().with_resources(resources)


def dispatch(path: Path) -> str | None:
    for prefix, schema_file in DISPATCH.items():
        if path.name.startswith(prefix):
            return schema_file
    return None


def _walk_strings(node, path):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk_strings(v, path + [str(k)])
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk_strings(v, path + [str(i)])
    elif isinstance(node, str):
        yield "/".join(path), node


def find_sentinels(instance) -> list[str]:
    hits = []
    for loc, s in _walk_strings(instance, []):
        m = SENTINEL_RE.search(s)
        if m:
            hits.append(f"  {loc}: sentinel {m.group(0)!r} in {s!r}")
    return hits


def validate_one(artifact_path: Path, registry: Registry, strict: bool) -> list[str]:
    schema_file = dispatch(artifact_path)
    if schema_file is None:
        return [f"unrecognized artifact filename (expected fedramp-<kind>-*.json)"]
    schema_path = SCHEMAS_DIR / schema_file
    if not schema_path.exists():
        return [f"schema not found: {schema_path.relative_to(REPO_ROOT)}"]
    with schema_path.open() as fh:
        schema = json.load(fh)
    with artifact_path.open() as fh:
        instance = json.load(fh)
    validator = Draft202012Validator(schema, registry=registry)
    errors = []
    for err in sorted(validator.iter_errors(instance), key=lambda e: list(e.absolute_path)):
        loc = "/".join(str(x) for x in err.absolute_path) or "<root>"
        errors.append(f"  {loc}: {err.message}")
    if strict:
        errors.extend(find_sentinels(instance))
    return errors


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--strict",
        action="store_true",
        help="also reject TBD sentinels (submission-readiness gate)",
    )
    args = p.parse_args()

    if not BUILD_SYSTEMS.exists():
        print(f"nothing to validate — {BUILD_SYSTEMS.relative_to(REPO_ROOT)} does not exist")
        return 0

    registry = build_registry()
    artifacts = sorted(BUILD_SYSTEMS.glob("*/fedramp-*.json"))
    if not artifacts:
        print("no FedRAMP artifacts found under build/systems/*/fedramp-*.json")
        return 0

    total, failed = 0, 0
    for path in artifacts:
        total += 1
        errors = validate_one(path, registry, args.strict)
        rel = path.relative_to(REPO_ROOT)
        if errors:
            failed += 1
            print(f"FAIL {rel}")
            for line in errors:
                print(line)
        else:
            print(f"ok   {rel}")

    mode = "strict" if args.strict else "schema-only"
    print(f"\nvalidated {total} artifact(s) [{mode}]; {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
