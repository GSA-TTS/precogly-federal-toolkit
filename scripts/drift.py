#!/usr/bin/env python3
"""Drift detection + reinjection guard for the version-controlled CRM
threat-model CycloneDX artifact.

The build artifact (build/example-system-crm-threat-model.cdx.json) is git-versioned: a
user opens it in the Precogly editor, edits, and saves back to the SAME file so
changes are tracked in git. But the CRM threats/controls are GENERATED from the
YAML data sources. If a user edits a generated entity in the editor (or the YAML
changes) the artifact can drift from what the generators would produce.

This script regenerates into a temp buffer and diffs the *generated* entities
(threats, scenarios, controls) between the on-disk artifact and a fresh build,
IGNORING volatile fields (serialNumber, version, metadata.timestamp) and
IGNORING user-owned DFD edits carried in base-dfd.cdx.json.

Modes:
  --check   (default) exit 1 and print a drift report if generated entities
            differ. Use in CI / pre-commit.
  --reinject  overwrite the artifact with a fresh generation (re-applies the
            YAML source of truth). Use when drift is a stray editor edit you
            want to discard. DFD edits should first be exported to
            base-dfd.cdx.json (see README round-trip).

Requires PyYAML (run via `uv run`).
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ARTIFACT = os.path.join(ROOT, "build", "example-system-crm-threat-model.cdx.json")
GENERATE = os.path.join(HERE, "generate.py")

if HERE not in sys.path:
    sys.path.insert(0, HERE)

from systems.loader import DEFAULT_SYSTEM  # noqa: E402

# Volatile top-level fields we never diff (change on every regeneration).
VOLATILE_TOP = {"serialNumber", "version"}


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def generated_view(doc):
    """Extract only the generator-owned entities, normalized for comparison.

    We compare threats, scenarios, and controls by bom-ref. Metadata timestamp
    and doc-level volatile fields are excluded. The DFD (blueprints) is NOT
    compared here because it is user-owned via base-dfd.cdx.json.
    """

    def index(items):
        return {it["bom-ref"]: it for it in items}

    th = doc.get("threats", {})
    return {
        "threats": index(th.get("threats", [])),
        "scenarios": index(th.get("scenarios", [])),
        "controls": index(doc.get("controls", [])),
    }


def diff_section(name, current, fresh):
    """Return a list of human-readable drift lines for one entity section."""
    lines = []
    cur_keys, fresh_keys = set(current), set(fresh)
    for ref in sorted(fresh_keys - cur_keys):
        lines.append(f"  [{name}] MISSING in artifact (generator adds): {ref}")
    for ref in sorted(cur_keys - fresh_keys):
        lines.append(f"  [{name}] EXTRA in artifact (not produced by generator): {ref}")
    for ref in sorted(cur_keys & fresh_keys):
        if current[ref] != fresh[ref]:
            lines.append(f"  [{name}] MODIFIED vs generator source: {ref}")
    return lines


def main():
    ap = argparse.ArgumentParser()
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        default=True,
        help="report drift and exit non-zero (default)",
    )
    mode.add_argument(
        "--reinject",
        action="store_true",
        help="regenerate the artifact from YAML source of truth",
    )
    ap.add_argument("--artifact", default=ARTIFACT)
    ap.add_argument(
        "--system",
        default=DEFAULT_SYSTEM,
        help="System slug to forward to generate.py (default: %(default)s).",
    )
    args = ap.parse_args()

    if args.reinject:
        # Regenerate straight over the versioned artifact.
        subprocess.run(
            [sys.executable, GENERATE, "--system", args.system, "--out", args.artifact],
            check=True,
        )
        print(
            f"Reinjected: {os.path.relpath(args.artifact, ROOT)} rebuilt "
            "from YAML source of truth.",
            file=sys.stderr,
        )
        print(
            "Review `git diff` and commit if the change is intended.", file=sys.stderr
        )
        return

    # --check: build fresh into a temp file, diff generated entities.
    if not os.path.exists(args.artifact):
        print(f"FAIL: artifact not found: {args.artifact}", file=sys.stderr)
        sys.exit(1)

    with tempfile.NamedTemporaryFile(suffix=".cdx.json", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        subprocess.run(
            [sys.executable, GENERATE, "--system", args.system, "--out", tmp_path],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        current = generated_view(load(args.artifact))
        fresh = generated_view(load(tmp_path))
    finally:
        os.unlink(tmp_path)

    drift = []
    for section in ("threats", "scenarios", "controls"):
        drift += diff_section(section, current[section], fresh[section])

    if drift:
        print(
            "DRIFT DETECTED between the versioned artifact and the YAML "
            "source of truth:",
            file=sys.stderr,
        )
        print("\n".join(drift), file=sys.stderr)
        print("\nResolve by either:", file=sys.stderr)
        print(
            "  - export DFD edits to data/model/base-dfd.cdx.json, or", file=sys.stderr
        )
        print(
            "  - fold intended changes into the YAML data sources, then",
            file=sys.stderr,
        )
        print("    run: make reinject", file=sys.stderr)
        print(
            "  (a stray editor edit to a generated entity is discarded by reinject.)",
            file=sys.stderr,
        )
        sys.exit(1)

    print("OK - no drift; versioned artifact matches the YAML source of truth.")


if __name__ == "__main__":
    main()
