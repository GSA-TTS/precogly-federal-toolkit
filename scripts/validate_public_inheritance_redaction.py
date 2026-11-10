#!/usr/bin/env python3
"""Reject universal redaction-policy violations in public inheritance artifacts."""

from __future__ import annotations

import sys
from pathlib import Path

try:
    from scripts.validate import FORBIDDEN
except ModuleNotFoundError:  # Support direct invocation from scripts/.
    from validate import FORBIDDEN

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_ARTIFACTS = (
    ROOT / "data" / "catalog" / "public-inheritance-profiles",
    ROOT / "data" / "catalog" / "public-inheritance-release-manifest.json",
    ROOT / "docs" / "analyses" / "public-ccc-inheritance-coverage.md",
    ROOT / "docs" / "templates" / "oscal-vault-pin-release-note.md",
)


def scan(path: Path) -> list[str]:
    """Return universal redaction-policy findings for one public artifact."""
    text = path.read_text(encoding="utf-8")
    return [
        f"{path}: unredacted {label}: {match.group(0)!r}"
        for pattern, label in FORBIDDEN
        for match in pattern.finditer(text)
    ]


def main() -> int:
    paths = [
        path
        for artifact in PUBLIC_ARTIFACTS
        for path in (sorted(artifact.glob("*.yaml")) if artifact.is_dir() else [artifact])
    ]
    findings = [finding for path in paths for finding in scan(path)]
    if findings:
        print("\n".join(findings), file=sys.stderr)
        return 1
    print(f"OK - {len(paths)} public inheritance artifact(s) pass universal redaction")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
