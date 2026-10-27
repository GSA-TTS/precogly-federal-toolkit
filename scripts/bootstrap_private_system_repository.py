#!/usr/bin/env python3
"""Validate a private system repository before local reconciliation checks run."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REQUIRED_SYSTEM_FILES = (
    "cui.yaml",
    "publication.yaml",
    "reconciliation-proposal.yaml",
)


def validate_layout(repository: Path, system_slug: str) -> list[str]:
    """Return layout errors without reading source documents or contacting a forge."""
    errors: list[str] = []
    system_dir = repository / "data" / "systems" / system_slug
    for name in _REQUIRED_SYSTEM_FILES:
        if not (system_dir / name).is_file():
            errors.append(
                f"missing required system artifact: data/systems/{system_slug}/{name}"
            )
    for name in ("vault", "evidence", "vendor/precogly-federal-toolkit"):
        if not (repository / name).is_dir():
            errors.append(f"missing required repository directory: {name}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("system_slug")
    parser.add_argument("--repository", default=".", type=Path)
    args = parser.parse_args()
    errors = validate_layout(args.repository.resolve(), args.system_slug)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("OK - private system repository layout is ready for local validation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
