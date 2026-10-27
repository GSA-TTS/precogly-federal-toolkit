#!/usr/bin/env python3
"""Validate the complete local publication-to-reconciliation evidence chain."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scripts.validate_publication_contracts import validate_manifest  # noqa: E402
from scripts.validate_reconciliation_evidence import validate_evidence  # noqa: E402
from scripts.validate_reconciliation_proposals import validate_proposal  # noqa: E402

SYSTEMS_DIR = REPO / "data" / "systems"


def _load(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text()) or {}


def missing_evidence(proposal_ids: set[str], evidence_ids: set[str]) -> set[str]:
    """Return validated proposal IDs that lack a recorded decision."""
    return proposal_ids - evidence_ids


def validate_chain(
    systems_dir: Path = SYSTEMS_DIR, repository: Path = REPO
) -> list[str]:
    errors: list[str] = []
    proposal_paths: dict[str, Path] = {}
    evidence_paths: dict[str, Path] = {}
    for system_dir in sorted(systems_dir.iterdir()):
        if not system_dir.is_dir():
            continue
        publication = system_dir / "publication.yaml"
        proposal = system_dir / "reconciliation-proposal.yaml"
        if publication.exists():
            errors.extend(validate_manifest(publication, repository=repository))
        if proposal.exists():
            errors.extend(validate_proposal(proposal, repository=repository))
            proposal_id = _load(proposal).get("proposal_id")
            if isinstance(proposal_id, str):
                if proposal_id in proposal_paths:
                    errors.append(f"{proposal}: duplicate proposal ID {proposal_id}")
                proposal_paths[proposal_id] = proposal
        for evidence in sorted((system_dir / "reconciliation-evidence").glob("*.yaml")):
            errors.extend(validate_evidence(evidence, repository=repository))
            proposal_id = _load(evidence).get("proposal_id")
            if isinstance(proposal_id, str):
                if proposal_id in evidence_paths:
                    errors.append(
                        f"{evidence}: duplicate decision evidence for {proposal_id}"
                    )
                elif proposal_id not in proposal_paths:
                    errors.append(
                        f"{evidence}: decision evidence references unknown proposal {proposal_id}"
                    )
                evidence_paths[proposal_id] = evidence
    for proposal_id in sorted(
        missing_evidence(set(proposal_paths), set(evidence_paths))
    ):
        errors.append(
            f"reconciliation proposal {proposal_id}: decision evidence is missing"
        )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--systems-root", default=str(SYSTEMS_DIR))
    args = parser.parse_args()
    systems_dir = Path(args.systems_root)
    errors = validate_chain(systems_dir, repository=systems_dir.parents[1])
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("OK - publication, proposal, and evidence chain valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
