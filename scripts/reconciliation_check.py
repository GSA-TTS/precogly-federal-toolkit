#!/usr/bin/env python3
"""Run all local publication and reconciliation validators in dependency order."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
VAULT = REPO / "vendor/oscal-vault"

from scripts.validate_cui_contracts import validate_systems  # noqa: E402
from scripts.validate_publication_contracts import validate_manifest  # noqa: E402
from scripts.validate_reconciliation_chain import validate_chain  # noqa: E402
from scripts.validate_reconciliation_evidence import validate_evidence  # noqa: E402
from scripts.validate_reconciliation_proposals import validate_proposal  # noqa: E402


def _resolve_tooling_root(
    repository: Path, core: Path | None = None
) -> Path | None:
    if core is not None:
        resolved = core.resolve()
        return (
            resolved
            if (resolved / "compliance/lib/reconciliation.py").is_file()
            else None
        )
    candidates = (
        repository / "vendor/oscal-vault-core",
        repository / "vendor/oscal-vault",
        REPO / "vendor/oscal-vault-core",
        VAULT,
    )
    return next(
        (
            root
            for root in candidates
            if (root / "compliance/lib/reconciliation.py").is_file()
        ),
        None,
    )


def validate_repository(
    repository: Path, core: Path | None = None
) -> list[str]:
    """Validate system-owned artifacts while loading schemas from this toolkit."""
    repository = repository.resolve()
    systems_dir = repository / "data" / "systems"
    if not systems_dir.is_dir():
        return [f"missing system data directory: {systems_dir}"]
    errors = validate_systems(systems_dir, require_all=False)
    for system_dir in sorted(systems_dir.iterdir()):
        if not system_dir.is_dir():
            continue
        publication = system_dir / "publication.yaml"
        proposal = system_dir / "reconciliation-proposal.yaml"
        if publication.exists():
            errors.extend(validate_manifest(publication, repository=repository))
        if proposal.exists():
            errors.extend(validate_proposal(proposal, repository=repository))
        for evidence in sorted((system_dir / "reconciliation-evidence").glob("*.yaml")):
            errors.extend(validate_evidence(evidence, repository=repository))
        automation_overlay = system_dir / "reconciliation" / "automation-overlay.yaml"
        if automation_overlay.is_file():
            tooling_root = _resolve_tooling_root(repository, core=core)
            if tooling_root is None:
                errors.append(
                    f"{automation_overlay}: missing compliance/lib/reconciliation.py "
                    "(initialize vendor/oscal-vault-core or pass --core)"
                )
            else:
                if str(tooling_root) not in sys.path:
                    sys.path.append(str(tooling_root))
                import yaml
                from compliance.lib.reconciliation import validate_overlay

                data = (
                    yaml.safe_load(automation_overlay.read_text(encoding="utf-8")) or {}
                )
                errors.extend(
                    f"{automation_overlay}: {error}"
                    for error in validate_overlay(data, require_ready=False)
                )
    errors.extend(validate_chain(systems_dir, repository=repository))
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=".", type=Path)
    parser.add_argument("--core", type=Path, help="Path to oscal-vault-core checkout")
    args = parser.parse_args(argv)
    errors = validate_repository(args.repository.resolve(), core=args.core)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("OK - local publication and reconciliation gates valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
