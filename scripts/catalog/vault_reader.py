"""Vault note readers, provided by the vendored oscal-vault-core.

Controls, inheritance, organization notes, and Ports/Protocols/Services (PPS) tables
are parsed by ``compliance/lib/vault_notes.py`` and ``compliance/lib/topology.py`` in
the core; this module re-exports them so existing callers keep one import path.
"""

from __future__ import annotations

import dataclasses
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vault_core

if not vault_core.available("vault_notes") or not vault_core.available("topology"):
    raise ImportError(
        "vendor/oscal-vault-core is missing or predates vault_notes/topology; "
        "run: git submodule update --init vendor/oscal-vault-core"
    )

_notes = vault_core.load("vault_notes")
_topo = vault_core.load("topology")
INLINE_META_RE = _notes.INLINE_META_RE
PART_HEADING_RE = _notes.PART_HEADING_RE
SECTION_HEADING_RE = _notes.SECTION_HEADING_RE
INHERITANCE_ROW_RE = _notes.INHERITANCE_ROW_RE
normalize_control_id = _notes.normalize_control_id
split_frontmatter = _notes.split_frontmatter
StatusMap = _notes.StatusMap
OriginationMap = _notes.OriginationMap
PartRecord = _notes.PartRecord
ControlRecord = _notes.ControlRecord
parse_control = _notes.parse_control
InheritanceEntry = _notes.InheritanceEntry
parse_inheritance = _notes.parse_inheritance
load_status_and_origination = _notes.load_status_and_origination
OrgParty = _notes.OrgParty
parse_org_parties = _notes.parse_org_parties

_pps_bool = _topo._truthy
_pps_direction = _topo._direction


@dataclasses.dataclass
class PpsFlow:
    """One row from a Ports, Protocols, and Services table."""

    source: str
    destination: str
    direction: str  # "Inbound", "Outbound", "Bi-Directional" (normalised)
    boundary_crossing: bool
    port: str
    protocol: str
    service: str
    purpose: str
    encrypted: bool
    data_sensitivity: str  # "Low", "Moderate", "High"


def parse_pps_topology(vault_system_dir: str) -> list[PpsFlow]:
    """Return PpsFlow records parsed from all Relationships/*.md PPS tables via oscal-vault-core."""
    system_path = Path(vault_system_dir)
    if not (system_path / "Relationships").is_dir():
        return []
    return [
        PpsFlow(
            source=row.source,
            destination=row.destination,
            direction=row.direction,
            boundary_crossing=row.boundary_crossing,
            port=row.port,
            protocol=row.protocol,
            service=row.service,
            purpose=row.purpose,
            encrypted=row.encrypted,
            data_sensitivity=row.sensitivity,
        )
        for row in _topo.load_pps_rows(system_path)
    ]


def load_topology(vault_root: str, system_slug: str) -> list[PpsFlow]:
    """Convenience wrapper — returns [] if vault dir is missing."""
    system_dir = os.path.join(vault_root, "examples", "vault", system_slug)
    if not os.path.isdir(system_dir):
        return []
    return parse_pps_topology(system_dir)
