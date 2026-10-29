"""Vault note readers, provided by the vendored oscal-vault-core.

Controls, inheritance and organization notes are parsed by ``compliance/lib/vault_notes.py`` in the
core; this module re-exports them so existing callers keep working. The Ports/Protocols/Services
reader below stays local: it returns ``PpsFlow`` records that ``vault_topology`` consumes, and the
core's ``topology`` module offers the same data in a different shape.
"""

from __future__ import annotations

import dataclasses
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vault_core

if not vault_core.available("vault_notes"):
    raise ImportError(
        "vendor/oscal-vault-core is missing or predates vault_notes; "
        "run: git submodule update --init vendor/oscal-vault-core"
    )

_notes = vault_core.load("vault_notes")
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


# ---------------------------------------------------------------------------
# PPS topology (Ports, Protocols, Services tables in Relationships/*.md)
# ---------------------------------------------------------------------------

_PPS_NULL = re.compile(r"^(n/a|-+|none)$", re.IGNORECASE)


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


def _pps_bool(val: str) -> bool:
    """Y/N cell to bool. Accepts qualified answers such as ``Yes (TLS v1.2)``."""
    token = re.split(r"[\s(]", val.strip(), maxsplit=1)[0].upper()
    return token in ("Y", "YES", "TRUE", "1")


def _pps_direction(val: str) -> str:
    v = val.strip().lower()
    if "inbound" in v and "outbound" in v:
        return "Bi-Directional"
    if "inbound" in v:
        return "Inbound"
    if "outbound" in v:
        return "Outbound"
    return val.strip().title()


def _parse_md_table(text: str) -> tuple[list[str], list[list[str]]]:
    """Parse a raw markdown table string into (headers, data_rows)."""
    rows: list[list[str]] = []
    for line in text.strip().split("\n"):
        if re.match(r"\|[-: |]+\|", line):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        rows.append(cells)
    if len(rows) < 2:
        return [], []
    return rows[0], rows[1:]


_MD_TABLE_RE = re.compile(r"\|[^\n]+\|\n\|[-: |]+\|\n(?:\|[^\n]+\|\n)+", re.MULTILINE)


def parse_pps_topology(vault_system_dir: str) -> list[PpsFlow]:
    """Return PpsFlow records parsed from all Relationships/*.md PPS tables.

    The PPS (Ports, Protocols, Services) table is the only consistently
    machine-readable topology source across vault systems.  Column order
    varies between systems so we locate columns by keyword match.
    Rows whose Source AND Destination are both N/A are skipped.
    """
    rel_dir = os.path.join(vault_system_dir, "Relationships")
    if not os.path.isdir(rel_dir):
        return []

    flows: list[PpsFlow] = []
    for fname in sorted(os.listdir(rel_dir)):
        if not fname.endswith(".md"):
            continue
        path = os.path.join(rel_dir, fname)
        try:
            with open(path, encoding="utf-8") as fh:
                body = fh.read()
        except OSError:
            continue
        _, content = split_frontmatter(body)

        for m in _MD_TABLE_RE.finditer(content):
            headers, rows = _parse_md_table(m.group(0))
            if not headers:
                continue
            hl = [h.lower() for h in headers]
            # Only process tables that have Source and Destination columns.
            src_col = next((i for i, h in enumerate(hl) if "source" in h), None)
            dst_col = next((i for i, h in enumerate(hl) if "dest" in h), None)
            if src_col is None or dst_col is None:
                continue
            # Locate optional columns by keyword
            dir_col = next((i for i, h in enumerate(hl) if "direction" in h), None)
            bc_col = next((i for i, h in enumerate(hl) if "boundary" in h), None)
            prt_col = next((i for i, h in enumerate(hl) if "port" in h), None)
            proto_col = next((i for i, h in enumerate(hl) if "protocol" in h), None)
            # "External Service (Y/N)" is a flag column, not the service name.
            svc_col = next(
                (i for i, h in enumerate(hl) if "service" in h and "external" not in h),
                None,
            )
            purp_col = next((i for i, h in enumerate(hl) if "purpose" in h), None)
            enc_col = next((i for i, h in enumerate(hl) if "encrypt" in h), None)
            sens_col = next(
                (i for i, h in enumerate(hl) if "sensitiv" in h or "data" in h), None
            )

            def _cell(row: list[str], col: int | None) -> str:
                if col is None or col >= len(row):
                    return ""
                return row[col].strip()

            for row in rows:
                if len(row) < max(c for c in [src_col, dst_col] if c is not None) + 1:
                    continue
                src = _cell(row, src_col)
                dst = _cell(row, dst_col)
                # Skip blank/N/A rows
                if _PPS_NULL.match(src) and _PPS_NULL.match(dst):
                    continue
                if not src and not dst:
                    continue
                flows.append(
                    PpsFlow(
                        source=src,
                        destination=dst,
                        direction=_pps_direction(
                            _cell(row, dir_col) or "Bi-Directional"
                        ),
                        boundary_crossing=_pps_bool(_cell(row, bc_col) or "N"),
                        port=_cell(row, prt_col),
                        protocol=_cell(row, proto_col),
                        service=_cell(row, svc_col),
                        purpose=_cell(row, purp_col),
                        encrypted=_pps_bool(_cell(row, enc_col) or "Y"),
                        data_sensitivity=_cell(row, sens_col) or "Low",
                    )
                )
    return flows


def load_topology(vault_root: str, system_slug: str) -> list[PpsFlow]:
    """Convenience wrapper — returns [] if vault dir is missing."""
    system_dir = os.path.join(vault_root, "examples", "vault", system_slug)
    if not os.path.isdir(system_dir):
        return []
    return parse_pps_topology(system_dir)
