"""Compatibility shim; authoritative implementation lives in precogly_toolkit."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from precogly_toolkit.flow_refs import (  # noqa: E402, F401
    first_blueprint,
    flow_ref_set,
    build_flow_alias_map,
    resolve_flow_ref,
    resolve_flow_overrides,
    resolve_flow_bindings,
)
