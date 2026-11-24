"""Legacy imports use the same implementation as the installed package."""

import importlib.util
from pathlib import Path

from precogly_toolkit import flow_refs


def test_legacy_flow_shim_has_no_second_implementation():
    source = Path(__file__).resolve().parents[1] / "scripts" / "flow_refs.py"
    spec = importlib.util.spec_from_file_location("_legacy_flow_shim", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for name in (
        "first_blueprint", "flow_ref_set", "build_flow_alias_map",
        "resolve_flow_ref", "resolve_flow_overrides", "resolve_flow_bindings",
    ):
        assert getattr(module, name) is getattr(flow_refs, name)
