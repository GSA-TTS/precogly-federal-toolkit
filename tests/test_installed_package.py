"""Run against an installed wheel, outside the repository import path."""

import json
import subprocess
import sys
from pathlib import Path

CLI = str(Path(sys.executable).parent / "precogly-toolkit")

from precogly_toolkit.flow_refs import build_flow_alias_map, resolve_flow_bindings


def test_alias_resolution_and_duplicate_rejection():
    blueprint = {"flows": [{"bom-ref": "flow-1", "source": "a", "destination": "b"}]}
    architecture = {
        "assets": {"source": "a", "destination": "b"},
        "flows": {"alias": {"source_asset": "source", "destination_asset": "destination"}},
    }
    assert build_flow_alias_map(architecture, blueprint) == ({"alias": "flow-1"}, [])
    bindings, errors = resolve_flow_bindings({"AC-1": ["alias", "flow-1"]}, architecture, blueprint)
    assert bindings == {"AC-1": ["flow-1"]}
    assert len(errors) == 1


def test_unknown_flow_fails_closed():
    assert resolve_flow_bindings({"AC-1": ["missing"]}, {}, {})[1]


def test_installed_cli_from_external_directory(tmp_path):
    architecture = tmp_path / "architecture.json"
    cdx = tmp_path / "cdx.json"
    architecture.write_text('{"flow_bindings": {"AC-1": ["flow-1"]}}')
    cdx.write_text('{"blueprints": [{"flows": [{"bom-ref": "flow-1"}]}]}')
    result = subprocess.run(
        [CLI, "flow-bindings", "--architecture", str(architecture), "--cdx", str(cdx)],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"bindings": {"AC-1": ["flow-1"]}, "errors": []}
    architecture.write_text('{"flow_bindings": {"AC-1": ["missing"]}}')
    assert subprocess.run(
        [CLI, "flow-bindings", "--architecture", str(architecture), "--cdx", str(cdx)],
        cwd=tmp_path, capture_output=True,
    ).returncode == 1


def test_installed_import_does_not_need_legacy_scripts(tmp_path):
    result = subprocess.run(
        [sys.executable, "-I", "-c", "from precogly_toolkit.flow_refs import first_blueprint; assert first_blueprint({}) == {}"],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
