import json
from pathlib import Path

import pytest

from precogly_toolkit import system_directory as systems
from precogly_toolkit.dfd_format import canonicalize_dfd, format_dfd, format_json


def test_system_paths_and_discovery_are_bound_to_explicit_consumer(tmp_path):
    directory = tmp_path / "systems"
    root = directory / "sample"
    (root / "model").mkdir(parents=True)
    (root / "system.yaml").write_text("slug: sample\nname: Synthetic system\n")
    (root / "model/base-dfd.cdx.json").write_text("{}")
    paths = systems.load_system("sample", systems_dir=directory)
    assert paths.root == root
    assert paths.model_dfd == root / "model/base-dfd.cdx.json"
    assert paths.countermeasures is None
    assert systems.discover_systems(systems_dir=directory) == ["sample"]
    assert systems.load_manifest("sample", systems_dir=directory)["slug"] == "sample"


@pytest.mark.parametrize("slug", ["", "..", "../escape", "/absolute", "a/b", "a\\b"])
def test_slug_cannot_escape_consumer_directory(tmp_path, slug):
    with pytest.raises(ValueError, match="path component"):
        systems.load_system(slug, systems_dir=tmp_path)


def test_missing_system_never_has_an_implicit_private_fallback(tmp_path):
    with pytest.raises(FileNotFoundError):
        systems.load_system("unknown", systems_dir=tmp_path)


def test_manifest_mismatch_and_explicit_missing_schema_fail(tmp_path):
    root = tmp_path / "sample"
    root.mkdir()
    (root / "system.yaml").write_text("slug: different\n")
    with pytest.raises(ValueError, match="does not match"):
        systems.load_manifest("sample", systems_dir=tmp_path)
    (root / "system.yaml").write_text("slug: sample\n")
    with pytest.raises(FileNotFoundError):
        systems.load_manifest("sample", systems_dir=tmp_path, schema_path=tmp_path / "missing.json")


def test_schema_validation_is_enforced_when_requested(tmp_path):
    root = tmp_path / "sample"
    root.mkdir()
    (root / "system.yaml").write_text("slug: sample\n")
    schema = tmp_path / "schema.json"
    schema.write_text(json.dumps({"type": "object", "required": ["name"]}))
    from jsonschema import ValidationError
    with pytest.raises(ValidationError):
        systems.load_manifest("sample", systems_dir=tmp_path, schema_path=schema)


def test_format_is_idempotent_and_check_mode_does_not_write(tmp_path):
    dfd = {"version": 1, "blueprints": [{"bom-ref": "b", "flows": [], "properties": [{"name": "z", "value": "2"}, {"name": "a", "value": "1"}]}]}
    canonical = canonicalize_dfd(dfd)
    assert canonicalize_dfd(canonical) == canonical
    assert dfd["blueprints"][0]["properties"][0]["name"] == "z"
    path = tmp_path / "dfd.json"
    path.write_text(json.dumps(dfd))
    before = path.read_bytes()
    assert format_dfd(path, check=True)
    assert path.read_bytes() == before
    assert format_dfd(path)
    assert path.read_text() == format_json(dfd)
    assert not format_dfd(path, check=True)


def test_legacy_format_exports_same_engine():
    import importlib.util
    from precogly_toolkit import dfd_format

    source = Path(__file__).resolve().parents[1] / "scripts/format_sources.py"
    spec = importlib.util.spec_from_file_location("_format_shim", source)
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.path.insert(0, str(source.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(source.parent))
    assert module.canonicalize_dfd is dfd_format.canonicalize_dfd
