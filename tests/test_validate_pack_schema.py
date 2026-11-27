import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from scripts import validate_pack_schema


SCHEMA = yaml.safe_load((REPO / "schemas" / "pack.schema.json").read_text())


def _write_pack(tmp_path: Path, edge_data: dict) -> Path:
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "pack.yaml").write_text(
        yaml.safe_dump(
            {
                "pack": {
                    "schema_version": 1,
                    "slug": "example-pack",
                    "name": "Example",
                    "version": "1.0.0",
                    "description": "Example pack.",
                    "author": "Example",
                    "maintainer": "Example",
                    "pack_type": "technology",
                    "precogly_schema_version": "2.0",
                    "maturity": "Draft",
                }
            }
        )
    )
    for name, key in (
        ("components.yaml", "components"),
        ("threats.yaml", "threats"),
        ("countermeasures.yaml", "countermeasures"),
    ):
        (pack / name).write_text(yaml.safe_dump({key: [{"id": key[:-1]}]}))
    template_dir = pack / "dfd-templates"
    template_dir.mkdir()
    (template_dir / "example.yaml").write_text(
        yaml.safe_dump({"canvas_data": {"edges": [{"id": "example", "data": edge_data}]}})
    )
    return pack / "pack.yaml"


def test_dfd_template_requires_port_and_authentication(tmp_path: Path):
    path = _write_pack(tmp_path, {"label": "Expected"})

    errors = validate_pack_schema.validate_pack(path, Draft202012Validator(SCHEMA))

    assert any("edge example: missing port" in error for error in errors)
    assert any("authentication must be a non-empty list" in error for error in errors)


def test_dfd_template_rejects_unknown_edge_data_keys(tmp_path: Path):
    path = _write_pack(
        tmp_path,
        {
            "label": "Expected",
            "port": "443",
            "authentication": ["Anonymous"],
            "stray": "YAML defect",
        },
    )

    errors = validate_pack_schema.validate_pack(path, Draft202012Validator(SCHEMA))

    assert any("edge example: unknown data key(s): stray" in error for error in errors)
