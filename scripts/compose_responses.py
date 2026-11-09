#!/usr/bin/env python3
"""Compose a system ``responses.yaml`` from its seed and component library.

Reads:
- ``data/systems/<system>/seed.yaml`` — declares which components are in the
  architecture and per-instance ``params``; may include per-part
  ``overrides``.
- ``data/components/<category>/<slug>.yaml`` — reusable component
  contributions.

Writes:
- ``data/systems/<system>/responses.yaml`` in the same shape read by
  ``scripts/merge_responses.py`` / ``scripts/merge_example-system_responses.py``.

Composition rules:
1. Resolve each seed ``components[i].id`` to ``data/components/<id>.yaml``.
2. For each control part contributed by any component, join contributions
   with a blank-line separator in seed order.
3. Substitute per-instance ``params`` using ``str.format(**params)``;
   list values render as ``, ``-joined text.
4. If the seed declares ``overrides.<control>.<part>``, it replaces any
   composed contribution for that (control, part).
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from systems.loader import load_system  # noqa: E402

COMPONENTS_DIR = Path("data/components")
SEEDS_DIR = Path("data/seeds")
RESPONSES_DIR = Path("data/responses")


class _LiteralStr(str):
    pass


def _literal_representer(dumper: yaml.Dumper, data: _LiteralStr):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


yaml.add_representer(_LiteralStr, _literal_representer, Dumper=yaml.SafeDumper)


def _dump(doc: Any) -> str:
    return yaml.safe_dump(doc, sort_keys=False, width=100, allow_unicode=True)


def _load_yaml(path: Path) -> dict:
    with path.open() as f:
        return yaml.safe_load(f) or {}


def _norm(cid: str) -> str:
    key = re.sub(r"\s+", "", (cid or "").upper())
    key = re.sub(r"^([A-Z]{2})-0*(\d+)", r"\1-\2", key)
    return re.sub(r"\(0*(\d+)\)", r"(\1)", key)


def _part_key(part) -> str:
    if part is None:
        return "-"
    return str(part).strip().lower()


def _render_value(v: Any) -> str:
    if isinstance(v, list):
        return ", ".join(str(x) for x in v) if v else "(none)"
    if v is None:
        return "(unset)"
    return str(v)


class _SafeFormatDict(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def _render_prose(template: str, params: dict) -> str:
    rendered = {k: _render_value(v) for k, v in params.items()}
    return template.format_map(_SafeFormatDict(rendered)).strip()


def _resolve_component(cid: str) -> Path:
    # cid is "<category>/<slug>" -> data/components/<category>/<slug>.yaml
    p = COMPONENTS_DIR / f"{cid}.yaml"
    if not p.exists():
        raise SystemExit(f"error: component not found: {p}")
    return p


def _merge_params(defaults: dict, overrides: dict | None) -> dict:
    merged: dict[str, Any] = {}
    for name, spec in (defaults or {}).items():
        if isinstance(spec, dict) and "default" in spec:
            merged[name] = spec["default"]
    for name, value in (overrides or {}).items():
        merged[name] = value
    # Fail on missing required
    missing = [
        n
        for n, spec in (defaults or {}).items()
        if isinstance(spec, dict)
        and spec.get("required")
        and n not in (overrides or {})
    ]
    if missing:
        raise SystemExit(f"error: component missing required params: {missing}")
    return merged


def compose(seed_path: Path, out_path: Path) -> dict:
    seed = _load_yaml(seed_path)
    system = seed.get("system") or seed_path.stem
    components = seed.get("components") or []
    overrides = seed.get("overrides") or {}
    response_defaults = seed.get("response_defaults") or {}
    control_metadata = seed.get("control_metadata") or {}

    per_part: OrderedDict[tuple[str, str], list[str]] = OrderedDict()
    part_display: dict[tuple[str, str], Any] = {}
    used_components: list[str] = []

    for entry in components:
        cid = entry.get("id")
        if not cid:
            continue
        comp = _load_yaml(_resolve_component(cid))
        params = _merge_params(comp.get("params"), entry.get("params"))
        used_components.append(cid)
        for control, parts in (comp.get("controls") or {}).items():
            key_ctrl = _norm(control)
            for p in parts or []:
                part = p.get("part")
                key = (key_ctrl, _part_key(part))
                per_part.setdefault(key, []).append(
                    _render_prose(p.get("implementation") or "", params)
                )
                part_display.setdefault(key, part)

    for control, parts in (overrides or {}).items():
        key_ctrl = _norm(control)
        for p in parts or []:
            part = p.get("part")
            key = (key_ctrl, _part_key(part))
            per_part[key] = [(p.get("implementation") or "").strip()]
            part_display[key] = part

    grouped: OrderedDict[str, list[dict]] = OrderedDict()
    for (ctrl_key, part_key), chunks in per_part.items():
        prose = "\n\n".join(x for x in chunks if x)
        grouped.setdefault(ctrl_key, []).append(
            {
                "part": part_display[(ctrl_key, part_key)],
                "implementation": _LiteralStr(prose + "\n"),
            }
        )

    doc = {
        "source": f"composed from {seed_path} + {len(used_components)} component(s)",
        "system": system,
        "components": used_components,
        "response_defaults": response_defaults,
        "control_metadata": control_metadata,
        "responses": dict(grouped),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(_dump(doc))
    return {
        "system": system,
        "components": used_components,
        "controls": len(grouped),
        "parts": sum(len(v) for v in grouped.values()),
        "out": str(out_path),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=Path, help="Path to seed YAML")
    ap.add_argument("--system", help="Shorthand: reads the system manifest's seed")
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output path (default: the manifest-backed system responses.yaml)",
    )
    args = ap.parse_args()

    if args.seed:
        seed_path = args.seed
    elif args.system:
        paths = load_system(args.system)
        if not paths.seed:
            ap.error(f"system {args.system} has no seed.yaml")
        seed_path = paths.seed
    else:
        ap.error("provide --seed or --system")
        return 2

    if not seed_path.exists():
        print(f"error: seed not found: {seed_path}", file=sys.stderr)
        return 2

    system = _load_yaml(seed_path).get("system") or seed_path.stem
    if args.out:
        out_path = args.out
    elif args.system:
        out_path = load_system(args.system).root / "responses.yaml"
    else:
        out_path = RESPONSES_DIR / f"{system}.yaml"
    result = compose(seed_path, out_path)
    print(f"Wrote {result['out']}")
    print(f"  system:     {result['system']}")
    print(f"  components: {len(result['components'])} -> {result['components']}")
    print(f"  controls:   {result['controls']}")
    print(f"  parts:      {result['parts']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
