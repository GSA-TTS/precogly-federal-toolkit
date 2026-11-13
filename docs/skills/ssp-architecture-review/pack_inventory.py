#!/usr/bin/env python3
"""Measure the facts the ssp-architecture-review skill scores for a federal-toolkit pack.

Read-only. Prints one JSON document per run (a list of per-pack fact objects).

    uv run --with pyyaml python skills/ssp-architecture-review/pack_inventory.py \
        vendor/precogly-federal-toolkit/packs/*
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

STRUCTURAL = {"trustZone", "systemScope"}
EXTERNAL = {"humanActor", "systemActor", "externalSystem"}
EDGE_REQUIRED = ("protocol", "encrypted")
EDGE_DESIRED = ("port", "authentication", "data_classification")
FIRST_PARTY = {"gsa", "tenant", "generic", "cloud.gov"}
CLAIM_PATTERNS = {
    "authorization_claim": re.compile(r"FedRAMP (?:Low|Moderate|High)[^.\n]{0,40}authorized", re.I),
    "approval_claim": re.compile(r"\[GSA: (?:Approved|DENIED)", re.I),
    "version_pin": re.compile(r"\b(?:v|version )\d+(?:\.\d+)*\b", re.I),
}
TRANSPORT_CRYPTO = re.compile(r"HTTPS|TLS|SSH|SFTP|LDAPS|MTLS", re.I)
CRYPTO_TERMS = ("FIPS", "AES", "TLS 1.", "SSE-KMS", "KMS", "HSTS")


def load(path: Path):
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def first_list(doc: dict) -> list[dict]:
    return next((v for v in doc.values() if isinstance(v, list)), [])


def ancestors(node: dict, nodes: dict[str, dict]) -> list[str]:
    chain = []
    while node.get("parentId"):
        node = nodes[node["parentId"]]
        chain.append(node["data"].get("label", node["id"]))
    return chain


def dfd_facts(path: Path, components: list[dict]) -> dict:
    component_ids = {c["id"] for c in components}
    doc = load(path)
    canvas = doc["canvas_data"]
    nodes = {n["id"]: n for n in canvas["nodes"]}
    edges = canvas["edges"]
    touched = {e["source"] for e in edges} | {e["target"] for e in edges}
    refs = {n["data"]["component_ref"] for n in nodes.values() if n["data"].get("component_ref")}
    attrs = Counter(k for e in edges for k in (e.get("data") or {}))
    known = {"label", "protocol", "encrypted", "port", "authentication", "data_classification", "description"}
    stray = sorted(k for k in attrs if k not in known)
    comp_provider = {c["id"]: c.get("provider") for c in components}
    third_party_inside = [
        {
            "node": n["id"],
            "component": n["data"]["component_ref"],
            "provider": comp_provider.get(n["data"]["component_ref"]),
        }
        for n in nodes.values()
        if n["data"].get("component_ref")
        and comp_provider.get(n["data"]["component_ref"]) not in FIRST_PARTY
        and any(
            a in [x["data"]["label"] for x in nodes.values() if x["type"] == "systemScope"] for a in ancestors(n, nodes)
        )
    ]
    return {
        "template": doc["template"]["slug"],
        "nodes": len(nodes),
        "edges": len(edges),
        "boundaries": [n["data"]["label"] for n in nodes.values() if n["type"] == "systemScope"],
        "zones": [n["data"]["label"] for n in nodes.values() if n["type"] == "trustZone"],
        "external": [
            {
                "id": n["id"],
                "type": n["type"],
                "label": n["data"].get("label"),
                "outside_boundary": not ancestors(n, nodes),
            }
            for n in nodes.values()
            if n["type"] in EXTERNAL
        ],
        "datastores": [n["id"] for n in nodes.values() if n["type"] == "datastore"],
        "isolated_nodes": [n["id"] for n in nodes.values() if n["type"] not in STRUCTURAL and n["id"] not in touched],
        "third_party_components_inside_boundary": third_party_inside,
        "unresolved_component_refs": sorted(r for r in refs if r not in component_ids),
        "unreferenced_nodes": [
            n["id"]
            for n in nodes.values()
            if n["type"] not in STRUCTURAL | EXTERNAL and not n["data"].get("component_ref")
        ],
        "edges_missing_required": {
            k: sum(1 for e in edges if (e.get("data") or {}).get(k) is None) for k in EDGE_REQUIRED
        },
        "edges_missing_desired": {k: sum(1 for e in edges if k not in (e.get("data") or {})) for k in EDGE_DESIRED},
        "edges_untraceable_encryption": [
            e["id"]
            for e in edges
            if (e.get("data") or {}).get("encrypted")
            and not TRANSPORT_CRYPTO.search(str((e.get("data") or {}).get("protocol")))
        ],
        "edge_protocols": sorted({str((e.get("data") or {}).get("protocol")) for e in edges}),
        "edges_encrypted_false": [e["id"] for e in edges if (e.get("data") or {}).get("encrypted") is False],
        "stray_edge_keys_yaml_parse_defect": stray,
        "component_refs": sorted(refs),
    }


def pack_facts(pack_dir: Path) -> dict:
    meta = load(pack_dir / "pack.yaml")["pack"]
    components = first_list(load(pack_dir / "components.yaml"))
    threats = first_list(load(pack_dir / "threats.yaml"))
    measures = first_list(load(pack_dir / "countermeasures.yaml"))
    ct = load(pack_dir / "joins" / "components-threats.yaml").get("mappings", [])
    tc = load(pack_dir / "joins" / "threats-countermeasures.yaml").get("mappings", [])
    cids = {c["id"] for c in components}
    tids = {t["id"] for t in threats}
    mids = {m["id"] for m in measures}
    joined_c = {m["component"] for m in ct}
    joined_t_ct = {x["threat"] for m in ct for x in m["threats"]}
    joined_t_tc = {m["threat"] for m in tc}
    joined_m = {c for m in tc for c in m["countermeasures"]}
    dfds = [dfd_facts(p, components) for p in sorted((pack_dir / "dfd-templates").glob("*.yaml"))]
    in_dfd = {r for d in dfds for r in d["component_refs"]}
    text = "".join(p.read_text(encoding="utf-8") for p in pack_dir.rglob("*.yaml"))
    offerings_path = pack_dir / "offerings.yaml"
    offerings = load(offerings_path).get("offerings", []) if offerings_path.exists() else []
    return {
        "pack": meta["slug"],
        "version": meta["version"],
        "maturity": meta["maturity"],
        "pack_type": meta["pack_type"],
        "maintainer": meta.get("maintainer"),
        "repository_url_present": bool(meta.get("repository_url")),
        "documentation_url_present": bool(meta.get("documentation_url")),
        "counts": {
            "components": len(components),
            "threats": len(threats),
            "countermeasures": len(measures),
            "dfds": len(dfds),
        },
        "providers": dict(Counter(c.get("provider") for c in components)),
        "categories": dict(Counter(c.get("category") for c in components)),
        "join_integrity": {
            "unknown_components": sorted(joined_c - cids),
            "unknown_threats": sorted((joined_t_ct | joined_t_tc) - tids),
            "unknown_countermeasures": sorted(joined_m - mids),
            "components_without_threat": sorted(cids - joined_c),
            "threats_without_component": sorted(tids - joined_t_ct),
            "threats_without_countermeasure": sorted(tids - joined_t_tc),
            "countermeasures_without_threat": sorted(mids - joined_m),
            "duplicate_ids": sorted(k for k, v in Counter([*cids, *tids, *mids]).items() if v > 1),
        },
        "components_not_in_any_dfd": sorted(cids - in_dfd),
        "offerings": [
            {
                "id": o["id"],
                "plans": [
                    {
                        "id": p["id"],
                        "controls": [f"{x['control']}:{x['origination']}" for x in p.get("provides", [])],
                        "unknown_incorporates": [i for i in p.get("incorporates", []) if i not in cids],
                    }
                    for p in o.get("plans", [])
                ],
            }
            for o in offerings
        ],
        "claims": {k: len(p.findall(text)) for k, p in CLAIM_PATTERNS.items()},
        "crypto_term_hits": {t: text.count(t) for t in CRYPTO_TERMS},
        "dfds": dfds,
    }


def main(argv: list[str]) -> int:
    dirs = [Path(a) for a in argv] or sorted(Path("packs").glob("*"))
    missing = [d for d in dirs if not (d / "pack.yaml").is_file()]
    if missing:
        print(f"BLOCKED: not a pack directory: {', '.join(map(str, missing))}", file=sys.stderr)
        return 2
    json.dump([pack_facts(d) for d in dirs], sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
