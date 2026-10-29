#!/usr/bin/env python3
"""Validate vault-projected system artifacts (ADR-SSPP-006 Phase 4).

For each system directory under build/systems/<slug>/:
  * <slug>.cdx.json is well-formed CycloneDX-Precogly:
      - blueprints/assets/zones structurally consistent
      - threats/scenarios/controls cross-referenced
      - status/category values in allowed sets
      - properties carry required vault: keys
  * pack/*.yaml joins reference existing components/threats/countermeasures
  * import-summary.yaml counts match generated artifacts
  * no unredacted URL, email, or IPv4 leaks
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from glob import glob

import yaml
from validators_common import (
    CATEGORIES,
    RISK_LEVELS,
    STATUSES,
    bidirectional_control_threat_errors,
    find_ipv4_leak,
)
from validators_common import (
    FORBIDDEN_PATTERNS as FORBIDDEN,
)

CDX_OPTIONAL_SYSTEMS = {
    "example-system",
    "example-system-composite-alt-managed-cloud-service",
    "example-system-composite-baseline-gsapages",
    "example-system-public-site-gsa-pages",
    "example-system-data-platform-core",
    "example-system-transfer-sftpgo-cloudgov",
    "example-system-transfer-managed-cloud-service",
    "gsa-pages-hosting-alt-fcs-managed-cloud-service",
    "gsa-pages-hosting-baseline-cloudgov-pages",
    "sample-net-new-saas-2026",
}

failures: list[str] = []
warnings: list[str] = []


def fail(system: str, msg: str) -> None:
    failures.append(f"[{system}] {msg}")


def warn(system: str, msg: str) -> None:
    warnings.append(f"[{system}] {msg}")


def validate_cdx(system: str, cdx_path: str) -> tuple[int, int, int]:
    with open(cdx_path, encoding="utf-8") as f:
        d = json.load(f)

    if d.get("specFormat") != "CycloneDX":
        fail(system, f"specFormat={d.get('specFormat')} (expected CycloneDX)")

    blueprints = d.get("blueprints") or []
    if not blueprints:
        fail(system, "no blueprints[]")
        return (0, 0, 0)
    bp = blueprints[0]

    assets = bp.get("assets", [])
    zones = bp.get("zones", [])
    flows = bp.get("flows", [])
    # Flows are addressable; threats/scenarios may reference either. Data stores are components
    # (flow endpoints and scenario targets) just like assets.
    aset = (
        {a["bom-ref"] for a in assets}
        | {s["bom-ref"] for s in bp.get("dataStores", []) if "bom-ref" in s}
        | {f["bom-ref"] for f in flows if "bom-ref" in f}
    )
    zset = {z["bom-ref"] for z in zones}

    if not aset:
        fail(system, "blueprint has no assets")
    for flow in flows:
        for endpoint in ("source", "destination"):
            ref = flow.get(endpoint)
            if ref and ref not in aset and ref not in zset:
                fail(system, f"flow {flow.get('bom-ref')} bad {endpoint} {ref}")
    for a in assets:
        z = a.get("zone")
        model_reference = any(
            reference.get("type") == "threat-model"
            for reference in a.get("externalReferences") or []
            if isinstance(reference, dict)
        )
        if not z and not model_reference:
            fail(system, f"asset {a['bom-ref']} has no zone")
        elif z and z not in zset:
            fail(system, f"asset {a['bom-ref']} references missing zone {z}")

    threats = d.get("threats", {}).get("threats", [])
    scenarios = d.get("threats", {}).get("scenarios", [])
    controls = d.get("controls", [])
    tset = {t["bom-ref"] for t in threats}
    cset = {c["bom-ref"] for c in controls}

    for s in scenarios:
        threat_refs = s.get("threats") or [s.get("threat")]
        for threat_ref in threat_refs:
            if threat_ref not in tset:
                fail(
                    system,
                    f"scenario {s.get('bom-ref')} -> missing threat {threat_ref}",
                )
        level = (s.get("riskScore") or {}).get("level")
        if level and level not in RISK_LEVELS:
            fail(system, f"scenario {s.get('bom-ref')} bad risk level {level}")
        for a in s.get("affectedAssets", []):
            if a not in aset:
                fail(system, f"scenario {s.get('bom-ref')} bad asset {a}")

    for t in threats:
        for m in t.get("mitigations", []):
            if m not in cset:
                fail(system, f"threat {t['bom-ref']} -> missing control {m}")
        for a in t.get("affectedAssets", []):
            if a not in aset:
                fail(system, f"threat {t['bom-ref']} bad asset {a}")
        props = {p.get("name"): p.get("value") for p in t.get("properties", [])}
        # Vault-projected: ctrl:id; ADR-005-native (Example System): ctrl:id (was crm:control-id);
        # base-DFD threats (non-CRM): resp:ctrl-ref. Accept any.
        if not any(k in props for k in ("ctrl:id", "resp:ctrl-ref")):
            warn(system, f"threat {t['bom-ref']} missing ctrl:id property")

    {c["bom-ref"]: c for c in controls}
    for c in controls:
        if c.get("category") not in CATEGORIES:
            fail(system, f"control {c['bom-ref']} bad category {c.get('category')}")
        if c.get("status") not in STATUSES:
            fail(system, f"control {c['bom-ref']} bad status {c.get('status')}")
        for m in c.get("mitigations", []):
            if m not in tset:
                fail(system, f"control {c['bom-ref']} -> missing threat {m}")
        props = {p.get("name"): p.get("value") for p in c.get("properties", [])}
        is_vault_style = any(k.startswith("vault:") for k in props)
        if is_vault_style:
            for required in (
                "ctrl:id",
                "vault:implementation-status",
                "vault:origination",
            ):
                if required not in props:
                    fail(system, f"control {c['bom-ref']} missing {required} property")
            # Flag undocumented planned controls (mirrors gsa-pages ccc-check)
            impl_status = props.get("vault:implementation-status", "")
            if impl_status == "planned" and not (c.get("description") or "").strip():
                warn(system, f"control {c['bom-ref']} status=planned with no prose")
        else:
            if not any(k in props for k in ("ctrl:id", "resp:evidence-key")):
                warn(
                    system,
                    f"control {c['bom-ref']} missing ctrl:id property",
                )

    for err in bidirectional_control_threat_errors(threats, controls):
        fail(system, err)

    # Strip intentional evidence URLs (externalReferences + resp:evidence-link
    # property values) before running the recon-leak scan.
    def _strip_evidence_urls(obj: object) -> object:
        if isinstance(obj, dict):
            stripped = {k: v for k, v in obj.items() if k != "externalReferences"}
            if "properties" in stripped:
                stripped["properties"] = [
                    p
                    for p in stripped["properties"]
                    if p.get("name") != "resp:evidence-link"
                ]
            return {k: _strip_evidence_urls(v) for k, v in stripped.items()}
        if isinstance(obj, list):
            return [_strip_evidence_urls(i) for i in obj]
        return obj

    raw = json.dumps(_strip_evidence_urls(d))
    for pattern, label in FORBIDDEN:
        m = pattern.search(raw)
        if m:
            fail(system, f"unredacted {label} in cdx: '{m.group(0)[:60]}'")
    ipv4 = find_ipv4_leak(raw)
    if ipv4:
        fail(system, f"unredacted IPv4 in cdx: '{ipv4.group(0)}'")

    return (len(threats), len(controls), len(scenarios))


def validate_pack(system: str, pack_dir: str) -> None:
    if system in CDX_OPTIONAL_SYSTEMS:
        return
    if not os.path.isdir(pack_dir):
        fail(system, f"pack/ directory missing: {pack_dir}")
        return

    def load(name: str) -> dict | None:
        p = os.path.join(pack_dir, name)
        if not os.path.isfile(p):
            fail(system, f"pack file missing: {name}")
            return None
        with open(p, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    pack = load("pack.yaml")
    comps = load("components.yaml")
    threats = load("threats.yaml")
    cms = load("countermeasures.yaml")
    ct = load(os.path.join("joins", "components-threats.yaml"))
    tc = load(os.path.join("joins", "threats-countermeasures.yaml"))
    fw = load(os.path.join("joins", "countermeasures-nist-800-53-r5.yaml"))

    if pack is None or comps is None or threats is None or cms is None:
        return

    cids = {c["id"] for c in comps.get("components", [])}
    tids = {t["id"] for t in threats.get("threats", [])}
    mids = {m["id"] for m in cms.get("countermeasures", [])}

    for m in cms.get("countermeasures", []):
        if not m.get("control_type"):
            fail(system, f"countermeasure {m['id']} missing control_type")
        if not m.get("default_status"):
            warn(system, f"countermeasure {m['id']} missing default_status")

    if ct:
        for row in ct.get("mappings", []):
            if row.get("component") not in cids:
                fail(
                    system,
                    f"components-threats join references unknown component {row.get('component')}",
                )
            for entry in row.get("threats", []):
                if entry.get("threat") not in tids:
                    fail(
                        system,
                        f"components-threats join references unknown threat {entry.get('threat')}",
                    )

    if tc:
        for row in tc.get("mappings", []):
            if row.get("threat") not in tids:
                fail(
                    system,
                    f"threats-countermeasures join references unknown threat {row.get('threat')}",
                )
            for cm in row.get("countermeasures", []):
                if cm not in mids:
                    fail(
                        system,
                        f"threats-countermeasures join references unknown countermeasure {cm}",
                    )

    if fw:
        for row in fw.get("mappings", []):
            if row.get("countermeasure") not in mids:
                fail(
                    system,
                    f"framework join references unknown countermeasure {row.get('countermeasure')}",
                )

    for name in (
        "pack.yaml",
        "components.yaml",
        "threats.yaml",
        "countermeasures.yaml",
    ):
        p = os.path.join(pack_dir, name)
        with open(p, encoding="utf-8") as f:
            raw = f.read()
        for pattern, label in FORBIDDEN:
            m = pattern.search(raw)
            if m:
                fail(system, f"unredacted {label} in pack/{name}: '{m.group(0)[:60]}'")
        ipv4 = find_ipv4_leak(raw)
        if ipv4:
            fail(system, f"unredacted IPv4 in pack/{name}: '{ipv4.group(0)}'")


def validate_summary(
    system: str, system_dir: str, threats: int, controls: int, scenarios: int
) -> None:
    p = os.path.join(system_dir, "import-summary.yaml")
    if not os.path.isfile(p):
        warn(system, "import-summary.yaml missing")
        return
    with open(p, encoding="utf-8") as f:
        s = yaml.safe_load(f) or {}
    if "threats" in s and s["threats"] != threats:
        fail(system, f"summary threats={s['threats']} but cdx has {threats}")
    if "controls" in s and s["controls"] != controls:
        fail(system, f"summary controls={s['controls']} but cdx has {controls}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--systems-root",
        default=os.path.join(
            os.path.dirname(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            ),
            "build",
            "systems",
        ),
    )
    ap.add_argument("--only", help="Comma-separated list of system slugs to validate")
    args = ap.parse_args(argv)

    root = args.systems_root
    if not os.path.isdir(root):
        print(f"FAIL: systems root missing: {root}", file=sys.stderr)
        return 2

    only = set(args.only.split(",")) if args.only else None

    system_dirs = [
        d for d in sorted(os.listdir(root)) if os.path.isdir(os.path.join(root, d))
    ]
    total = 0
    for slug in system_dirs:
        if only and slug not in only:
            continue
        system_dir = os.path.join(root, slug)
        cdx_files = glob(os.path.join(system_dir, "*.cdx.json"))
        if not cdx_files:
            if slug in CDX_OPTIONAL_SYSTEMS:
                total += 1
                continue
            fail(slug, "no *.cdx.json found")
            continue
        counts = validate_cdx(slug, cdx_files[0])
        validate_pack(slug, os.path.join(system_dir, "pack"))
        validate_summary(slug, system_dir, *counts)
        total += 1

    for w in warnings:
        print(f"WARN: {w}", file=sys.stderr)
    for f in failures:
        print(f"FAIL: {f}", file=sys.stderr)

    if failures:
        print(
            f"\n{len(failures)} failure(s) across {total} system(s).", file=sys.stderr
        )
        return 1
    print(f"OK - {total} system(s) validated, {len(warnings)} warning(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
