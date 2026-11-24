"""Legacy system-selector CLI over the installed DFD-formatting engine."""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from precogly_toolkit.dfd_format import canonicalize_dfd, format_json, format_dfd
from systems.loader import DEFAULT_SYSTEM, load_system


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system", default=DEFAULT_SYSTEM)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    paths = load_system(args.system)
    if paths.model_dfd is None:
        print(f"FAIL: {args.system}: missing model/base-dfd.cdx.json", file=sys.stderr)
        return 1
    changed = format_dfd(paths.model_dfd, check=args.check)
    if args.check and changed:
        print(f"FAIL: {paths.model_dfd.relative_to(ROOT)} is not canonically formatted", file=sys.stderr)
        return 1
    print(f"{'Formatted' if changed else 'OK -'} {paths.model_dfd.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
