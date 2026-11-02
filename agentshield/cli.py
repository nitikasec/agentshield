"""AgentShield CLI.

    python -m agentshield scan <config.json> [--html out.html] [--json out.json]

Static analysis only — it reads and parses the config; it never runs it.
"""
from __future__ import annotations

import argparse
import json
import sys

from .analyzer import analyze
from . import report as report_mod


def main(argv=None):
    ap = argparse.ArgumentParser(prog="agentshield", description="Static MCP config security scanner")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="scan an MCP config JSON file")
    sc.add_argument("config", help="path to an MCP config JSON (e.g. claude_desktop_config.json)")
    sc.add_argument("--html", help="write an HTML report to this path")
    sc.add_argument("--json", dest="json_out", help="write a JSON report to this path")
    args = ap.parse_args(argv)

    try:
        with open(args.config) as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"error: file not found: {args.config}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as e:
        print(f"error: invalid JSON in {args.config}: {e}", file=sys.stderr)
        return 2

    rep = analyze(config)
    print(report_mod.to_text(rep, target=args.config))

    if args.html:
        with open(args.html, "w") as f:
            f.write(report_mod.to_html(rep, target=args.config))
        print(f"\nHTML report: {args.html}")
    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump(rep.to_dict(), f, indent=2)
        print(f"JSON report: {args.json_out}")

    # non-zero exit if any confirmed finding (useful in CI)
    return 1 if rep.confirmed else 0


if __name__ == "__main__":
    raise SystemExit(main())
