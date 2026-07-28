#!/usr/bin/env python3
"""Print a compact triage queue from out/scan-latest.json (read-only)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--report",
        type=Path,
        default=ROOT / "out" / "scan-latest.json",
    )
    args = ap.parse_args()
    if not args.report.exists():
        print(f"No report at {args.report}. Run: python3 scripts/scan.py", file=sys.stderr)
        return 1

    report = json.loads(args.report.read_text())
    print(f"Scan: {report.get('scanned_at')}  owner={report.get('owner')}")
    print()

    print("## Quick wins (heuristic)")
    # Single-alert dependabot repos
    for d in report.get("dependabot") or []:
        if d["total"] <= 3:
            sev = d.get("by_severity") or {}
            print(
                f"- [fix-direct] {d['repo']}: Dependabot {d['total']} {sev} → {d['url']}"
            )
    # CodeQL missing permissions / small counts
    for c in report.get("code_scanning") or []:
        tools = c.get("by_tool") or {}
        if c["total"] <= 5 and "CodeQL" in tools:
            print(
                f"- [fix-direct] {c['repo']}: Code scanning {c['total']} "
                f"{c.get('top_rules')} → {c['url']}"
            )
        elif c["total"] > 20:
            print(
                f"- [park/batch] {c['repo']}: Code scanning {c['total']} "
                f"tools={tools} → {c['url']}"
            )
    for d in report.get("dependabot") or []:
        if d["total"] > 15:
            print(
                f"- [batch-pr] {d['repo']}: Dependabot {d['total']} "
                f"{d.get('by_severity')} → {d['url']}"
            )

    print()
    print("## PRs to triage")
    for p in report.get("prs") or []:
        cls = p.get("classification") or "human"
        size = p.get("size") or ""
        tag = cls if cls != "human" else size or cls
        print(f"- [{tag}] {p['repo']}#{p['number']} {p['title'][:70]}")
        print(f"    {p['url']}")

    print()
    print("## Issues to triage")
    for i in report.get("issues") or []:
        cls = i.get("classification") or "human"
        size = i.get("size") or ""
        tag = cls if cls != "human" else size or cls
        print(f"- [{tag}] {i['repo']}#{i['number']} {i['title'][:70]}")
        print(f"    {i['url']}")

    dirty = [r for r in (report.get("local") or []) if r.get("dirty")]
    if dirty:
        print()
        print("## Dirty local trees")
        for r in dirty:
            owned = "owned" if r.get("owned") else "other"
            print(f"- {r['name']}: dirty={r['dirty']} ({owned}) {r.get('branch')}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
