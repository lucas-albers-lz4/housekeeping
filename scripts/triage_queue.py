#!/usr/bin/env python3
"""Print a compact triage queue from out/scan-latest.json (read-only)."""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from hygiene_verdicts import (  # noqa: E402
    VERDICT_META,
    finding_id_counts_by_verdict,
    group_hygiene_findings,
    verdict_counts,
)


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

    hygiene = report.get("repo_hygiene") or []
    if hygiene:
        needs = sum(1 for h in hygiene if h.get("score") == "needs-work")
        ok = sum(1 for h in hygiene if h.get("score") == "ok")
        parked = sum(1 for h in hygiene if h.get("score") == "park")
        grouped = group_hygiene_findings(hygiene)
        by_verdict = verdict_counts(grouped)
        id_by_v = finding_id_counts_by_verdict(grouped)

        print("## Hygiene finding counts (by verdict)")
        print(f"- scores: {needs} needs-work · {ok} ok · {parked} park")
        print("- sorted by verdict (exclusions first — why we are not fixing):")
        for key, label, n in by_verdict:
            meta = VERDICT_META.get(key) or {}
            reason = meta.get("reason") or ""
            ids = id_by_v.get(key) or collections.Counter()
            id_s = ", ".join(f"{i}×{c}" for i, c in ids.most_common(6))
            print(f"  - [{label}] {n} findings — {reason}")
            if id_s:
                print(f"      ids: {id_s}")
            # Repo rollup for this verdict
            repos = sorted({i["repo"] for i in grouped.get(key) or [] if i.get("repo")})
            if repos:
                print(f"      repos: {', '.join(repos)}")
        print()

        # Active owned leftovers still listed for convenience
        print("## Repo hygiene — owned / active-fork detail")
        for key in (
            "active_fork",
            "ship_only",
            "suggest_only",
            "tier2_skip",
            "pipeline_skip",
        ):
            items = grouped.get(key) or []
            if not items:
                continue
            print(f"### {VERDICT_META[key]['label']}")
            by_repo: dict[str, list] = collections.defaultdict(list)
            for i in items:
                by_repo[i["repo"]].append(i)
            for repo in sorted(by_repo):
                ids = ", ".join(f"{x['finding_id']}({x.get('severity')})" for x in by_repo[repo])
                url = by_repo[repo][0].get("url") or ""
                print(f"- [{key}] {repo}: {ids}")
                if url:
                    print(f"    {url}")
        print()

    print("## Quick wins (heuristic)")
    for d in report.get("dependabot") or []:
        if d["total"] <= 3:
            sev = d.get("by_severity") or {}
            print(f"- [fix-direct] {d['repo']}: Dependabot {d['total']} {sev} → {d['url']}")
    for c in report.get("code_scanning") or []:
        tools = c.get("by_tool") or {}
        if c["total"] <= 5 and "CodeQL" in tools:
            print(
                f"- [fix-direct] {c['repo']}: Code scanning {c['total']} "
                f"{c.get('top_rules')} → {c['url']}"
            )
        elif c["total"] > 20:
            print(
                f"- [park/batch] {c['repo']}: Code scanning {c['total']} tools={tools} → {c['url']}"
            )
    for d in report.get("dependabot") or []:
        if d["total"] > 15:
            print(
                f"- [batch-pr] {d['repo']}: Dependabot {d['total']} "
                f"{d.get('by_severity')} → {d['url']}"
            )

    print()
    print("## PRs to triage")
    parked_prs = []
    for p in report.get("prs") or []:
        cls = p.get("classification") or "human"
        if cls == "park":
            parked_prs.append(p)
            continue
        size = p.get("size") or ""
        tag = cls if cls != "human" else size or cls
        print(f"- [{tag}] {p['repo']}#{p['number']} {p['title'][:70]}")
        print(f"    {p['url']}")
    if parked_prs:
        print()
        print("## PRs parked (archived — skip)")
        for p in parked_prs:
            print(f"- [park] {p['repo']}#{p['number']} {p['title'][:70]}")
            print(f"    {p['url']}")

    print()
    print("## Issues to triage")
    parked_issues = []
    for i in report.get("issues") or []:
        cls = i.get("classification") or "human"
        if cls == "park":
            parked_issues.append(i)
            continue
        size = i.get("size") or ""
        tag = cls if cls != "human" else size or cls
        print(f"- [{tag}] {i['repo']}#{i['number']} {i['title'][:70]}")
        print(f"    {i['url']}")
    if parked_issues:
        print()
        print("## Issues parked (archived — skip)")
        for i in parked_issues:
            print(f"- [park] {i['repo']}#{i['number']} {i['title'][:70]}")
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
