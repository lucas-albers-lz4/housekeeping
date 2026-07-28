#!/usr/bin/env python3
"""Scan GitHub owner repos for Dependabot, code/secret scanning, PRs, issues, and local dirty trees.

Read-only. Requires: gh (authenticated), python3, jq optional.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import subprocess
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "config.toml"


def load_config(path: Path) -> dict:
    with path.open("rb") as f:
        return tomllib.load(f)


def expand(p: str) -> Path:
    return Path(os.path.expanduser(p)).resolve()


def run_gh(args: list[str], check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["gh", *args],
        capture_output=True,
        text=True,
        check=check,
    )


def gh_json(args: list[str]):
    p = run_gh(args)
    if p.returncode != 0:
        return None, (p.stderr or p.stdout or "").strip()
    if not p.stdout.strip():
        return [], None
    try:
        return json.loads(p.stdout), None
    except json.JSONDecodeError as e:
        return None, f"json decode: {e}"


def gh_api(path: str):
    """GET a GitHub API path with pagination. Returns (data|None, error|None).
    None data + error means unavailable (404/disabled). Empty list is valid.
    """
    p = run_gh(["api", path, "--paginate"])
    if p.returncode != 0:
        err = (p.stderr or p.stdout or "").strip()
        # Disabled features return 404 — treat as unavailable, not empty.
        if "404" in err or "disabled" in err.lower():
            return None, "disabled_or_unavailable"
        return None, err.split("\n")[0][:200]
    if not p.stdout.strip():
        return [], None
    try:
        data = json.loads(p.stdout)
        return (data if isinstance(data, list) else []), None
    except json.JSONDecodeError:
        return None, "invalid_json"


def list_repos(owner: str) -> list[dict]:
    data, err = gh_json(
        [
            "repo",
            "list",
            owner,
            "--limit",
            "200",
            "--json",
            "name,url,isPrivate,updatedAt,description,defaultBranchRef",
        ]
    )
    if err or data is None:
        raise SystemExit(f"Failed to list repos: {err}")
    return data


def scan_dependabot(owner: str, repo: str) -> dict | None:
    alerts, err = gh_api(f"repos/{owner}/{repo}/dependabot/alerts?state=open&per_page=100")
    if alerts is None:
        return None
    by = collections.Counter()
    pkgs = collections.Counter()
    samples = []
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for a in alerts:
        sev = (a.get("security_vulnerability") or {}).get("severity") or "unknown"
        by[sev] += 1
        pkg = ((a.get("dependency") or {}).get("package") or {}).get("name") or "?"
        pkgs[pkg] += 1
    for a in sorted(
        alerts,
        key=lambda x: order.get(
            ((x.get("security_vulnerability") or {}).get("severity") or "z"), 9
        ),
    )[:8]:
        samples.append(
            {
                "number": a.get("number"),
                "severity": (a.get("security_vulnerability") or {}).get("severity"),
                "package": ((a.get("dependency") or {}).get("package") or {}).get("name"),
                "ecosystem": ((a.get("dependency") or {}).get("package") or {}).get(
                    "ecosystem"
                ),
                "advisory": (a.get("security_advisory") or {}).get("summary"),
                "url": a.get("html_url"),
                "manifest": (a.get("dependency") or {}).get("manifest_path"),
            }
        )
    return {
        "repo": repo,
        "total": len(alerts),
        "by_severity": dict(by),
        "top_packages": pkgs.most_common(10),
        "samples": samples,
        "url": f"https://github.com/{owner}/{repo}/security/dependabot",
    }


def scan_code_scanning(owner: str, repo: str) -> dict | None:
    alerts, err = gh_api(
        f"repos/{owner}/{repo}/code-scanning/alerts?state=open&per_page=100"
    )
    if alerts is None:
        return None
    by = collections.Counter()
    tools = collections.Counter()
    rules = collections.Counter()
    samples = []
    for a in alerts:
        sev = (
            (a.get("rule") or {}).get("security_severity")
            or (a.get("rule") or {}).get("severity")
            or "unknown"
        )
        by[sev] += 1
        tools[((a.get("tool") or {}).get("name") or "?")] += 1
        rules[((a.get("rule") or {}).get("id") or "?")] += 1
    for a in alerts[:10]:
        samples.append(
            {
                "number": a.get("number"),
                "severity": (a.get("rule") or {}).get("security_severity")
                or (a.get("rule") or {}).get("severity"),
                "rule": (a.get("rule") or {}).get("id"),
                "description": (a.get("rule") or {}).get("description"),
                "tool": (a.get("tool") or {}).get("name"),
                "url": a.get("html_url"),
            }
        )
    return {
        "repo": repo,
        "total": len(alerts),
        "by_severity": dict(by),
        "by_tool": dict(tools),
        "top_rules": rules.most_common(8),
        "samples": samples,
        "url": f"https://github.com/{owner}/{repo}/security/code-scanning",
    }


def scan_secrets(owner: str, repo: str) -> dict | None:
    alerts, err = gh_api(
        f"repos/{owner}/{repo}/secret-scanning/alerts?state=open&per_page=100"
    )
    if alerts is None:
        return None
    if not alerts:
        return {"repo": repo, "total": 0, "types": {}, "items": []}
    types = collections.Counter(
        a.get("secret_type_display_name") or a.get("secret_type") for a in alerts
    )
    return {
        "repo": repo,
        "total": len(alerts),
        "types": dict(types),
        "items": [
            {
                "number": a.get("number"),
                "type": a.get("secret_type_display_name") or a.get("secret_type"),
                "validity": a.get("validity"),
                "url": a.get("html_url"),
                "created": a.get("created_at"),
            }
            for a in alerts
        ],
        "url": f"https://github.com/{owner}/{repo}/security/secret-scanning",
    }


def label_names(obj: dict) -> list[str]:
    return [l.get("name") for l in (obj.get("labels") or []) if l.get("name")]


def classify_item(
    repo: str,
    labels: list[str],
    cfg: dict,
) -> str:
    pipeline_repos = set(cfg.get("pipeline_repos") or [])
    pipeline_labels = set(cfg.get("pipeline_labels") or [])
    never_merge = set(cfg.get("never_merge_labels") or [])
    if never_merge.intersection(labels):
        return "never-merge"
    if repo in pipeline_repos and pipeline_labels.intersection(labels):
        return "pipeline"
    if pipeline_labels.intersection(labels):
        return "pipeline"
    return "human"


def scan_prs(owner: str, repo: str, cfg: dict) -> list[dict]:
    data, err = gh_json(
        [
            "pr",
            "list",
            "--repo",
            f"{owner}/{repo}",
            "--state",
            "open",
            "--limit",
            "50",
            "--json",
            "number,title,url,createdAt,updatedAt,author,labels,isDraft,reviewDecision",
        ]
    )
    if not data:
        return []
    out = []
    for pr in data:
        labels = label_names(pr)
        author = (pr.get("author") or {}).get("login") or "?"
        out.append(
            {
                "repo": repo,
                "number": pr.get("number"),
                "title": pr.get("title"),
                "url": pr.get("url"),
                "author": author,
                "is_bot": author.startswith("app/") or "dependabot" in author,
                "labels": labels,
                "isDraft": pr.get("isDraft"),
                "classification": classify_item(repo, labels, cfg),
                "createdAt": pr.get("createdAt"),
                "updatedAt": pr.get("updatedAt"),
            }
        )
    return out


def scan_issues(owner: str, repo: str, cfg: dict) -> list[dict]:
    data, err = gh_json(
        [
            "issue",
            "list",
            "--repo",
            f"{owner}/{repo}",
            "--state",
            "open",
            "--limit",
            "100",
            "--json",
            "number,title,url,createdAt,updatedAt,author,labels,assignees",
        ]
    )
    if not data:
        return []
    out = []
    for issue in data:
        labels = label_names(issue)
        out.append(
            {
                "repo": repo,
                "number": issue.get("number"),
                "title": issue.get("title"),
                "url": issue.get("url"),
                "author": (issue.get("author") or {}).get("login"),
                "labels": labels,
                "classification": classify_item(repo, labels, cfg),
                "createdAt": issue.get("createdAt"),
                "updatedAt": issue.get("updatedAt"),
            }
        )
    return out


def local_status(gitroot: Path, owner: str) -> list[dict]:
    if not gitroot.is_dir():
        return []
    rows = []
    for child in sorted(gitroot.iterdir()):
        if not child.is_dir():
            continue
        gitdir = child / ".git"
        if not gitdir.exists():
            rows.append({"name": child.name, "git": False})
            continue
        branch = (
            subprocess.run(
                ["git", "-C", str(child), "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True,
                text=True,
            ).stdout.strip()
            or "?"
        )
        remote = (
            subprocess.run(
                ["git", "-C", str(child), "remote", "get-url", "origin"],
                capture_output=True,
                text=True,
            ).stdout.strip()
            or ""
        )
        dirty = len(
            subprocess.run(
                ["git", "-C", str(child), "status", "--porcelain"],
                capture_output=True,
                text=True,
            ).stdout.splitlines()
        )
        ahead = behind = None
        ab = subprocess.run(
            [
                "git",
                "-C",
                str(child),
                "rev-list",
                "--left-right",
                "--count",
                "HEAD...@{u}",
            ],
            capture_output=True,
            text=True,
        )
        if ab.returncode == 0 and ab.stdout.strip():
            parts = ab.stdout.strip().split()
            if len(parts) == 2:
                ahead, behind = int(parts[0]), int(parts[1])
        owned = owner.lower() in remote.lower()
        rows.append(
            {
                "name": child.name,
                "git": True,
                "branch": branch,
                "dirty": dirty,
                "ahead": ahead,
                "behind": behind,
                "remote": remote,
                "owned": owned,
            }
        )
    return rows


def suggest_size(item: dict, kind: str) -> str:
    """Heuristic size tag for triage boards."""
    cls = item.get("classification")
    if cls == "pipeline":
        return "pipeline"
    if cls == "never-merge":
        return "never-merge"
    if kind == "pr" and item.get("is_bot"):
        title = (item.get("title") or "").lower()
        # Single-package bumps tend to be small; group updates are batch.
        if "group" in title or "across" in title:
            return "batch-pr"
        return "fix-direct"
    if kind == "issue":
        return "issue-pr"
    return "review"


def print_summary(report: dict) -> None:
    dep = report["dependabot"]
    code = report["code_scanning"]
    secrets = report["secrets"]
    prs = report["prs"]
    issues = report["issues"]

    print("=== SUMMARY ===")
    print(f"owner: {report['owner']}")
    print(f"repos: {report['repo_count']}")
    print(
        f"dependabot: {sum(d['total'] for d in dep)} across {len(dep)} repos"
    )
    print(
        f"code scanning: {sum(c['total'] for c in code)} across {len(code)} repos"
    )
    print(
        f"secrets: {sum(s['total'] for s in secrets if s.get('total'))} across "
        f"{sum(1 for s in secrets if s.get('total'))} repos"
    )
    print(f"open PRs: {len(prs)}")
    print(f"open issues: {len(issues)}")
    pipe_prs = sum(1 for p in prs if p["classification"] in ("pipeline", "never-merge"))
    pipe_issues = sum(1 for i in issues if i["classification"] == "pipeline")
    print(f"pipeline-classified PRs: {pipe_prs}")
    print(f"pipeline-classified issues: {pipe_issues}")
    print()

    if dep:
        print("--- Dependabot by repo ---")
        for d in sorted(dep, key=lambda x: -x["total"]):
            print(f"  {d['repo']}: {d['total']} {d['by_severity']}")
        print()

    if code:
        print("--- Code scanning by repo ---")
        for c in sorted(code, key=lambda x: -x["total"]):
            print(f"  {c['repo']}: {c['total']} {c['by_severity']} tools={c['by_tool']}")
        print()

    human_prs = [p for p in prs if p["classification"] == "human"]
    pipe = [p for p in prs if p["classification"] != "human"]
    if human_prs:
        print("--- Open PRs (human / dep triage) ---")
        for p in human_prs:
            print(
                f"  {p['repo']}#{p['number']} [{p.get('size')}] "
                f"{p['author']}: {p['title'][:70]}"
            )
        print()
    if pipe:
        print("--- Open PRs (pipeline / never-merge) ---")
        for p in pipe:
            print(
                f"  {p['repo']}#{p['number']} [{p['classification']}] "
                f"{p['title'][:70]}"
            )
        print()

    human_issues = [i for i in issues if i["classification"] == "human"]
    pipe_i = [i for i in issues if i["classification"] != "human"]
    if human_issues:
        print("--- Open issues (human) ---")
        for i in human_issues:
            print(f"  {i['repo']}#{i['number']}: {i['title'][:80]}")
        print()
    if pipe_i:
        print("--- Open issues (pipeline — leave to workflow) ---")
        for i in pipe_i:
            labs = ",".join(i["labels"][:5])
            print(f"  {i['repo']}#{i['number']} [{labs}]: {i['title'][:60]}")
        print()

    dirty = [r for r in report.get("local", []) if r.get("dirty")]
    if dirty:
        print("--- Dirty local checkouts ---")
        for r in dirty:
            print(f"  {r['name']}: dirty={r['dirty']} branch={r.get('branch')}")
        print()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    ap.add_argument("--owner", help="GitHub owner/org (overrides config)")
    ap.add_argument("--gitroot", help="Local checkouts root (overrides config)")
    ap.add_argument(
        "--out",
        type=Path,
        help="Write full JSON report here (default: out/scan-<timestamp>.json)",
    )
    ap.add_argument(
        "--skip-local",
        action="store_true",
        help="Skip ~/gitroot dirty-tree scan",
    )
    ap.add_argument(
        "--skip-alerts",
        action="store_true",
        help="Skip Dependabot / code / secret scanning",
    )
    ap.add_argument(
        "--repos",
        help="Comma-separated repo names to scan (default: all owned)",
    )
    args = ap.parse_args()

    cfg = load_config(args.config) if args.config.exists() else {}
    owner = args.owner or cfg.get("owner") or "lucas-albers-lz4"
    gitroot = expand(args.gitroot or cfg.get("gitroot") or "~/gitroot")
    out_dir = expand(str(ROOT / (cfg.get("out_dir") or "out")))

    repos = list_repos(owner)
    if args.repos:
        want = {n.strip() for n in args.repos.split(",") if n.strip()}
        repos = [r for r in repos if r["name"] in want]

    print(f"Scanning {len(repos)} repos for {owner} …", file=sys.stderr)

    dependabot = []
    code_scanning = []
    secrets = []
    prs = []
    issues = []

    for i, r in enumerate(repos, 1):
        name = r["name"]
        print(f"  [{i}/{len(repos)}] {name}", file=sys.stderr)
        if not args.skip_alerts:
            d = scan_dependabot(owner, name)
            if d and d["total"]:
                dependabot.append(d)
            c = scan_code_scanning(owner, name)
            if c and c["total"]:
                code_scanning.append(c)
            s = scan_secrets(owner, name)
            if s and s.get("total"):
                secrets.append(s)
        for pr in scan_prs(owner, name, cfg):
            pr["size"] = suggest_size(pr, "pr")
            prs.append(pr)
        for issue in scan_issues(owner, name, cfg):
            issue["size"] = suggest_size(issue, "issue")
            issues.append(issue)

    local = [] if args.skip_local else local_status(gitroot, owner)

    report = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "owner": owner,
        "gitroot": str(gitroot),
        "repo_count": len(repos),
        "repos": [r["name"] for r in repos],
        "dependabot": sorted(dependabot, key=lambda x: -x["total"]),
        "code_scanning": sorted(code_scanning, key=lambda x: -x["total"]),
        "secrets": sorted(secrets, key=lambda x: -x.get("total", 0)),
        "prs": prs,
        "issues": issues,
        "local": local,
        "config": {
            "pipeline_repos": cfg.get("pipeline_repos"),
            "pipeline_labels": cfg.get("pipeline_labels"),
            "never_merge_labels": cfg.get("never_merge_labels"),
        },
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = args.out or (out_dir / f"scan-{stamp}.json")
    out_path.write_text(json.dumps(report, indent=2) + "\n")
    # Also write latest symlink-style copy for agents
    latest = out_dir / "scan-latest.json"
    latest.write_text(json.dumps(report, indent=2) + "\n")

    print_summary(report)
    print(f"Wrote {out_path}")
    print(f"Wrote {latest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
