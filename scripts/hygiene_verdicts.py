"""Classify repo hygiene findings into triage verdicts (display / queue).

Verdicts are sorted by how we treat them in cleanup — exclusions first so the
board shows *why* something is not in the active fix queue.
"""

from __future__ import annotations

import tomllib
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "config.toml"

# Display order: exclusions / deferrals before anything you'd actively fix.
VERDICT_ORDER = [
    "park_archived",
    "park_fork",
    "park_repo",
    "tier2_skip",
    "pipeline_skip",
    "suggest_only",
    "ship_only",
    "active_fork",
]

VERDICT_META = {
    "park_archived": {
        "label": "Park — archived",
        "reason": "Archived repos; ignore in cleanup.",
    },
    "park_fork": {
        "label": "Park — fork noise",
        "reason": "Fork gaps; park unless listed in config active_forks.",
    },
    "park_repo": {
        "label": "Park — config parked_repos",
        "reason": "Explicitly parked owned repos (class/experiment clones).",
    },
    "active_fork": {
        "label": "Active fork — fix",
        "reason": "Forks you maintain (config active_forks); keep Dependabot/settings current.",
    },
    "tier2_skip": {
        "label": "Tier-2 skipped by design",
        "reason": "dependency-review etc. deferred (noise vs benefit this pass).",
    },
    "pipeline_skip": {
        "label": "Pipeline — leave alone",
        "reason": "Pipeline repos (config pipeline_repos): skip optional CodeQL noise.",
    },
    "suggest_only": {
        "label": "Suggest only — human confirm",
        "reason": (
            "Polish or destructive/ambiguous cleanup (README badges, About "
            "metadata, stale merged branches). List for human; never auto-apply."
        ),
    },
    "ship_only": {
        "label": "Only if shipping",
        "reason": (
            "CI / CodeQL / Node-20 action pins on quiet or toolkit repos — "
            "fix only if you ship them."
        ),
    },
}

TIER2_FINDING_IDS = {"dependency_review_missing"}
SUGGEST_ONLY_FINDING_IDS = {
    "stale_merged_branches",
    "readme_badges_thin",
    "about_metadata_thin",
}


def _load_config(config_path: Path | None = None) -> dict[str, Any]:
    path = config_path or DEFAULT_CONFIG
    if not path.exists():
        return {}
    with path.open("rb") as f:
        return tomllib.load(f)


def load_active_forks(config_path: Path | None = None) -> set[str]:
    return set(_load_config(config_path).get("active_forks") or [])


def load_pipeline_repos(config_path: Path | None = None) -> set[str]:
    return set(_load_config(config_path).get("pipeline_repos") or [])


def load_parked_repos(config_path: Path | None = None) -> set[str]:
    return set(_load_config(config_path).get("parked_repos") or [])


def classify_finding(
    repo_row: dict[str, Any],
    finding: dict[str, Any],
    active_forks: set[str] | None = None,
    pipeline_repos: set[str] | None = None,
    parked_repos: set[str] | None = None,
) -> str:
    """Return a VERDICT_ORDER key for one finding on one repo."""
    active = active_forks if active_forks is not None else load_active_forks()
    pipelines = (
        pipeline_repos if pipeline_repos is not None else load_pipeline_repos()
    )
    parked = parked_repos if parked_repos is not None else load_parked_repos()
    fid = finding.get("id") or ""
    repo = repo_row.get("repo") or ""
    if fid == "archived" or repo_row.get("archived"):
        return "park_archived"
    if repo in parked:
        return "park_repo"
    # README/About polish + branch cleanup — always suggest-only (even on active forks).
    if fid in SUGGEST_ONLY_FINDING_IDS:
        return "suggest_only"
    if repo_row.get("fork"):
        if repo in active:
            return "active_fork"
        return "park_fork"
    if fid in TIER2_FINDING_IDS:
        return "tier2_skip"
    if repo in pipelines and fid == "code_scanning_not_configured":
        return "pipeline_skip"
    return "ship_only"


def group_hygiene_findings(
    hygiene: list[dict[str, Any]],
    active_forks: set[str] | None = None,
    pipeline_repos: set[str] | None = None,
    parked_repos: set[str] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Map verdict → list of {repo, finding_id, severity, size, private, fork}."""
    active = active_forks if active_forks is not None else load_active_forks()
    pipelines = (
        pipeline_repos if pipeline_repos is not None else load_pipeline_repos()
    )
    parked = parked_repos if parked_repos is not None else load_parked_repos()
    grouped: dict[str, list[dict[str, Any]]] = {k: [] for k in VERDICT_ORDER}
    for h in hygiene:
        for f in h.get("findings") or []:
            verdict = classify_finding(h, f, active, pipelines, parked)
            grouped.setdefault(verdict, []).append(
                {
                    "repo": h.get("repo"),
                    "finding_id": f.get("id"),
                    "severity": f.get("severity"),
                    "size": f.get("size"),
                    "private": bool(h.get("private")),
                    "fork": bool(h.get("fork")),
                    "url": h.get("url"),
                }
            )
    for v, items_v in grouped.items():
        items_v.sort(key=lambda x: (x.get("finding_id") or "", x.get("repo") or ""))
    return grouped


def verdict_counts(grouped: dict[str, list]) -> list[tuple[str, str, int]]:
    """Ordered (verdict_key, label, count) for charts / summaries."""
    out = []
    for key in VERDICT_ORDER:
        n = len(grouped.get(key) or [])
        if n:
            out.append((key, VERDICT_META[key]["label"], n))
    for key, items in grouped.items():
        if key not in VERDICT_ORDER and items:
            out.append((key, key, len(items)))
    return out


def finding_id_counts_by_verdict(
    grouped: dict[str, list],
) -> dict[str, Counter]:
    out: dict[str, Counter] = {}
    for key, items in grouped.items():
        c = Counter(i["finding_id"] for i in items)
        if c:
            out[key] = c
    return out
