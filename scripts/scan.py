#!/usr/bin/env python3
"""Scan GitHub owner repos for Dependabot, code/secret scanning, PRs, issues,
repo hygiene (config/automation), and local dirty trees.

Read-only. Requires: gh (authenticated), python3, jq optional.
"""

from __future__ import annotations

import argparse
import base64
import collections
import contextlib
import json
import re
import subprocess
import sys
import tomllib
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "config.toml"

# Path patterns → Dependabot package-ecosystem ids.
MANIFEST_ECOSYSTEMS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(^|/)go\.mod$"), "gomod"),
    (
        re.compile(
            r"(^|/)package-lock\.json$|(^|/)package\.json$|(^|/)yarn\.lock$|(^|/)pnpm-lock\.yaml$"
        ),
        "npm",
    ),  # noqa: E501
    (
        re.compile(
            r"(^|/)requirements[^/]*\.txt$|(^|/)Pipfile(\.lock)?$|(^|/)poetry\.lock$|(^|/)pyproject\.toml$"
        ),
        "pip",
    ),  # noqa: E501
    (re.compile(r"(^|/)Cargo\.(toml|lock)$"), "cargo"),
    (re.compile(r"(^|/)Gemfile(\.lock)?$"), "bundler"),
    (re.compile(r"(^|/)composer\.(json|lock)$"), "composer"),
    (re.compile(r"(^|/)Dockerfile[^/]*$|(^|/)docker-compose\.ya?ml$"), "docker"),
    (re.compile(r"(^|/)\.github/workflows/[^/]+\.ya?ml$"), "github-actions"),
]

DEPENDABOT_ECOSYSTEM_RE = re.compile(r"package-ecosystem:\s*[\"']?([a-zA-Z0-9_-]+)[\"']?")

# Workflow `uses:` pins — capture action@ref (skip local ./ and docker://).
USES_ACTION_RE = re.compile(r"(?m)^\s*(?:-\s*)?uses:\s*[\"']?([^\"'\s#]+)[\"']?")

# First-party actions whose older majors still declare a Node 20 action runtime.
# Bump majors to clear GitHub's "Node.js 20 is deprecated … forced to Node.js 24"
# warning (job node-version / setup-python version is unrelated).
DEFAULT_NODE20_ACTION_MIN_MAJORS: dict[str, int] = {
    "actions/checkout": 5,
    "actions/setup-node": 5,
    "actions/setup-python": 6,
    "actions/cache": 5,
    "actions/upload-artifact": 5,
    "actions/download-artifact": 5,
}

# Branch cleanup defaults (suggest-only; never auto-delete in scan).
DEFAULT_BRANCH_CLEANUP: dict = {
    "enabled": True,
    "merged_retention_days": 30,
    "max_merged_prs": 100,
    "max_list": 15,
    "protected_names": [
        "main",
        "master",
        "develop",
        "dev",
        "staging",
        "production",
        "gh-pages",
    ],
    "protected_prefixes": [
        "release/",
        "dependabot/",
        "renovate/",
    ],
}

# README badges + GitHub About metadata (suggest-only polish).
DEFAULT_README_POLISH: dict = {
    "enabled": True,
}

# Markdown / HTML badge image markup in READMEs.
_MD_BADGE_RE = re.compile(r"!\[([^\]]*)\]\(([^)]+)\)")
_HTML_IMG_RE = re.compile(
    r"<img\b[^>]*(?:alt\s*=\s*[\"']([^\"']*)[\"'][^>]*src\s*=\s*[\"']([^\"']+)[\"']"
    r"|src\s*=\s*[\"']([^\"']+)[\"'][^>]*alt\s*=\s*[\"']([^\"']*)[\"'])[^>]*>",
    re.I,
)
_SHIELDS_URL_RE = re.compile(r"https?://img\.shields\.io/[^\s\)\"'<>]+", re.I)
_ACTIONS_BADGE_RE = re.compile(r"https?://github\.com/[^\s\)\"'<>]+/badge\.svg[^\s\)\"'<>]*", re.I)
_RST_IMAGE_RE = re.compile(r"\.\.\s+image::\s+(\S+)", re.I)

README_CANDIDATES = (
    "README.md",
    "README.rst",
    "README",
    "README.txt",
    "Readme.md",
    "readme.md",
)


def load_config(path: Path) -> dict:
    with path.open("rb") as f:
        return tomllib.load(f)


def expand(p: str) -> Path:
    return Path(p).expanduser().resolve()


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


def gh_api_object(path: str):
    """GET a single JSON object (no pagination flatten). Returns (dict|None, err)."""
    p = run_gh(["api", path])
    if p.returncode != 0:
        err = (p.stderr or p.stdout or "").strip()
        if "404" in err or "disabled" in err.lower():
            return None, "disabled_or_unavailable"
        return None, err.split("\n")[0][:200]
    if not p.stdout.strip():
        return None, "empty"
    try:
        data = json.loads(p.stdout)
        if isinstance(data, dict):
            return data, None
        return None, "not_object"
    except json.JSONDecodeError:
        return None, "invalid_json"


def gh_api_status(path: str) -> int | None:
    """GET and return HTTP status (via -i). None on unexpected failure."""
    p = run_gh(["api", path, "-i"])
    # gh still exits non-zero on 404; parse status from headers either way.
    text = (p.stdout or "") + "\n" + (p.stderr or "")
    m = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", text)
    if m:
        return int(m.group(1))
    return None


def sa_status(security_and_analysis: dict | None, key: str) -> str | None:
    if not security_and_analysis:
        return None
    block = security_and_analysis.get(key) or {}
    return block.get("status")


def list_repos(owner: str) -> list[dict]:
    data, err = gh_json(
        [
            "repo",
            "list",
            owner,
            "--limit",
            "200",
            "--json",
            "name,url,isPrivate,isFork,isArchived,updatedAt,description,defaultBranchRef",
        ]
    )
    if err or data is None:
        raise SystemExit(f"Failed to list repos: {err}")
    return data


def _default_branch(repo_meta: dict) -> str:
    ref = repo_meta.get("defaultBranchRef")
    if isinstance(ref, dict):
        return ref.get("name") or "main"
    if isinstance(ref, str) and ref:
        return ref
    return repo_meta.get("default_branch") or "main"


def _repo_tree_paths(owner: str, repo: str, branch: str) -> list[str] | None:
    """Recursive git tree paths for default branch, or None if unavailable."""
    data, err = gh_api_object(f"repos/{owner}/{repo}/git/trees/{branch}?recursive=1")
    if data is None:
        return None
    if data.get("truncated"):
        # Truncated trees still usable for shallow path checks; continue.
        pass
    return [t.get("path") for t in (data.get("tree") or []) if t.get("path")]


def _detect_ecosystems(paths: list[str]) -> set[str]:
    found: set[str] = set()
    for path in paths:
        for pat, eco in MANIFEST_ECOSYSTEMS:
            if pat.search(path):
                found.add(eco)
    return found


def _fetch_file_text(owner: str, repo: str, path: str) -> str | None:
    data, err = gh_api_object(f"repos/{owner}/{repo}/contents/{path}")
    if not data or data.get("type") != "file":
        return None
    content = data.get("content")
    if not content:
        return None
    try:
        return base64.b64decode(content).decode("utf-8", errors="replace")
    except Exception:
        return None


def _dependabot_ecosystems(yml_text: str | None) -> set[str]:
    if not yml_text:
        return set()
    return set(DEPENDABOT_ECOSYSTEM_RE.findall(yml_text))


def _action_major(ref: str) -> int | None:
    """Parse major from refs like v4, v4.2.2, 5, 5.0.0. None if unparseable."""
    ref = (ref or "").strip()
    if re.fullmatch(r"[0-9a-f]{40}", ref.lower()):
        return None
    m = re.match(r"^v?(\d+)(?:\.|$)", ref, re.I)
    if not m:
        return None
    return int(m.group(1))


def _load_node20_min_majors(cfg: dict | None) -> dict[str, int]:
    raw = (cfg or {}).get("node20_action_min_majors")
    if not isinstance(raw, dict) or not raw:
        return dict(DEFAULT_NODE20_ACTION_MIN_MAJORS)
    out = dict(DEFAULT_NODE20_ACTION_MIN_MAJORS)
    for k, v in raw.items():
        try:
            out[str(k)] = int(v)
        except (TypeError, ValueError):
            continue
    return out


def _scan_node20_action_pins(
    owner: str,
    repo: str,
    workflow_paths: list[str],
    min_majors: dict[str, int],
) -> list[dict]:
    """Return [{action, ref, major, need, workflow}, ...] for Node-20-runtime pins."""
    hits: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for wf in workflow_paths:
        text = _fetch_file_text(owner, repo, wf)
        if not text:
            continue
        for raw in USES_ACTION_RE.findall(text):
            pin = raw.strip()
            if pin.startswith(("./", "docker://")):
                continue
            if "@" not in pin:
                continue
            action, _, ref = pin.partition("@")
            action = action.strip()
            ref = ref.strip()
            need = min_majors.get(action)
            if need is None:
                continue
            major = _action_major(ref)
            if major is None or major >= need:
                continue
            key = (action, ref, wf)
            if key in seen:
                continue
            seen.add(key)
            hits.append(
                {
                    "action": action,
                    "ref": ref,
                    "major": major,
                    "need": need,
                    "workflow": wf,
                }
            )
    hits.sort(key=lambda h: (h["action"], h["workflow"], h["ref"]))
    return hits


def _load_branch_cleanup_cfg(cfg: dict | None) -> dict:
    raw = (cfg or {}).get("branch_cleanup")
    out = dict(DEFAULT_BRANCH_CLEANUP)
    if not isinstance(raw, dict):
        return out
    if "enabled" in raw:
        out["enabled"] = bool(raw["enabled"])
    for key in ("merged_retention_days", "max_merged_prs", "max_list"):
        if key in raw:
            with contextlib.suppress(TypeError, ValueError):
                out[key] = int(raw[key])
    if isinstance(raw.get("protected_names"), list):
        out["protected_names"] = [str(x) for x in raw["protected_names"]]
    if isinstance(raw.get("protected_prefixes"), list):
        out["protected_prefixes"] = [str(x) for x in raw["protected_prefixes"]]
    return out


def _load_readme_polish_cfg(cfg: dict | None) -> dict:
    raw = (cfg or {}).get("readme_polish")
    out = dict(DEFAULT_README_POLISH)
    if not isinstance(raw, dict):
        return out
    if "enabled" in raw:
        out["enabled"] = bool(raw["enabled"])
    return out


def _readme_path(paths: list[str]) -> str | None:
    """First root-level README candidate present in the tree."""
    path_set = set(paths)
    for name in README_CANDIDATES:
        if name in path_set:
            return name
    # Case-insensitive fallback for odd casings at repo root.
    lower_map = {p.lower(): p for p in paths if "/" not in p}
    for name in README_CANDIDATES:
        hit = lower_map.get(name.lower())
        if hit:
            return hit
    return None


def _has_license_file(paths: list[str]) -> bool:
    for p in paths:
        if "/" in p:
            continue
        base = p.upper()
        if base == "LICENSE" or base.startswith("LICENSE.") or base == "COPYING":
            return True
        if base.startswith("COPYING."):
            return True
    return False


def _readme_badge_blobs(text: str) -> list[str]:
    """Lowercased alt+url blobs for badge-like images in README text."""
    blobs: list[str] = []
    for m in _MD_BADGE_RE.finditer(text):
        blobs.append(f"{m.group(1)} {m.group(2)}".lower())
    for m in _HTML_IMG_RE.finditer(text):
        alt = m.group(1) or m.group(4) or ""
        src = m.group(2) or m.group(3) or ""
        blobs.append(f"{alt} {src}".lower())
    for m in _RST_IMAGE_RE.finditer(text):
        blobs.append(m.group(1).lower())
    for m in _SHIELDS_URL_RE.finditer(text):
        blobs.append(m.group(0).lower())
    for m in _ACTIONS_BADGE_RE.finditer(text):
        blobs.append(m.group(0).lower())
    return blobs


def _blob_is_license_badge(blob: str) -> bool:
    """True if blob looks like a license badge (not a workflow named license-*)."""
    # Actions / workflow status badges are CI, even if the workflow name mentions license.
    if "actions/workflows/" in blob or "github/actions/workflow" in blob:
        return False
    if "badge/license" in blob:
        return True
    if "img.shields.io" in blob and re.search(r"\blicense\b", blob):
        return True
    # Markdown/HTML alt text precedes the URL.
    alt = blob.split("http", 1)[0]
    return bool(re.search(r"\blicense\b", alt))


def _badge_categories_present(blobs: list[str]) -> set[str]:
    """Heuristic categories covered by README badge markup."""
    found: set[str] = set()
    for blob in blobs:
        if (
            "/badge.svg" in blob
            or re.search(r"\b(tests?|ci|build|workflow)\b", blob)
            or "actions/workflows" in blob
        ):
            found.add("ci")
        if _blob_is_license_badge(blob):
            found.add("license")
        if (
            "pypi.org" in blob
            or "pypi/" in blob
            or "npmjs.com" in blob
            or "/npm/" in blob
            or "crates.io" in blob
            or "crates/" in blob
            or "badge/pypi" in blob
        ):
            found.add("package")
    return found


def _missing_readme_badge_categories(
    blobs: list[str],
    *,
    has_workflows: bool,
    has_license: bool,
) -> list[str]:
    """Applicable badge categories not present in README.

    Package-registry badges (PyPI/npm/crates) are intentionally not required:
    local manifests often do not mean a published package of the same name.
    """
    present = _badge_categories_present(blobs)
    missing: list[str] = []
    if has_workflows and "ci" not in present:
        missing.append("ci")
    if has_license and "license" not in present:
        missing.append("license")
    return missing


def _repo_topics(owner: str, repo: str, meta: dict) -> list[str]:
    """Topic names for a repo (dedicated topics endpoint, then meta fallback)."""
    data, _err = gh_api_object(f"repos/{owner}/{repo}/topics")
    if isinstance(data, dict) and isinstance(data.get("names"), list):
        return [str(x) for x in data["names"] if x]
    topics = meta.get("topics")
    if isinstance(topics, list):
        return [str(x) for x in topics if x]
    return []


def _branch_is_protected(name: str, cleanup_cfg: dict) -> bool:
    if name in set(cleanup_cfg.get("protected_names") or []):
        return True
    return any(name.startswith(pref) for pref in (cleanup_cfg.get("protected_prefixes") or []))


def _remote_branch_exists(owner: str, repo: str, name: str) -> bool:
    """True if refs/heads/<name> exists (name may contain '/')."""
    p = run_gh(["api", f"repos/{owner}/{repo}/git/ref/heads/{name}"])
    return p.returncode == 0


def _open_pr_branch_names(owner: str, repo: str) -> set[str] | None:
    """Head + base ref names for all open PRs. None = fail closed (API error)."""
    names: set[str] = set()
    page = 1
    max_pages = 50
    while page <= max_pages:
        p = run_gh(
            [
                "api",
                f"repos/{owner}/{repo}/pulls?state=open&per_page=100&page={page}",
            ]
        )
        if p.returncode != 0:
            return None
        if not p.stdout.strip():
            break
        try:
            batch = json.loads(p.stdout)
        except json.JSONDecodeError:
            return None
        if not isinstance(batch, list):
            return None
        if not batch:
            break
        for pr in batch:
            head = ((pr.get("head") or {}).get("ref") or "").strip()
            base = ((pr.get("base") or {}).get("ref") or "").strip()
            if head:
                names.add(head)
            if base:
                names.add(base)
        if len(batch) < 100:
            break
        # Full page at the page cap → inventory incomplete; fail closed.
        if page == max_pages:
            return None
        page += 1
    return names


def _latest_merge_for_branch(owner: str, repo: str, branch: str) -> dict | None | bool:
    """Latest merged PR for a head branch.

    Returns:
      dict with name/pr/merged_at/_ts — latest merge found
      None — no merged PR for this head
      False — API failure (caller must not suggest)
    """
    # head filter is owner:ref for same-repo (and most fork) PRs.
    p = run_gh(
        [
            "api",
            f"repos/{owner}/{repo}/pulls?state=closed&head={owner}:{branch}&per_page=30",
        ]
    )
    if p.returncode != 0:
        return False
    if not p.stdout.strip():
        return None
    try:
        batch = json.loads(p.stdout)
    except json.JSONDecodeError:
        return False
    if not isinstance(batch, list):
        return False
    best: dict | None = None
    for pr in batch:
        merged_at = pr.get("merged_at") or ""
        if not merged_at:
            continue
        head = ((pr.get("head") or {}).get("ref") or "").strip()
        if head != branch:
            continue
        try:
            ts = datetime.fromisoformat(merged_at.replace("Z", "+00:00")).timestamp()
        except ValueError:
            continue
        if best is None or ts > best["_ts"]:
            best = {
                "name": branch,
                "pr": pr.get("number"),
                "merged_at": merged_at,
                "_ts": ts,
            }
    return best


def _scan_stale_merged_branches(
    owner: str,
    repo: str,
    default_branch: str,
    cleanup_cfg: dict,
) -> list[dict]:
    """Suggest-only: remote heads of merged PRs past retention, still present.

    Cautious filters — never includes default/protected branches, heads/bases of
    open PRs, or branches without a merged PR. Uses the *latest* merge per
    branch (verified via head filter, not only the merged-PR sample) so a
    recent re-merge keeps the branch out of the list. Fail closed if open PRs
    cannot be fully listed. Scan does not delete anything.
    """
    if not cleanup_cfg.get("enabled", True):
        return []

    retention = int(cleanup_cfg.get("merged_retention_days") or 30)
    max_prs = int(cleanup_cfg.get("max_merged_prs") or 100)
    max_list = int(cleanup_cfg.get("max_list") or 15)

    cutoff = datetime.now(UTC).timestamp() - retention * 86400

    merged, err = gh_json(
        [
            "pr",
            "list",
            "--repo",
            f"{owner}/{repo}",
            "--state",
            "merged",
            "--limit",
            str(max_prs),
            "--json",
            "number,headRefName,mergedAt",
        ]
    )
    if err or not isinstance(merged, list):
        return []

    # Fail closed: without a complete open-PR set we must not suggest deletes.
    in_use = _open_pr_branch_names(owner, repo)
    if in_use is None:
        return []

    # Seed candidates from the merged-PR sample (latest in-sample per name).
    latest: dict[str, dict] = {}
    for pr in merged:
        name = (pr.get("headRefName") or "").strip()
        merged_at = pr.get("mergedAt") or ""
        if not name or not merged_at:
            continue
        if name == default_branch or _branch_is_protected(name, cleanup_cfg):
            continue
        if name in in_use:
            continue
        try:
            ts = datetime.fromisoformat(merged_at.replace("Z", "+00:00")).timestamp()
        except ValueError:
            continue
        prev = latest.get(name)
        if prev is None or ts > prev["_ts"]:
            latest[name] = {
                "name": name,
                "pr": pr.get("number"),
                "merged_at": merged_at,
                "_ts": ts,
            }

    # Rough pre-filter, then verify true latest merge per head (sample order
    # is by createdAt, so re-merges can sit outside max_merged_prs).
    seed = [row for row in latest.values() if row["_ts"] <= cutoff]
    seed.sort(key=lambda x: x["_ts"])

    out: list[dict] = []
    for row in seed:
        if len(out) >= max_list:
            break
        verified = _latest_merge_for_branch(owner, repo, row["name"])
        if verified is False:
            # Fail closed for this branch — do not suggest.
            continue
        if verified is None:
            continue
        if verified["_ts"] > cutoff:
            continue
        if verified["name"] in in_use:
            continue
        if not _remote_branch_exists(owner, repo, verified["name"]):
            continue
        out.append(
            {
                "name": verified["name"],
                "pr": verified["pr"],
                "merged_at": verified["merged_at"],
            }
        )
    return out


def _finding(
    fid: str,
    severity: str,
    size: str,
    message: str,
) -> dict:
    return {
        "id": fid,
        "severity": severity,
        "size": size,
        "message": message,
    }


def scan_repo_hygiene(
    owner: str,
    repo: str,
    list_meta: dict | None = None,
    active_forks: set[str] | None = None,
    node20_min_majors: dict[str, int] | None = None,
    skip_workflow_pins: bool = False,
    branch_cleanup_cfg: dict | None = None,
    skip_branch_cleanup: bool = False,
    readme_polish_cfg: dict | None = None,
    skip_readme_polish: bool = False,
    pipeline_repos: set[str] | None = None,
    parked_repos: set[str] | None = None,
    no_ci_repos: set[str] | None = None,
) -> dict:
    """Read-only Tier-1/2 config audit for one repo."""
    list_meta = list_meta or {}
    active_forks = active_forks or set()
    node20_min_majors = node20_min_majors or dict(DEFAULT_NODE20_ACTION_MIN_MAJORS)
    branch_cleanup_cfg = branch_cleanup_cfg or dict(DEFAULT_BRANCH_CLEANUP)
    readme_polish_cfg = readme_polish_cfg or dict(DEFAULT_README_POLISH)
    pipeline_repos = pipeline_repos or set()
    parked_repos = parked_repos or set()
    no_ci_repos = no_ci_repos or set()
    meta, meta_err = gh_api_object(f"repos/{owner}/{repo}")
    if meta is None:
        return {
            "repo": repo,
            "score": "unavailable",
            "findings": [
                _finding(
                    "repo_meta_unavailable",
                    "low",
                    "park",
                    f"Could not load repo metadata: {meta_err}",
                )
            ],
            "url": f"https://github.com/{owner}/{repo}",
        }

    is_fork = bool(meta.get("fork") if meta.get("fork") is not None else list_meta.get("isFork"))
    is_archived = bool(
        meta.get("archived") if meta.get("archived") is not None else list_meta.get("isArchived")
    )
    is_private = bool(meta.get("private"))
    branch = meta.get("default_branch") or _default_branch(list_meta)
    sa = meta.get("security_and_analysis") or {}
    delete_branch = bool(meta.get("delete_branch_on_merge"))

    vuln_status = gh_api_status(f"repos/{owner}/{repo}/vulnerability-alerts")
    vuln_alerts_on = vuln_status == 204

    dep_sec = sa_status(sa, "dependabot_security_updates")
    secret_scan = sa_status(sa, "secret_scanning")
    push_prot = sa_status(sa, "secret_scanning_push_protection")

    # Private repos without GitHub Advanced Security cannot enable secret scanning /
    # push protection; security_and_analysis is often null or stuck at disabled.
    secret_scanning_unavailable_private = is_private and secret_scan != "enabled"
    if secret_scanning_unavailable_private:
        secret_scan_report = "unavailable_private"
        push_prot_report = "unavailable_private"
    else:
        secret_scan_report = secret_scan
        push_prot_report = push_prot

    # Dependabot security updates: only flag explicit "disabled". Missing/null with
    # vulnerability alerts already on is treated as OK (private/API quirks).
    dep_sec_report = dep_sec
    if dep_sec is None and vuln_alerts_on:
        dep_sec_report = "assumed_on"

    default_setup, _ = gh_api_object(f"repos/{owner}/{repo}/code-scanning/default-setup")
    cs_state = (default_setup or {}).get("state")  # configured | not-configured | …

    paths = _repo_tree_paths(owner, repo, branch) or []
    detected = _detect_ecosystems(paths)
    workflow_paths = [
        p for p in paths if p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml"))
    ]
    has_workflows = bool(workflow_paths)
    has_dependabot_yml = any(
        p in (".github/dependabot.yml", ".github/dependabot.yaml") for p in paths
    )
    has_renovate = any(
        p in ("renovate.json", "renovate.json5", ".github/renovate.json", ".github/renovate.json5")
        for p in paths
    )
    has_codeql_workflow = any(
        "codeql" in p.lower() and p.startswith(".github/workflows/") for p in paths
    )
    has_osv_workflow = any("osv" in p.lower() and p.startswith(".github/workflows/") for p in paths)
    has_dependency_review = any(
        "dependency-review" in p.lower() and p.startswith(".github/workflows/") for p in paths
    )
    has_lockfile = any(
        p.endswith(
            (
                "package-lock.json",
                "yarn.lock",
                "pnpm-lock.yaml",
                "go.sum",
                "Pipfile.lock",
                "poetry.lock",
                "Cargo.lock",
                "composer.lock",
                "Gemfile.lock",
            )
        )
        or p == "go.sum"
        for p in paths
    )
    # Code-ish if we detected a language ecosystem (excluding actions-only empty repos).
    has_code = bool(detected - {"github-actions"}) or any(
        p.endswith((".go", ".py", ".ts", ".tsx", ".js", ".jsx", ".rs", ".java"))
        for p in paths[:5000]
    )

    configured_ecosystems: set[str] = set()
    dependabot_text = None
    if has_dependabot_yml:
        dep_path = (
            ".github/dependabot.yml"
            if ".github/dependabot.yml" in paths
            else ".github/dependabot.yaml"
        )
        dependabot_text = _fetch_file_text(owner, repo, dep_path)
        configured_ecosystems = _dependabot_ecosystems(dependabot_text)

    findings: list[dict] = []
    is_active_fork = is_fork and repo in active_forks
    # Active forks get fix-direct; other forks/archived stay park.
    park_size = (
        "fix-direct" if is_active_fork else ("park" if is_fork or is_archived else "fix-direct")
    )

    if is_archived:
        return {
            "repo": repo,
            "score": "park",
            "fork": is_fork,
            "archived": True,
            "private": is_private,
            "default_branch": branch,
            "detected_ecosystems": sorted(detected),
            "dependabot_ecosystems": sorted(configured_ecosystems),
            "findings": [_finding("archived", "low", "park", "Archived — skip hygiene fixes")],
            "url": f"https://github.com/{owner}/{repo}/settings/security_analysis",
        }

    if not vuln_alerts_on:
        findings.append(
            _finding(
                "vuln_alerts_off",
                "high",
                park_size,
                "Vulnerability alerts disabled — Dependabot alerts will not surface",
            )
        )

    if dep_sec == "disabled":
        findings.append(
            _finding(
                "dependabot_security_updates_off",
                "high",
                park_size,
                "Dependabot security updates disabled — enable for auto security PRs",
            )
        )
    elif dep_sec is None and not vuln_alerts_on:
        # No SA field and alerts off — still call out enabling security updates.
        findings.append(
            _finding(
                "dependabot_security_updates_off",
                "high",
                park_size,
                "Dependabot security updates not confirmed — enable for auto security PRs",
            )
        )

    if detected and not has_renovate and not has_dependabot_yml:
        findings.append(
            _finding(
                "missing_dependabot_yml",
                "high",
                park_size,
                "No .github/dependabot.yml — add security-only config (see templates/)",
            )
        )
    elif has_dependabot_yml and not has_renovate:
        missing = detected - configured_ecosystems
        # Always want github-actions when workflows exist.
        if has_workflows and "github-actions" not in configured_ecosystems:
            missing.add("github-actions")
        for eco in sorted(missing):
            fid = (
                "missing_github_actions_ecosystem"
                if eco == "github-actions"
                else f"missing_ecosystem_{eco}"
            )
            findings.append(
                _finding(
                    fid,
                    "medium",
                    park_size,
                    f"dependabot.yml missing package-ecosystem: {eco}",
                )
            )

    if has_renovate and has_dependabot_yml:
        findings.append(
            _finding(
                "renovate_and_dependabot",
                "low",
                "park",
                "Renovate + Dependabot both present — avoid dual version-update bots",
            )
        )
    elif has_renovate:
        findings.append(
            _finding(
                "renovate_present",
                "low",
                "park",
                "Renovate present — skip Dependabot version-update advice",
            )
        )

    if not secret_scanning_unavailable_private and secret_scan != "enabled":
        findings.append(
            _finding(
                "secret_scanning_off",
                "high",
                park_size,
                "Secret scanning disabled",
            )
        )

    if not secret_scanning_unavailable_private and push_prot != "enabled":
        findings.append(
            _finding(
                "push_protection_off",
                "medium",
                park_size,
                "Secret scanning push protection disabled",
            )
        )

    code_scanning_ok = cs_state == "configured" or has_codeql_workflow or has_osv_workflow
    # Private repos without GitHub Advanced Security cannot enable code scanning
    # either (same GHAS gate as secret scanning / push protection).
    code_scanning_unavailable_private = secret_scanning_unavailable_private
    code_scanning_report = "unavailable_private" if code_scanning_unavailable_private else cs_state
    if has_code and not code_scanning_ok and not code_scanning_unavailable_private:
        findings.append(
            _finding(
                "code_scanning_not_configured",
                "medium",
                park_size,
                "Code scanning default setup not configured (and no CodeQL/osv workflow)",
            )
        )

    if has_code and not has_workflows and repo not in no_ci_repos:
        findings.append(
            _finding(
                "missing_ci_workflow",
                "medium",
                park_size,
                "No .github/workflows — CI needed so Dependabot PRs are safe to merge",
            )
        )

    # Tier 2 (low): only for non-fork active repos
    if not is_fork:
        if not delete_branch:
            findings.append(
                _finding(
                    "delete_branch_on_merge_off",
                    "low",
                    "fix-direct",
                    "Auto-delete head branches is off (repo setting)",
                )
            )
        if has_lockfile and has_workflows and not has_dependency_review:
            findings.append(
                _finding(
                    "dependency_review_missing",
                    "low",
                    "fix-direct",
                    "No dependency-review workflow — consider for PRs with lockfiles",
                )
            )

    node20_action_pins: list[dict] = []
    if has_workflows and not skip_workflow_pins:
        node20_action_pins = _scan_node20_action_pins(
            owner, repo, workflow_paths, node20_min_majors
        )
        if node20_action_pins:
            # Unique action@ref for the message (workflows listed in structured field).
            uniq: list[str] = []
            seen_ar: set[str] = set()
            for h in node20_action_pins:
                label = f"{h['action']}@{h['ref']} (need v{h['need']}+)"
                if label not in seen_ar:
                    seen_ar.add(label)
                    uniq.append(label)
            findings.append(
                _finding(
                    "node20_action_runtime",
                    "medium",
                    park_size,
                    "Node 20 action runtime pins: "
                    + ", ".join(uniq)
                    + " — bump majors before Node 20 removal (not job node-version)",
                )
            )

    # Suggest-only branch cleanup: owned + active forks; never pipeline/parked.
    stale_merged_branches: list[dict] = []
    run_branch_cleanup = (
        not skip_branch_cleanup
        and branch_cleanup_cfg.get("enabled", True)
        and repo not in parked_repos
        and repo not in pipeline_repos
        and (not is_fork or is_active_fork)
    )
    if run_branch_cleanup:
        stale_merged_branches = _scan_stale_merged_branches(owner, repo, branch, branch_cleanup_cfg)
        if stale_merged_branches:
            days = int(branch_cleanup_cfg.get("merged_retention_days") or 30)
            parts = [
                f"{b['name']} (merged PR #{b['pr']} @ {b['merged_at'][:10]})"
                for b in stale_merged_branches
            ]
            findings.append(
                _finding(
                    "stale_merged_branches",
                    "low",
                    "suggest",
                    f"Stale merged branches (>{days}d, still on remote; suggest-only — "
                    f"confirm before delete): " + "; ".join(parts),
                )
            )

    # Suggest-only README badges + About metadata polish.
    readme_path: str | None = None
    readme_missing_badges: list[str] = []
    about_gaps: list[str] = []
    run_readme_polish = (
        not skip_readme_polish
        and readme_polish_cfg.get("enabled", True)
        and has_code
        and repo not in parked_repos
        and repo not in pipeline_repos
        and (not is_fork or is_active_fork)
    )
    if run_readme_polish:
        readme_path = _readme_path(paths)
        if readme_path:
            readme_text = _fetch_file_text(owner, repo, readme_path)
            if readme_text is not None:
                blobs = _readme_badge_blobs(readme_text)
                readme_missing_badges = _missing_readme_badge_categories(
                    blobs,
                    has_workflows=has_workflows,
                    has_license=_has_license_file(paths),
                )
                if readme_missing_badges:
                    findings.append(
                        _finding(
                            "readme_badges_thin",
                            "low",
                            "suggest",
                            "README badge gaps (suggest-only): missing "
                            + ", ".join(readme_missing_badges)
                            + " — add shields/Actions badges when useful",
                        )
                    )

        desc = (meta.get("description") or "").strip()
        topics = _repo_topics(owner, repo, meta)
        if not desc:
            about_gaps.append("description")
        if not topics:
            about_gaps.append("topics")
        if about_gaps:
            findings.append(
                _finding(
                    "about_metadata_thin",
                    "low",
                    "suggest",
                    "GitHub About gaps (suggest-only): missing "
                    + ", ".join(about_gaps)
                    + " — set repo description and topics in Settings → General",
                )
            )

    if is_fork and not is_active_fork:
        for f in findings:
            f["size"] = "park"
        score = "park"
    elif not findings:
        score = "ok"
    elif any(f["severity"] in ("high", "medium") for f in findings):
        score = "needs-work"
    else:
        score = "needs-work"

    return {
        "repo": repo,
        "score": score,
        "fork": is_fork,
        "active_fork": is_active_fork,
        "archived": is_archived,
        "private": is_private,
        "default_branch": branch,
        "vuln_alerts": vuln_alerts_on,
        "dependabot_security_updates": dep_sec_report,
        "secret_scanning": secret_scan_report,
        "push_protection": push_prot_report,
        "code_scanning_default_setup": code_scanning_report,
        "delete_branch_on_merge": delete_branch,
        "has_dependabot_yml": has_dependabot_yml,
        "has_renovate": has_renovate,
        "has_workflows": has_workflows,
        "detected_ecosystems": sorted(detected),
        "dependabot_ecosystems": sorted(configured_ecosystems),
        "node20_action_pins": node20_action_pins,
        "stale_merged_branches": stale_merged_branches,
        "readme_path": readme_path,
        "readme_missing_badges": readme_missing_badges,
        "about_gaps": about_gaps,
        "findings": findings,
        "url": f"https://github.com/{owner}/{repo}/settings/security_analysis",
    }


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
                "ecosystem": ((a.get("dependency") or {}).get("package") or {}).get("ecosystem"),
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
    alerts, err = gh_api(f"repos/{owner}/{repo}/code-scanning/alerts?state=open&per_page=100")
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
    alerts, err = gh_api(f"repos/{owner}/{repo}/secret-scanning/alerts?state=open&per_page=100")
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
    return [label.get("name") for label in (obj.get("labels") or []) if label.get("name")]


def classify_item(
    repo: str,
    labels: list[str],
    cfg: dict,
    *,
    archived: bool = False,
) -> str:
    # Archived repos are not cleanup debt — open PRs/issues stay visible but parked.
    if archived:
        return "park"
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


def scan_prs(owner: str, repo: str, cfg: dict, *, archived: bool = False) -> list[dict]:
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
                "classification": classify_item(repo, labels, cfg, archived=archived),
                "createdAt": pr.get("createdAt"),
                "updatedAt": pr.get("updatedAt"),
            }
        )
    return out


def scan_issues(owner: str, repo: str, cfg: dict, *, archived: bool = False) -> list[dict]:
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
                "classification": classify_item(repo, labels, cfg, archived=archived),
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
    if cls == "park":
        return "park"
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
    hygiene = report.get("repo_hygiene") or []

    print("=== SUMMARY ===")
    print(f"owner: {report['owner']}")
    print(f"repos: {report['repo_count']}")
    print(f"dependabot: {sum(d['total'] for d in dep)} across {len(dep)} repos")
    print(f"code scanning: {sum(c['total'] for c in code)} across {len(code)} repos")
    print(
        f"secrets: {sum(s['total'] for s in secrets if s.get('total'))} across "
        f"{sum(1 for s in secrets if s.get('total'))} repos"
    )
    print(f"open PRs: {len(prs)}")
    print(f"open issues: {len(issues)}")
    pipe_prs = sum(1 for p in prs if p["classification"] in ("pipeline", "never-merge"))
    pipe_issues = sum(1 for i in issues if i["classification"] == "pipeline")
    park_prs = sum(1 for p in prs if p["classification"] == "park")
    park_issues = sum(1 for i in issues if i["classification"] == "park")
    print(f"pipeline-classified PRs: {pipe_prs}")
    print(f"pipeline-classified issues: {pipe_issues}")
    if park_prs or park_issues:
        print(f"archived-parked PRs: {park_prs}")
        print(f"archived-parked issues: {park_issues}")
    if hygiene:
        needs = sum(1 for h in hygiene if h.get("score") == "needs-work")
        ok = sum(1 for h in hygiene if h.get("score") == "ok")
        parked = sum(1 for h in hygiene if h.get("score") == "park")
        finding_n = sum(len(h.get("findings") or []) for h in hygiene)
        print(f"repo hygiene: {needs} needs-work · {ok} ok · {parked} park · {finding_n} findings")
    print()

    if hygiene:
        actionable = [
            h
            for h in hygiene
            if h.get("score") == "needs-work"
            and any(f.get("size") == "fix-direct" for f in (h.get("findings") or []))
        ]
        if actionable:
            print("--- Repo hygiene (needs-work, non-fork) ---")
            for h in sorted(
                actionable,
                key=lambda x: (
                    -len([f for f in (x.get("findings") or []) if f.get("severity") == "high"])
                ),
            ):
                ids = ", ".join(f["id"] for f in (h.get("findings") or [])[:6])
                print(f"  {h['repo']}: {h['score']} — {ids}")
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
    pipe = [p for p in prs if p["classification"] in ("pipeline", "never-merge")]
    park_pr_list = [p for p in prs if p["classification"] == "park"]
    if human_prs:
        print("--- Open PRs (human / dep triage) ---")
        for p in human_prs:
            print(f"  {p['repo']}#{p['number']} [{p.get('size')}] {p['author']}: {p['title'][:70]}")
        print()
    if pipe:
        print("--- Open PRs (pipeline / never-merge) ---")
        for p in pipe:
            print(f"  {p['repo']}#{p['number']} [{p['classification']}] {p['title'][:70]}")
        print()
    if park_pr_list:
        print("--- Open PRs (archived — park) ---")
        for p in park_pr_list:
            print(f"  {p['repo']}#{p['number']} [park] {p['title'][:70]}")
        print()

    human_issues = [i for i in issues if i["classification"] == "human"]
    pipe_i = [i for i in issues if i["classification"] == "pipeline"]
    park_issue_list = [i for i in issues if i["classification"] == "park"]
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
    if park_issue_list:
        print("--- Open issues (archived — park) ---")
        for i in park_issue_list:
            print(f"  {i['repo']}#{i['number']} [park]: {i['title'][:60]}")
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
        "--skip-hygiene",
        action="store_true",
        help="Skip repo hygiene / automation config audit",
    )
    ap.add_argument(
        "--skip-workflow-pins",
        action="store_true",
        help="Skip Node 20 action-runtime pin checks (faster hygiene)",
    )
    ap.add_argument(
        "--skip-branch-cleanup",
        action="store_true",
        help="Skip suggest-only stale merged-branch checks",
    )
    ap.add_argument(
        "--skip-readme-polish",
        action="store_true",
        help="Skip suggest-only README badge / About metadata checks",
    )
    ap.add_argument(
        "--repos",
        help="Comma-separated repo names to scan (default: all owned)",
    )
    args = ap.parse_args()

    cfg = load_config(args.config) if args.config.exists() else {}
    owner = args.owner or cfg.get("owner")
    if not owner:
        print(
            "error: set owner in config.toml (see config.example.toml) or pass --owner",
            file=sys.stderr,
        )
        return 2
    gitroot = expand(args.gitroot or cfg.get("gitroot") or "~/gitroot")
    out_dir = expand(str(ROOT / (cfg.get("out_dir") or "out")))
    node20_mins = _load_node20_min_majors(cfg)
    branch_cleanup = _load_branch_cleanup_cfg(cfg)
    readme_polish = _load_readme_polish_cfg(cfg)
    pipeline_repos = set(cfg.get("pipeline_repos") or [])
    parked_repos = set(cfg.get("parked_repos") or [])
    active_forks = set(cfg.get("active_forks") or [])
    no_ci_repos = set(cfg.get("no_ci_repos") or [])

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
    repo_hygiene = []

    for i, r in enumerate(repos, 1):
        name = r["name"]
        is_archived = bool(r.get("isArchived"))
        print(f"  [{i}/{len(repos)}] {name}", file=sys.stderr)
        # Archived: no alert debt — hygiene still records park reason.
        if not args.skip_alerts and not is_archived:
            d = scan_dependabot(owner, name)
            if d and d["total"]:
                dependabot.append(d)
            c = scan_code_scanning(owner, name)
            if c and c["total"]:
                code_scanning.append(c)
            s = scan_secrets(owner, name)
            if s and s.get("total"):
                secrets.append(s)
        if not args.skip_hygiene:
            repo_hygiene.append(
                scan_repo_hygiene(
                    owner,
                    name,
                    r,
                    active_forks=active_forks,
                    node20_min_majors=node20_mins,
                    skip_workflow_pins=args.skip_workflow_pins,
                    branch_cleanup_cfg=branch_cleanup,
                    skip_branch_cleanup=args.skip_branch_cleanup,
                    readme_polish_cfg=readme_polish,
                    skip_readme_polish=args.skip_readme_polish,
                    pipeline_repos=pipeline_repos,
                    parked_repos=parked_repos,
                    no_ci_repos=no_ci_repos,
                )
            )
        for pr in scan_prs(owner, name, cfg, archived=is_archived):
            pr["size"] = suggest_size(pr, "pr")
            prs.append(pr)
        for issue in scan_issues(owner, name, cfg, archived=is_archived):
            issue["size"] = suggest_size(issue, "issue")
            issues.append(issue)

    local = [] if args.skip_local else local_status(gitroot, owner)

    def _hygiene_sort_key(h: dict):
        sev_rank = {"high": 0, "medium": 1, "low": 2}
        findings = h.get("findings") or []
        worst = min((sev_rank.get(f.get("severity"), 9) for f in findings), default=9)
        return (
            0 if h.get("score") == "needs-work" else 1,
            worst,
            -len(findings),
            h.get("repo") or "",
        )

    report = {
        "scanned_at": datetime.now(UTC).isoformat(),
        "owner": owner,
        "gitroot": str(gitroot),
        "repo_count": len(repos),
        "repos": [r["name"] for r in repos],
        "dependabot": sorted(dependabot, key=lambda x: -x["total"]),
        "code_scanning": sorted(code_scanning, key=lambda x: -x["total"]),
        "secrets": sorted(secrets, key=lambda x: -x.get("total", 0)),
        "repo_hygiene": sorted(repo_hygiene, key=_hygiene_sort_key),
        "prs": prs,
        "issues": issues,
        "local": local,
        "config": {
            "pipeline_repos": cfg.get("pipeline_repos"),
            "pipeline_labels": cfg.get("pipeline_labels"),
            "never_merge_labels": cfg.get("never_merge_labels"),
            "active_forks": cfg.get("active_forks"),
        },
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
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
