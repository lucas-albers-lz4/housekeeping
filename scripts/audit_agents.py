#!/usr/bin/env python3
"""Opt-in instruction-surface inventory for named repos only.

Requires --repos. Never walks the owner's full repo list as audit targets.
Does not emit agents_md_missing. Not called by scan.py.

Read-only inventory + local cache. Qualitative scoring is the agents-md skill.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from difflib import SequenceMatcher
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import scan  # noqa: E402

SKILL_VERSION = "1"
DEFAULT_LINE_BUDGET = 40
DEFAULT_CACHE = ROOT / "out" / "agents-md-cache.json"
DUPLICATE_RATIO = 0.8

ROUTE_KINDS = frozenset({"cursor_rule", "cursorrules", "cursor_skill", "claude_skill"})


class InventoryError(Exception):
    """Remote tree fetch failed; must not look like an empty surface."""


def cache_key(owner: str, repo: str) -> str:
    return f"{owner}/{repo}"


def parse_repo_list(raw: str | None) -> list[str]:
    if not raw or not str(raw).strip():
        return []
    names = [n.strip() for n in str(raw).split(",") if n.strip()]
    # Preserve order, drop dupes.
    seen: set[str] = set()
    out: list[str] = []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def classify_path(rel: str) -> str | None:
    rel = rel.replace("\\", "/")
    while rel.startswith("./"):
        rel = rel[2:]
    name = rel.rsplit("/", 1)[-1]
    if name == "AGENTS.md":
        return "agents_root" if "/" not in rel else "agents_nested"
    if name == "CLAUDE.md":
        return "claude"
    if name == "GEMINI.md":
        return "gemini"
    if name == ".cursorrules":
        return "cursorrules"
    if name.lower() == "copilot-instructions.md":
        return "copilot"
    prefixed = f"/{rel}"
    if "/.github/instructions/" in prefixed or rel.startswith(".github/instructions/"):
        return "gh_instructions"
    if "/.cursor/rules/" in prefixed or rel.startswith(".cursor/rules/"):
        return "cursor_rule"
    if name == "SKILL.md":
        if "/.cursor/skills/" in prefixed or rel.startswith(".cursor/skills/"):
            return "cursor_skill"
        if "/.claude/skills/" in prefixed or rel.startswith(".claude/skills/"):
            return "claude_skill"
    return None


def fingerprint(
    files: list[dict],
    skill_version: str = SKILL_VERSION,
) -> str:
    parts = [f"{f['path']} {f['sha']}" for f in sorted(files, key=lambda x: x["path"])]
    payload = skill_version + "\n" + "\n".join(parts)
    return hashlib.sha256(payload.encode()).hexdigest()


def _line_count(text: str) -> int:
    if not text:
        return 0
    return text.count("\n") + (0 if text.endswith("\n") else 1)


def claude_is_duplicate(agents_text: str | None, claude_text: str | None) -> bool:
    if not agents_text or not claude_text:
        return False
    a = agents_text.strip()
    c = claude_text.strip()
    if not a or not c:
        return False
    if a == c:
        return True
    return SequenceMatcher(None, a, c).ratio() >= DUPLICATE_RATIO


def mechanical_notes(
    files: list[dict],
    repo: str,
    long_form_repos: set[str] | None = None,
    line_budget: int = DEFAULT_LINE_BUDGET,
) -> list[dict]:
    """Suggest-only mechanical notes. Never emits agents_md_missing."""
    long_form = long_form_repos or set()
    notes: list[dict] = []
    kinds = {f.get("kind") for f in files}
    has_root = "agents_root" in kinds
    if (kinds & ROUTE_KINDS) and not has_root:
        notes.append(
            {
                "id": "routing_gap",
                "size": "suggest",
                "message": (
                    "Rules or skills exist without a root AGENTS.md pointer "
                    "(suggest-only; do not auto-write a stub)"
                ),
            }
        )

    agents_text = next((f.get("text") for f in files if f.get("kind") == "agents_root"), None)
    for f in files:
        if f.get("kind") == "agents_root" and repo not in long_form:
            lines = int(f.get("lines") or 0)
            if lines > line_budget:
                notes.append(
                    {
                        "id": "agents_md_over_budget",
                        "size": "suggest",
                        "message": (
                            f"Root AGENTS.md is {lines} lines "
                            f"(budget {line_budget}; not in long_form_repos)"
                        ),
                    }
                )
        if f.get("kind") == "claude" and claude_is_duplicate(agents_text, f.get("text")):
            notes.append(
                {
                    "id": "claude_md_duplicate",
                    "size": "suggest",
                    "message": ("CLAUDE.md is a near-copy of AGENTS.md; prefer a thin pointer"),
                }
            )
    return notes


def owner_login_matches(owner: str, repo_json: dict) -> bool:
    login = (repo_json.get("owner") or {}).get("login") or ""
    return bool(login) and login.lower() == owner.lower()


def repo_is_under_owner(owner: str, repo: str) -> tuple[bool, dict | None]:
    """True if GET repos/{owner}/{repo} exists and belongs to owner (no 200-cap list)."""
    data, _err = scan.gh_api_object(f"repos/{owner}/{repo}")
    if not isinstance(data, dict):
        return False, None
    if not owner_login_matches(owner, data):
        return False, None
    return True, data


def assert_repos_in_owner(requested: list[str], owned: set[str]) -> list[str]:
    """Return names outside owned. Empty means ok."""
    return [n for n in requested if n not in owned]


def _strip_texts(files: list[dict]) -> list[dict]:
    out = []
    for f in files:
        row = {k: v for k, v in f.items() if k != "text"}
        out.append(row)
    return out


def _git_ls_tree(checkout: Path) -> list[tuple[str, str]]:
    """Return (sha, path) pairs from HEAD, or empty if not a git repo."""
    p = subprocess.run(
        ["git", "-C", str(checkout), "ls-tree", "-r", "HEAD"],
        capture_output=True,
        text=True,
    )
    if p.returncode != 0:
        return []
    rows: list[tuple[str, str]] = []
    for line in p.stdout.splitlines():
        # <mode> <type> <sha>\t<path>
        try:
            meta, path = line.split("\t", 1)
            sha = meta.split()[2]
        except (ValueError, IndexError):
            continue
        rows.append((sha, path))
    return rows


def _working_tree_blob_sha(checkout: Path, rel: str, text: str) -> str:
    """Blob SHA of the working-tree file so fingerprints track dirty edits."""
    p = subprocess.run(
        ["git", "-C", str(checkout), "hash-object", "--", rel],
        capture_output=True,
        text=True,
    )
    sha = (p.stdout or "").strip()
    if p.returncode == 0 and sha:
        return sha
    return hashlib.sha256(text.encode()).hexdigest()[:40]


def _inventory_local(checkout: Path) -> list[dict]:
    files: list[dict] = []
    tree = _git_ls_tree(checkout)
    if tree:
        for _sha, path in tree:
            kind = classify_path(path)
            if not kind:
                continue
            fp = checkout / path
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            files.append(
                {
                    "path": path,
                    "kind": kind,
                    "sha": _working_tree_blob_sha(checkout, path, text),
                    "lines": _line_count(text),
                    "text": text,
                }
            )
        return files
    for p in checkout.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(checkout).as_posix()
        if rel.startswith(".git/"):
            continue
        kind = classify_path(rel)
        if not kind:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        sha = hashlib.sha256(text.encode()).hexdigest()[:40]
        files.append(
            {
                "path": rel,
                "kind": kind,
                "sha": sha,
                "lines": _line_count(text),
                "text": text,
            }
        )
    return files


def _repo_tree_blobs(owner: str, repo: str, branch: str) -> list[tuple[str, str]] | None:
    """Blob (sha, path) pairs, or None if the tree API call failed."""
    data, err = scan.gh_api_object(f"repos/{owner}/{repo}/git/trees/{branch}?recursive=1")
    if data is None or err:
        return None
    if data.get("truncated"):
        return None
    out: list[tuple[str, str]] = []
    for t in data.get("tree") or []:
        if t.get("type") != "blob":
            continue
        path = t.get("path")
        sha = t.get("sha")
        if path and sha:
            out.append((sha, path))
    return out


def _inventory_github(owner: str, repo: str, branch: str) -> list[dict]:
    blobs = _repo_tree_blobs(owner, repo, branch)
    if blobs is None:
        raise InventoryError(f"failed to fetch git tree for {owner}/{repo}@{branch}")
    files: list[dict] = []
    for sha, path in blobs:
        kind = classify_path(path)
        if not kind:
            continue
        text = scan._fetch_file_text(owner, repo, path) or ""
        files.append(
            {
                "path": path,
                "kind": kind,
                "sha": sha,
                "lines": _line_count(text),
                "text": text,
            }
        )
    return files


def inventory_repo(
    owner: str,
    repo: str,
    gitroot: Path,
    list_meta: dict | None = None,
) -> list[dict]:
    checkout = gitroot / repo
    if checkout.is_dir() and (checkout / ".git").exists():
        return _inventory_local(checkout)
    meta = list_meta or {}
    branch = scan._default_branch(meta) if meta else "main"
    if not meta:
        data, _err = scan.gh_api_object(f"repos/{owner}/{repo}")
        if isinstance(data, dict):
            branch = data.get("default_branch") or "main"
    return _inventory_github(owner, repo, branch)


def load_cache(path: Path) -> dict:
    if not path.exists():
        return {"skill_version": SKILL_VERSION, "repos": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"skill_version": SKILL_VERSION, "repos": {}}
    if not isinstance(data, dict):
        return {"skill_version": SKILL_VERSION, "repos": {}}
    data.setdefault("skill_version", SKILL_VERSION)
    data.setdefault("repos", {})
    return data


def write_cache(path: Path, cache: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache, indent=2) + "\n", encoding="utf-8")


def cache_hit(entry: dict | None, fp: str, owner: str | None = None) -> dict | None:
    if not entry:
        return None
    if owner is not None and entry.get("owner") != owner:
        return None
    if entry.get("skill_version") != SKILL_VERSION:
        return None
    if entry.get("fingerprint") != fp:
        return None
    audit = entry.get("audit")
    if not audit:
        return None
    return audit


def _normalize_save_blob(raw: dict, fallback_repo: str | None) -> list[dict]:
    if "audits" in raw and isinstance(raw["audits"], list):
        return [a for a in raw["audits"] if isinstance(a, dict)]
    if "repo" in raw or "score" in raw or "keep" in raw:
        blob = dict(raw)
        if fallback_repo and "repo" not in blob:
            blob["repo"] = fallback_repo
        return [blob]
    return []


def load_instruction_audit_cfg(cfg: dict) -> dict:
    block = cfg.get("instruction_audit") or {}
    if not isinstance(block, dict):
        return {"long_form_repos": []}
    return {
        "long_form_repos": list(block.get("long_form_repos") or []),
    }


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=__doc__,
        epilog="Not part of scan.py. Forkers: this pass never runs unless --repos is given.",
    )
    ap.add_argument("--config", type=Path, default=scan.DEFAULT_CONFIG)
    ap.add_argument("--owner", help="GitHub owner/org (overrides config)")
    ap.add_argument("--gitroot", help="Local checkouts root (overrides config)")
    ap.add_argument(
        "--repos",
        required=True,
        help="Comma-separated repo names (required; never defaults to all owned)",
    )
    ap.add_argument(
        "--cache",
        type=Path,
        default=DEFAULT_CACHE,
        help="Local qualitative cache (default: out/agents-md-cache.json)",
    )
    ap.add_argument(
        "--save",
        type=Path,
        help="Merge qualitative audit JSON into the cache for the inventoried repos",
    )
    ap.add_argument(
        "--line-budget",
        type=int,
        default=DEFAULT_LINE_BUDGET,
        help="Root AGENTS.md line budget (skipped for long_form_repos)",
    )
    return ap


def audit_named_repos(
    owner: str,
    gitroot: Path,
    names: list[str],
    owned: set[str],
    long_form_repos: set[str],
    cache: dict,
    line_budget: int = DEFAULT_LINE_BUDGET,
    list_meta_by_name: dict[str, dict] | None = None,
) -> tuple[int, dict]:
    """Build report for named repos. Returns (exit_code, report)."""
    outside = assert_repos_in_owner(names, owned)
    if outside:
        return 2, {
            "error": "repos outside owner",
            "owner": owner,
            "outside": outside,
        }

    meta_map = list_meta_by_name or {}
    cache_repos = cache.setdefault("repos", {})
    results = []
    for name in names:
        try:
            files = inventory_repo(owner, name, gitroot, meta_map.get(name))
        except InventoryError as e:
            return 2, {
                "error": "inventory failed",
                "owner": owner,
                "repo": name,
                "detail": str(e),
            }
        fp = fingerprint(files)
        notes = mechanical_notes(files, name, long_form_repos, line_budget)
        key = cache_key(owner, name)
        prior = cache_repos.get(key) if isinstance(cache_repos.get(key), dict) else None
        hit = cache_hit(prior, fp, owner=owner)
        row = {
            "repo": name,
            "fingerprint": fp,
            "skill_version": SKILL_VERSION,
            "cache": "hit" if hit else "miss",
            "files": _strip_texts(files),
            "notes": notes,
        }
        if hit:
            row["audit"] = hit
        results.append(row)

        entry = {
            "owner": owner,
            "skill_version": SKILL_VERSION,
            "fingerprint": fp,
            "inventoried_at": datetime.now(UTC).isoformat(),
            "files": _strip_texts(files),
            "notes": notes,
        }
        if hit:
            entry["audit"] = hit
        cache_repos[key] = entry

    report = {
        "scanned_at": datetime.now(UTC).isoformat(),
        "owner": owner,
        "skill_version": SKILL_VERSION,
        "repos": results,
    }
    return 0, report


def apply_save(cache: dict, report: dict, save_path: Path) -> None:
    raw = json.loads(save_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("--save JSON must be an object")
    fallback = None
    if len(report.get("repos") or []) == 1:
        fallback = report["repos"][0]["repo"]
    blobs = _normalize_save_blob(raw, fallback)
    by_name = {r["repo"]: r for r in report.get("repos") or []}
    cache_repos = cache.setdefault("repos", {})
    owner = report.get("owner") or ""
    for blob in blobs:
        name = blob.get("repo")
        if not name or name not in by_name:
            continue
        entry = cache_repos.setdefault(cache_key(owner, name), {})
        entry["owner"] = owner
        entry["skill_version"] = SKILL_VERSION
        entry["fingerprint"] = by_name[name]["fingerprint"]
        entry["audit"] = {k: v for k, v in blob.items() if k != "repo"}
        entry["audited_at"] = datetime.now(UTC).isoformat()
        by_name[name]["cache"] = "hit"
        by_name[name]["audit"] = entry["audit"]


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    names = parse_repo_list(args.repos)
    if not names:
        print("error: --repos is required and must list at least one repo", file=sys.stderr)
        return 2

    cfg = scan.load_config(args.config) if args.config.exists() else {}
    owner = args.owner or cfg.get("owner")
    if not owner:
        print(
            "error: set owner in config.toml (see config.example.toml) or pass --owner",
            file=sys.stderr,
        )
        return 2
    gitroot = scan.expand(args.gitroot or cfg.get("gitroot") or "~/gitroot")
    ia = load_instruction_audit_cfg(cfg)
    long_form = set(ia["long_form_repos"])

    owned: set[str] = set()
    meta_by: dict[str, dict] = {}
    outside: list[str] = []
    for name in names:
        ok, meta = repo_is_under_owner(owner, name)
        if ok and meta is not None:
            owned.add(name)
            meta_by[name] = meta
        else:
            outside.append(name)
    if outside:
        print(
            json.dumps(
                {"error": "repos outside owner", "owner": owner, "outside": outside},
                indent=2,
            )
        )
        return 2

    cache_path = args.cache
    cache = load_cache(cache_path)
    code, report = audit_named_repos(
        owner,
        gitroot,
        names,
        owned,
        long_form,
        cache,
        line_budget=args.line_budget,
        list_meta_by_name=meta_by,
    )
    if code != 0:
        print(json.dumps(report, indent=2))
        return code

    write_cache(cache_path, cache)
    save_ok = True
    if args.save:
        try:
            apply_save(cache, report, args.save)
            write_cache(cache_path, cache)
        except (OSError, json.JSONDecodeError, ValueError) as e:
            print(f"error: --save failed: {e}", file=sys.stderr)
            save_ok = False

    print(json.dumps(report, indent=2))
    return 0 if save_ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
