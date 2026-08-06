"""Pure-logic tests for housekeeping scan/triage heuristics.

These cover the regression-prone parts of the scanner: path→ecosystem
detection, action-major parsing, README badge heuristics, branch
protection config, and triage classification. No network, no `gh`
mocking — pure functions only.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import scan  # noqa: E402
from hygiene_verdicts import classify_finding  # noqa: E402

# ---------------------------------------------------------------------------
# _detect_ecosystems
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("paths", "expected"),
    [
        (["go.mod"], {"gomod"}),
        (["sub/go.mod"], {"gomod"}),
        (["package.json"], {"npm"}),
        (["yarn.lock"], {"npm"}),
        (["requirements.txt"], {"pip"}),
        (["pyproject.toml"], {"pip"}),
        (["Cargo.toml"], {"cargo"}),
        (["Gemfile.lock"], {"bundler"}),
        (["composer.json"], {"composer"}),
        (["Dockerfile"], {"docker"}),
        (["docker-compose.yml"], {"docker"}),
        (["Dockerfile.prod"], {"docker"}),
        ([".github/workflows/ci.yml"], {"github-actions"}),
        (["README.md", "LICENSE"], set()),
        (["src/requirements-dev.txt"], {"pip"}),
        (["a/b/c/package-lock.json"], {"npm"}),
    ],
)
def test_detect_ecosystems(paths, expected):
    assert scan._detect_ecosystems(paths) == expected


def test_detect_ecosystems_multiple():
    paths = ["go.mod", "Dockerfile", ".github/workflows/t.yml"]
    assert scan._detect_ecosystems(paths) == {"gomod", "docker", "github-actions"}


# ---------------------------------------------------------------------------
# _action_major
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        ("v4", 4),
        ("v4.2.2", 4),
        ("5", 5),
        ("5.0.0", 5),
        ("v11", 11),
        ("main", None),
        ("a" * 40, None),  # full SHA pin
        ("", None),
        ("docker://alpine:3.19", None),
    ],
)
def test_action_major(ref, expected):
    assert scan._action_major(ref) == expected


# ---------------------------------------------------------------------------
# README badge heuristics
# ---------------------------------------------------------------------------


def test_blob_is_license_badge_shields():
    blob = "license mit https://img.shields.io/badge/license-MIT-blue.svg"
    assert scan._blob_is_license_badge(blob)


def test_blob_is_license_badge_alt_text():
    # Blob form is lowercased "alt url" (as produced by _readme_badge_blobs).
    blob = "license: mit https://example.com/LICENSE.png"
    assert scan._blob_is_license_badge(blob)


def test_blob_is_license_badge_workflow_is_not():
    blob = "license-check https://github.com/x/y/actions/workflows/license.yml/badge.svg"
    assert not scan._blob_is_license_badge(blob)


def test_badge_categories_present_ci():
    blobs = ["ci passing https://github.com/x/y/actions/workflows/t.yml/badge.svg"]
    assert "ci" in scan._badge_categories_present(blobs)


def test_badge_categories_present_license_and_package():
    blobs = [
        "license mit https://img.shields.io/badge/license-MIT-blue.svg",
        "pypi https://badge/pypi/v/pkg",
    ]
    cats = scan._badge_categories_present(blobs)
    assert {"license", "package"} <= cats


def test_missing_readme_badge_categories():
    # No badges at all, both applicable.
    assert scan._missing_readme_badge_categories([], has_workflows=True, has_license=True) == [
        "ci",
        "license",
    ]
    # No workflows → ci not applicable.
    assert scan._missing_readme_badge_categories([], has_workflows=False, has_license=True) == [
        "license"
    ]
    # All present → nothing missing.
    blobs = [
        "ci https://github.com/x/y/actions/workflows/t.yml/badge.svg",
        "license https://img.shields.io/badge/license-MIT-blue.svg",
    ]
    assert scan._missing_readme_badge_categories(blobs, has_workflows=True, has_license=True) == []


# ---------------------------------------------------------------------------
# Branch protection config
# ---------------------------------------------------------------------------


def test_branch_is_protected_names():
    cfg = scan.DEFAULT_BRANCH_CLEANUP
    assert scan._branch_is_protected("main", cfg)
    assert scan._branch_is_protected("master", cfg)
    assert scan._branch_is_protected("gh-pages", cfg)


def test_branch_is_protected_prefixes():
    cfg = scan.DEFAULT_BRANCH_CLEANUP
    assert scan._branch_is_protected("release/1.0", cfg)
    assert scan._branch_is_protected("dependabot/npm/x", cfg)
    assert not scan._branch_is_protected("feature/foo", cfg)


# ---------------------------------------------------------------------------
# README / license file detection
# ---------------------------------------------------------------------------


def test_readme_path_candidates():
    assert scan._readme_path(["README.md"]) == "README.md"
    assert scan._readme_path(["readme.md", "docs/x.md"]) == "readme.md"
    assert scan._readme_path(["README.rst"]) == "README.rst"
    assert scan._readme_path(["docs/README.md"]) is None  # not root-level
    assert scan._readme_path([]) is None


def test_has_license_file():
    assert scan._has_license_file(["LICENSE"])
    assert scan._has_license_file(["LICENSE.md"])
    assert scan._has_license_file(["LICENSE.txt"])
    assert scan._has_license_file(["COPYING"])
    assert scan._has_license_file(["COPYING.LESSER"])
    assert not scan._has_license_file(["docs/LICENSE"])  # not root
    assert not scan._has_license_file(["README.md"])


# ---------------------------------------------------------------------------
# Config loaders
# ---------------------------------------------------------------------------


def test_load_branch_cleanup_cfg_defaults():
    cfg = scan._load_branch_cleanup_cfg(None)
    assert cfg["enabled"] is True
    assert cfg["merged_retention_days"] == 30


def test_load_branch_cleanup_cfg_overrides_and_bad_values():
    cfg = scan._load_branch_cleanup_cfg(
        {
            "branch_cleanup": {
                "merged_retention_days": "not-an-int",
                "max_merged_prs": 5,
                "enabled": False,
            }
        }
    )
    assert cfg["merged_retention_days"] == 30  # bad int ignored
    assert cfg["max_merged_prs"] == 5
    assert cfg["enabled"] is False


def test_load_node20_min_majors():
    assert scan._load_node20_min_majors(None)["actions/checkout"] == 5
    cfg = scan._load_node20_min_majors({"node20_action_min_majors": {"actions/checkout": 6}})
    assert cfg["actions/checkout"] == 6
    assert cfg["actions/setup-node"] == 5  # unset keeps default


def test_dependabot_ecosystems_parse():
    yml = """
version: 2
updates:
  - package-ecosystem: "github-actions"
  - package-ecosystem: gomod
"""
    assert scan._dependabot_ecosystems(yml) == {"github-actions", "gomod"}
    assert scan._dependabot_ecosystems(None) == set()
    assert scan._dependabot_ecosystems("") == set()


# ---------------------------------------------------------------------------
# Triage classification
# ---------------------------------------------------------------------------


def test_classify_item():
    cfg = {
        "pipeline_repos": ["pipe-repo"],
        "pipeline_labels": ["pipeline"],
        "never_merge_labels": ["miner-eval"],
    }
    assert scan.classify_item("any", ["miner-eval"], cfg) == "never-merge"
    assert scan.classify_item("pipe-repo", ["pipeline"], cfg) == "pipeline"
    assert scan.classify_item("other", ["pipeline"], cfg) == "pipeline"  # label anywhere
    assert scan.classify_item("other", [], cfg) == "human"
    assert scan.classify_item("archived-repo", [], cfg, archived=True) == "park"


def test_suggest_size():
    cfg = {}
    assert scan.suggest_size({"classification": "park"}, "pr") == "park"
    assert scan.suggest_size({"classification": "pipeline"}, "issue") == "pipeline"
    assert scan.suggest_size({"classification": "never-merge"}, "pr") == "never-merge"
    bot_single = {"classification": "human", "is_bot": True, "title": "Bump dep"}
    assert scan.suggest_size(bot_single, "pr") == "fix-direct"
    bot_group = {"classification": "human", "is_bot": True, "title": "Group bump across 5 deps"}
    assert scan.suggest_size(bot_group, "pr") == "batch-pr"
    assert scan.suggest_size({"classification": "human", "is_bot": False}, "issue") == "issue-pr"
    assert scan.suggest_size({"classification": "human", "is_bot": False}, "pr") == "review"


def test_classify_finding_verdicts():
    cfg_repo = {"repo": "x", "fork": False, "archived": False}
    assert classify_finding(cfg_repo, {"id": "readme_badges_thin"}) == "suggest_only"
    assert classify_finding(cfg_repo, {"id": "stale_merged_branches"}) == "suggest_only"
    assert classify_finding(cfg_repo, {"id": "dependency_review_missing"}) == "tier2_skip"
    assert classify_finding(cfg_repo, {"id": "vuln_alerts_off"}) == "ship_only"
    assert classify_finding({**cfg_repo, "archived": True}, {"id": "x"}) == "park_archived"
    assert classify_finding({**cfg_repo, "fork": True}, {"id": "x"}) == "park_fork"
    assert (
        classify_finding({**cfg_repo, "fork": True}, {"id": "x"}, active_forks={"x"})
        == "active_fork"
    )
    assert (
        classify_finding(cfg_repo, {"id": "code_scanning_not_configured"}, pipeline_repos={"x"})
        == "pipeline_skip"
    )
    assert classify_finding(cfg_repo, {"id": "x"}, parked_repos={"x"}) == "park_repo"


# ---------------------------------------------------------------------------
# GHAS sub-feature findings on User accounts
# ---------------------------------------------------------------------------


def test_ghas_findings_suggest_on_user_account(monkeypatch):
    """On a User account the GHAS sub-feature toggles are UI-only (no REST API),
    so the findings must be size=suggest with a UI pointer, not fix-direct."""
    from scan import scan_repo_hygiene

    def fake_gh_api_object(path):
        # Minimal repo meta: public, secret scanning enabled (GHAS present).
        if path.endswith("/code-scanning/default-setup"):
            return {"state": "configured"}, None
        if path.startswith("repos/"):
            return {
                "fork": False,
                "archived": False,
                "private": False,
                "default_branch": "main",
                "security_and_analysis": {
                    "secret_scanning": {"status": "enabled"},
                    "secret_scanning_validity_checks": {"status": "disabled"},
                    "secret_scanning_non_provider_patterns": {"status": "disabled"},
                    "secret_scanning_push_protection": {"status": "enabled"},
                },
            }, None
        return None, "disabled_or_unavailable"

    monkeypatch.setattr(scan, "gh_api_object", fake_gh_api_object)
    monkeypatch.setattr(scan, "gh_api", lambda *a, **k: ([], None))
    monkeypatch.setattr(scan, "gh_api_status", lambda *a, **k: 204)
    monkeypatch.setattr(scan, "_repo_tree_paths", lambda *a, **k: ["go.mod"])
    monkeypatch.setattr(scan, "_detect_ecosystems", lambda p: {"gomod"})
    monkeypatch.setattr(scan, "_default_branch_protection", lambda *a, **k: None)
    monkeypatch.setattr(scan, "_repo_rulesets", lambda *a, **k: [])
    monkeypatch.setattr(scan, "_actions_workflow_permissions", lambda *a, **k: None)

    row = scan_repo_hygiene("owner", "repo", owner_is_user=True)
    ghas = [f for f in row["findings"] if f["id"].startswith("secret_")]
    assert ghas, "expected GHAS sub-feature findings"
    for f in ghas:
        assert f["size"] == "suggest"
        assert "Settings → Code security" in f["message"]

    # Org account: same findings stay fix-direct.
    row_org = scan_repo_hygiene("owner", "repo", owner_is_user=False)
    ghas_org = [f for f in row_org["findings"] if f["id"].startswith("secret_")]
    assert ghas_org
    for f in ghas_org:
        assert f["size"] == "fix-direct"


def test_branch_protection_require_reviews_config(monkeypatch):
    """Solo default: flag required reviews; team mode: suggest reviews when unprotected."""
    from scan import scan_repo_hygiene

    protected_with_reviews = {
        "required_pull_request_reviews": {"required_approving_review_count": 1},
        "enforce_admins": {"enabled": False},
    }

    def fake_meta(path):
        if path.endswith("/code-scanning/default-setup"):
            return {"state": "configured"}, None
        if path.startswith("repos/"):
            return {
                "fork": False,
                "archived": False,
                "private": False,
                "default_branch": "main",
                "security_and_analysis": {
                    "secret_scanning": {"status": "enabled"},
                    "secret_scanning_push_protection": {"status": "enabled"},
                },
            }, None
        return None, "disabled_or_unavailable"

    monkeypatch.setattr(scan, "gh_api_object", fake_meta)
    monkeypatch.setattr(scan, "gh_api", lambda *a, **k: ([], None))
    monkeypatch.setattr(scan, "gh_api_status", lambda *a, **k: 204)
    monkeypatch.setattr(scan, "_repo_tree_paths", lambda *a, **k: ["go.mod"])
    monkeypatch.setattr(scan, "_detect_ecosystems", lambda p: {"gomod"})
    monkeypatch.setattr(scan, "_repo_rulesets", lambda *a, **k: [])
    monkeypatch.setattr(scan, "_actions_workflow_permissions", lambda *a, **k: None)

    monkeypatch.setattr(
        scan, "_default_branch_protection", lambda *a, **k: protected_with_reviews
    )
    row = scan_repo_hygiene(
        "owner",
        "repo",
        branch_protection_cfg={"require_approving_reviews": False},
    )
    ids = {f["id"] for f in row["findings"]}
    assert "branch_requires_reviews" in ids
    assert "branch_unprotected" not in ids

    row_team = scan_repo_hygiene(
        "owner",
        "repo",
        branch_protection_cfg={"require_approving_reviews": True},
    )
    assert "branch_requires_reviews" not in {f["id"] for f in row_team["findings"]}

    monkeypatch.setattr(scan, "_default_branch_protection", lambda *a, **k: None)
    row_solo_unprot = scan_repo_hygiene(
        "owner",
        "repo",
        branch_protection_cfg={"require_approving_reviews": False},
    )
    unprot = [f for f in row_solo_unprot["findings"] if f["id"] == "branch_unprotected"]
    assert unprot
    assert "Do not require approving reviews" in unprot[0]["message"]
    assert "required reviews + status checks" not in unprot[0]["message"]

    row_team_unprot = scan_repo_hygiene(
        "owner",
        "repo",
        branch_protection_cfg={"require_approving_reviews": True},
    )
    unprot_team = [f for f in row_team_unprot["findings"] if f["id"] == "branch_unprotected"]
    assert unprot_team
    assert "required reviews + status checks" in unprot_team[0]["message"]

