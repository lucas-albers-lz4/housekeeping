"""Pure-logic tests for housekeeping scan/triage heuristics.

These cover the regression-prone parts of the scanner: path→ecosystem
detection, action-major parsing, README badge heuristics, branch
protection config, and triage classification. No network, no `gh`
mocking — pure functions only.
"""

from __future__ import annotations

import json
import subprocess
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


def test_load_workflow_linters_cfg_defaults():
    cfg = scan._load_workflow_linters_cfg(None)
    assert cfg["enabled"] is True
    assert cfg["actionlint_path"] == ""
    assert cfg["zizmor_path"] == ""
    assert cfg["zizmor_min_severity"] == "high"
    assert cfg["zizmor_persona"] == "regular"


def test_load_workflow_linters_cfg_overrides_and_bad_values():
    cfg = scan._load_workflow_linters_cfg(
        {
            "workflow_linters": {
                "enabled": False,
                "actionlint_path": "/opt/actionlint",
                "zizmor_path": "/opt/zizmor",
                "zizmor_min_severity": "not-a-sev",
                "zizmor_persona": "extra",
            }
        }
    )
    assert cfg["enabled"] is False
    assert cfg["actionlint_path"] == "/opt/actionlint"
    assert cfg["zizmor_path"] == "/opt/zizmor"
    assert cfg["zizmor_min_severity"] == "high"
    assert cfg["zizmor_persona"] == "regular"


def test_load_workflow_linters_cfg_valid_persona_severity():
    cfg = scan._load_workflow_linters_cfg(
        {
            "workflow_linters": {
                "zizmor_min_severity": "Medium",
                "zizmor_persona": "AUDITOR",
            }
        }
    )
    assert cfg["zizmor_min_severity"] == "medium"
    assert cfg["zizmor_persona"] == "auditor"


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
    assert classify_finding(cfg_repo, {"id": "workflow_lint_actionlint"}) == "suggest_only"
    assert classify_finding(cfg_repo, {"id": "workflow_lint_zizmor"}) == "suggest_only"
    assert classify_finding(cfg_repo, {"id": "dependency_review_missing"}) == "tier2_skip"
    assert classify_finding(cfg_repo, {"id": "vuln_alerts_off"}) == "ship_only"
    assert classify_finding({**cfg_repo, "archived": True}, {"id": "x"}) == "park_archived"
    assert classify_finding({**cfg_repo, "archived": True}, {"id": "workflow_lint_zizmor"}) == (
        "park_archived"
    )
    assert classify_finding({**cfg_repo, "fork": True}, {"id": "x"}) == "park_fork"
    assert (
        classify_finding({**cfg_repo, "fork": True}, {"id": "workflow_lint_actionlint"})
        == "suggest_only"
    )
    assert (
        classify_finding(cfg_repo, {"id": "workflow_lint_zizmor"}, pipeline_repos={"x"})
        == "suggest_only"
    )
    assert (
        classify_finding({**cfg_repo, "fork": True}, {"id": "x"}, active_forks={"x"})
        == "active_fork"
    )
    assert (
        classify_finding(cfg_repo, {"id": "code_scanning_not_configured"}, pipeline_repos={"x"})
        == "pipeline_skip"
    )
    assert classify_finding(cfg_repo, {"id": "x"}, parked_repos={"x"}) == "park_repo"
    assert (
        classify_finding(cfg_repo, {"id": "workflow_lint_zizmor"}, parked_repos={"x"})
        == "park_repo"
    )


# ---------------------------------------------------------------------------
# GHAS sub-feature findings on User accounts
# ---------------------------------------------------------------------------


def test_ghas_findings_suggest_on_user_account(monkeypatch):
    """On a User account the GHAS sub-feature toggles are UI-only (no REST API),
    so the findings must be size=suggest with a UI pointer, not fix-direct."""
    scan_repo_hygiene = scan.scan_repo_hygiene

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
    monkeypatch.setattr(scan, "_fetch_codeql_analyses", lambda *a, **k: [])
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
    scan_repo_hygiene = scan.scan_repo_hygiene

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
    monkeypatch.setattr(scan, "_fetch_codeql_analyses", lambda *a, **k: [])
    monkeypatch.setattr(scan, "_detect_ecosystems", lambda p: {"gomod"})
    monkeypatch.setattr(scan, "_repo_rulesets", lambda *a, **k: [])
    monkeypatch.setattr(scan, "_actions_workflow_permissions", lambda *a, **k: None)

    monkeypatch.setattr(scan, "_default_branch_protection", lambda *a, **k: protected_with_reviews)
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


# ---------------------------------------------------------------------------
# CodeQL deep-check helpers
# ---------------------------------------------------------------------------


def test_codeql_languages_from_paths():
    paths = [
        "a.py",
        "b.py",
        "c.py",  # python (3 files → included)
        "x.js",
        "y.ts",  # javascript-typescript (2 → below floor)
        "m.go",
        "n.go",
        "o.go",
        "p.go",  # go (4 → included)
        "q.unknown_ext",
        "README.md",
    ]
    langs = scan._codeql_languages_from_paths(paths)
    assert langs == {"python", "go"}
    # floor: a single file of a language is not a gap
    assert "javascript-typescript" not in langs


def test_codeql_languages_floor_configurable():
    paths = ["only.js", "other.js"]
    assert scan._codeql_languages_from_paths(paths, min_files=2) == {"javascript-typescript"}


def test_workflow_triggers_block_and_shorthand():
    block = """name: cq
on:
  push:
    branches: [main]
  schedule:
    - cron: '31 9 * * 3'
"""
    assert scan._workflow_triggers(block) == (True, True)
    assert scan._workflow_triggers("on: push") == (True, False)
    assert scan._workflow_triggers("on: workflow_dispatch") == (False, False)
    assert scan._workflow_triggers("") == (False, False)


def test_workflow_excludes_branch_inline_and_block():
    txt_inline = "on:\n  push:\n    branches: [main]\n  pull_request:\n    branches: [ main ]\n"
    assert not scan._workflow_excludes_branch(txt_inline, "main")
    assert scan._workflow_excludes_branch(txt_inline, "master")

    txt_block = "on:\n  push:\n    branches:\n      - main\n      - dev\n"
    assert not scan._workflow_excludes_branch(txt_block, "dev")
    assert scan._workflow_excludes_branch(txt_block, "master")

    txt_ignore = "on:\n  push:\n    branches-ignore: [main, dev]\n"
    assert scan._workflow_excludes_branch(txt_ignore, "main")
    assert not scan._workflow_excludes_branch(txt_ignore, "master")

    # no branch filters at all → covers everything
    assert not scan._workflow_excludes_branch("on: push", "main")


def test_workflow_has_security_events():
    good = "permissions:\n  security-events: write\n  contents: read\n"
    assert scan._workflow_has_security_events(good)
    assert not scan._workflow_has_security_events("permissions:\n  contents: read\n")
    assert not scan._workflow_has_security_events("permissions:\n  # security-events: write\n")


def test_workflow_queries_suite():
    assert scan._workflow_queries_suite("queries: security-and-quality") == "security-and-quality"
    assert scan._workflow_queries_suite("queries: security-extended,security-and-quality") == (
        "security-and-quality"
    )
    assert scan._workflow_queries_suite("queries: security-extended") == "security-extended"
    assert scan._workflow_queries_suite("queries: ./custom.ql") == "custom"
    assert scan._workflow_queries_suite("packs:\n  - codeql/python-queries") == "custom"
    assert scan._workflow_queries_suite("") is None
    # commented-out suite line = no suite configured (happycow template case)
    assert scan._workflow_queries_suite("# queries: security-extended") is None
    # a literal suite name that is not a known keyword is not "custom"
    assert scan._workflow_queries_suite("queries: default") == "default"


def test_codeql_action_majors():
    txt = """uses: actions/checkout@v5
uses: github/codeql-action/init@v2
uses: github/codeql-action/analyze@v3
uses: github/codeql-action/init@v1.2.3
"""
    majors = scan._codeql_action_majors(txt)
    assert ("init", "v2") in majors
    assert ("init", "v1.2.3") in majors
    assert not any(s == "analyze" for s, _ in majors)


def test_workflow_paths_ignore_all():
    assert scan._workflow_paths_ignore_all("paths-ignore: ['**']")
    assert scan._workflow_paths_ignore_all("paths-ignore:\n  - '**'\n  - docs/**")
    assert not scan._workflow_paths_ignore_all("paths-ignore: ['docs/**', 'tests/**']")
    assert not scan._workflow_paths_ignore_all("paths: ['src/**']")


def test_load_codeql_suite():
    assert scan._load_codeql_suite(None) == "extended"
    assert scan._load_codeql_suite(
        {"codeql": {"required_query_suite": "security-and-quality"}}
    ) == ("security-and-quality")
    assert scan._load_codeql_suite({"codeql": {"required_query_suite": "Extended"}}) == "extended"
    assert scan._load_codeql_suite({"codeql": {"required_query_suite": "default"}}) == "default"
    assert scan._load_codeql_suite({"codeql": {"other": 1}}) == "extended"


def _hygiene_row(
    monkeypatch, default_setup_state, no_ci=(), suite_value="default", config_file=None
):
    """Drive scan_repo_hygiene with mocked gh; return the row dict."""
    scan_repo_hygiene = scan.scan_repo_hygiene

    def fake_gh_api_object(path):
        if path.endswith("/code-scanning/default-setup"):
            if default_setup_state == "configured":
                cs = {
                    "state": "configured",
                    "languages": ["python"],
                    "schedule": "weekly",
                    "updated_at": "2026-08-08T00:00:00Z",
                }
                if suite_value is not None:
                    cs["query_suite"] = suite_value
                return cs, None
            return {"state": "not-configured"}, None
        if path.endswith("/actions/workflows"):
            return {"workflows": []}, None
        if path.startswith("repos/"):
            return {
                "fork": False,
                "archived": False,
                "private": False,
                "default_branch": "main",
                "codeql_config_file": config_file,
                "security_and_analysis": {
                    "secret_scanning": {"status": "enabled"},
                    "secret_scanning_push_protection": {"status": "enabled"},
                },
            }, None
        return None, "unavailable"

    monkeypatch.setattr(scan, "gh_api_object", fake_gh_api_object)
    monkeypatch.setattr(scan, "gh_api", lambda *a, **k: ([], None))
    monkeypatch.setattr(scan, "gh_api_status", lambda *a, **k: 204)
    monkeypatch.setattr(scan, "_repo_tree_paths", lambda *a, **k: ["main.py", "x.py", "y.py"])
    monkeypatch.setattr(scan, "_fetch_codeql_analyses", lambda *a, **k: [])
    monkeypatch.setattr(scan, "_detect_ecosystems", lambda p: {"pip"})
    monkeypatch.setattr(scan, "_default_branch_protection", lambda *a, **k: None)
    monkeypatch.setattr(scan, "_repo_rulesets", lambda *a, **k: [])
    monkeypatch.setattr(scan, "_actions_workflow_permissions", lambda *a, **k: None)
    return scan_repo_hygiene("owner", "repo", no_ci_repos=set(no_ci))


def test_code_scanning_not_configured_fires_when_code_present(monkeypatch):
    row = _hygiene_row(monkeypatch, "not-configured")
    ids = {f["id"] for f in row["findings"]}
    assert "code_scanning_not_configured" in ids


def test_codeql_default_query_suite_emitted_for_weak_suite(monkeypatch):
    row = _hygiene_row(monkeypatch, "configured")
    by_id = {f["id"]: f for f in row["findings"]}
    assert "codeql_default_query_suite" in by_id
    assert by_id["codeql_default_query_suite"]["severity"] == "medium"
    assert by_id["codeql_default_query_suite"]["size"] == "fix-direct"
    cfg = row["code_scanning_config"]
    assert cfg["mode"] == "default-setup"
    assert cfg["query_suite"] == "default"
    assert cfg["languages"] == ["python"]


def test_codeql_suite_check_disabled_via_config(monkeypatch):
    # Mocks stay active from _hygiene_row — call with the config-disabled value.
    _hygiene_row(monkeypatch, "configured")
    row_off = scan.scan_repo_hygiene(
        "owner",
        "repo",
        codeql_required_suite="default",
    )
    ids = {f["id"] for f in row_off["findings"]}
    assert "codeql_default_query_suite" not in ids


def test_codeql_extended_suite_passes_floor(monkeypatch):
    row = _hygiene_row(monkeypatch, "configured", suite_value="extended")
    ids = {f["id"] for f in row["findings"]}
    assert "codeql_default_query_suite" not in ids


def test_codeql_missing_suite_fails_closed(monkeypatch):
    # API returns state=configured without query_suite → treated as weakest.
    row = _hygiene_row(monkeypatch, "configured", suite_value=None)
    ids = {f["id"] for f in row["findings"]}
    assert "codeql_default_query_suite" in ids


def test_codeql_config_file_skips_suite_check(monkeypatch):
    # github-codeql-config-file merges custom queries → floor check not applied.
    row = _hygiene_row(monkeypatch, "configured", config_file="codeql-config.yml")
    ids = {f["id"] for f in row["findings"]}
    assert "codeql_default_query_suite" not in ids


def _analysis(
    category,
    created_at,
    error="",
    warning="",
    ref="refs/heads/main",
    analysis_key=None,
):
    row = {
        "category": category,
        "ref": ref,
        "created_at": created_at,
        "error": error,
        "warning": warning,
    }
    if analysis_key is not None:
        row["analysis_key"] = analysis_key
        if category is None:
            del row["category"]
    return row


def test_latest_codeql_analyses_by_category_grouping():
    rows = [
        _analysis("/language:python", "2026-08-18T00:00:00Z", error=""),
        _analysis("/language:python", "2024-01-01T00:00:00Z", error="old"),
        _analysis("/language:ruby", "2025-01-23T12:00:00Z", error="unsuccessful execution"),
        _analysis("/language:ruby", "2026-08-18T00:00:00Z", error="", ref="refs/heads/dev"),
        {"analysis_key": "key/js", "ref": "refs/heads/main", "created_at": "2026-01-01T00:00:00Z",
         "error": "", "warning": ""},
    ]
    latest = scan._latest_codeql_analyses_by_category(rows, "main")
    assert set(latest) == {"/language:python", "/language:ruby", "key/js"}
    assert latest["/language:python"]["error"] == ""
    assert latest["/language:ruby"]["error"] == "unsuccessful execution"
    assert latest["/language:ruby"]["created_at"].startswith("2025-01-23")


def test_fetch_codeql_analyses_caps_and_404(monkeypatch):
    calls: list[str] = []

    def fake_full(path):
        calls.append(path)
        return [{"id": i} for i in range(scan.CODEQL_ANALYSES_PAGE)], None

    monkeypatch.setattr(scan, "_gh_api_list_page", fake_full)
    out = scan._fetch_codeql_analyses("o", "r", "main")
    assert len(out) == scan.CODEQL_ANALYSES_MAX
    assert len(calls) == 5
    assert "ref=refs%2Fheads%2Fmain" in calls[0]
    assert "tool_name=CodeQL" in calls[0]

    monkeypatch.setattr(
        scan, "_gh_api_list_page", lambda _p: (None, "disabled_or_unavailable")
    )
    assert scan._fetch_codeql_analyses("o", "r", "main") is None


def test_fetch_codeql_analyses_other_error_is_skip(monkeypatch):
    monkeypatch.setattr(
        scan, "_gh_api_list_page", lambda _p: (None, "API rate limit exceeded")
    )
    assert scan._fetch_codeql_analyses("o", "r", "main") is None


def test_codeql_analysis_error_rke2setup_shaped(monkeypatch):
    rows = [
        _analysis("/language:python", "2026-08-18T10:00:00Z"),
        _analysis("/language:actions", "2026-08-18T10:00:00Z"),
        _analysis(
            "/language:ruby",
            "2025-01-23T00:00:00Z",
            error="unsuccessful execution, exit code: 0, description:  ",
        ),
    ]
    _hygiene_row(monkeypatch, "configured", suite_value="extended")
    monkeypatch.setattr(scan, "_fetch_codeql_analyses", lambda *a, **k: rows)
    monkeypatch.setattr(scan, "_latest_failed_codeql_workflow_run", lambda *a, **k: None)
    row = scan.scan_repo_hygiene("owner", "repo")
    errs = [f for f in row["findings"] if f["id"] == "codeql_analysis_error"]
    assert len(errs) == 1
    assert errs[0]["severity"] == "medium"
    assert errs[0]["size"] == "suggest"
    assert "/language:ruby" in errs[0]["message"]
    assert "2025-01-23" in errs[0]["message"]
    assert "security/code-scanning" in errs[0]["message"]
    assert "codeql_analysis_warning" not in {f["id"] for f in row["findings"]}
    health = row["codeql_analysis_health"]
    assert len(health) == 1
    assert health[0]["category"] == "/language:ruby"
    assert "unsuccessful execution" in health[0]["error"]


def test_codeql_analysis_warning_only(monkeypatch):
    rows = [_analysis("/language:python", "2026-08-18T00:00:00Z", warning="slow query pack")]
    monkeypatch.setattr(scan, "_fetch_codeql_analyses", lambda *a, **k: rows)
    monkeypatch.setattr(scan, "_latest_failed_codeql_workflow_run", lambda *a, **k: None)
    health, findings = scan._scan_codeql_analysis_health("o", "r", "main")
    assert [f["id"] for f in findings] == ["codeql_analysis_warning"]
    assert findings[0]["severity"] == "low"
    assert findings[0]["size"] == "suggest"
    assert "slow query pack" in findings[0]["message"]
    assert health[0]["warning"] == "slow query pack"


def test_codeql_analysis_empty_error_warning_none(monkeypatch):
    rows = [_analysis("/language:python", "2026-08-18T00:00:00Z", error="  ", warning="")]
    monkeypatch.setattr(scan, "_fetch_codeql_analyses", lambda *a, **k: rows)
    monkeypatch.setattr(scan, "_latest_failed_codeql_workflow_run", lambda *a, **k: None)
    health, findings = scan._scan_codeql_analysis_health("o", "r", "main")
    assert findings == []
    assert health == []


def test_codeql_analysis_404_none(monkeypatch):
    monkeypatch.setattr(scan, "_fetch_codeql_analyses", lambda *a, **k: None)
    health, findings = scan._scan_codeql_analysis_health("o", "r", "main")
    assert findings == []
    assert health == []
    _hygiene_row(monkeypatch, "configured", suite_value="extended")
    monkeypatch.setattr(scan, "_fetch_codeql_analyses", lambda *a, **k: None)
    row = scan.scan_repo_hygiene("owner", "repo")
    ids = {f["id"] for f in row["findings"]}
    assert "codeql_analysis_error" not in ids
    assert row["codeql_analysis_health"] == []


def test_codeql_analysis_error_beats_warning_same_category(monkeypatch):
    rows = [
        _analysis(
            "/language:python",
            "2026-08-18T00:00:00Z",
            error="boom",
            warning="also warn",
        )
    ]
    monkeypatch.setattr(scan, "_fetch_codeql_analyses", lambda *a, **k: rows)
    monkeypatch.setattr(scan, "_latest_failed_codeql_workflow_run", lambda *a, **k: None)
    _health, findings = scan._scan_codeql_analysis_health("o", "r", "main")
    assert [f["id"] for f in findings] == ["codeql_analysis_error"]


def test_codeql_failed_workflow_without_newer_analysis(monkeypatch):
    monkeypatch.setattr(scan, "_fetch_codeql_analyses", lambda *a, **k: [])
    monkeypatch.setattr(
        scan,
        "_latest_failed_codeql_workflow_run",
        lambda *a, **k: {"conclusion": "failure", "created_at": "2026-08-01T00:00:00Z"},
    )
    health, findings = scan._scan_codeql_analysis_health("o", "r", "main")
    assert [f["id"] for f in findings] == ["codeql_analysis_error"]
    assert "failure" in findings[0]["message"]
    assert health[0]["category"] == "workflow"


def test_codeql_failed_workflow_suppressed_by_newer_ok_analysis(monkeypatch):
    rows = [_analysis("/language:python", "2026-08-18T00:00:00Z")]
    monkeypatch.setattr(scan, "_fetch_codeql_analyses", lambda *a, **k: rows)
    monkeypatch.setattr(
        scan,
        "_latest_failed_codeql_workflow_run",
        lambda *a, **k: {"conclusion": "failure", "created_at": "2026-08-01T00:00:00Z"},
    )
    _health, findings = scan._scan_codeql_analysis_health("o", "r", "main")
    assert findings == []


def test_codeql_failed_workflow_not_double_emitted_with_analysis_error(monkeypatch):
    rows = [_analysis("/language:ruby", "2025-01-23T00:00:00Z", error="unsuccessful")]
    monkeypatch.setattr(scan, "_fetch_codeql_analyses", lambda *a, **k: rows)
    monkeypatch.setattr(
        scan,
        "_latest_failed_codeql_workflow_run",
        lambda *a, **k: {"conclusion": "failure", "created_at": "2026-08-01T00:00:00Z"},
    )
    _health, findings = scan._scan_codeql_analysis_health("o", "r", "main")
    assert [f["id"] for f in findings] == ["codeql_analysis_error"]
    assert "/language:ruby" in findings[0]["message"]


def test_latest_failed_codeql_run_ignores_cancelled(monkeypatch):
    monkeypatch.setattr(
        scan,
        "gh_api_object",
        lambda *_a, **_k: (
            {
                "workflow_runs": [
                    {
                        "path": ".github/workflows/codeql.yml",
                        "head_branch": "main",
                        "status": "completed",
                        "conclusion": "cancelled",
                        "created_at": "2026-08-18T00:00:00Z",
                    }
                ]
            },
            None,
        ),
    )
    assert scan._latest_failed_codeql_workflow_run("o", "r", "main") is None


def test_workflow_branch_glob_semantics():
    # `**` / `*` allowlists cover the default branch; literal lists still exclude.
    assert not scan._workflow_excludes_branch("on:\n  push:\n    branches: ['**']", "main")
    assert not scan._workflow_excludes_branch("on:\n  push:\n    branches: ['*']", "main")
    assert not scan._workflow_excludes_branch("on:\n  push:\n    branches: ['*']", "master")
    assert scan._workflow_excludes_branch("on:\n  push:\n    branches: ['release/*']", "main")
    assert not scan._workflow_excludes_branch(
        "on:\n  push:\n    branches: ['release/*']", "release/1.0"
    )
    # glob in block form too
    assert not scan._workflow_excludes_branch("on:\n  push:\n    branches:\n      - '**'\n", "main")


def test_badge_url_hosts_exact_netloc():
    blob = "[![pypi](https://pypi.org/project/x/)] [![evil](https://evilpypi.org/x)]"
    hosts = scan._badge_url_hosts(blob)
    # Equality / subset — never `"host" in url` (CodeQL substring rule).
    assert {"pypi.org", "evilpypi.org"} <= hosts
    assert not ({"pypi.org"} <= scan._badge_url_hosts("https://evilpypi.org/x"))
    assert scan._hosts_equal_any(hosts, {"pypi.org"})
    assert not scan._hosts_equal_any(
        scan._badge_url_hosts("https://evilpypi.org/x"), {"pypi.org"}
    )
    assert scan._badge_url_hosts("no url here") == set()
    assert scan._badge_url_hosts("https://img.shields.io/badge/license-MIT-blue") == {
        "img.shields.io"
    }


# ---------------------------------------------------------------------------
# Workflow linters (actionlint + zizmor)
# ---------------------------------------------------------------------------


def test_is_workflow_linter_collectable():
    assert scan._is_workflow_linter_collectable(".github/workflows/ci.yml")
    assert scan._is_workflow_linter_collectable(".github/workflows/ci.yaml")
    assert scan._is_workflow_linter_collectable("foo/action.yml")
    assert scan._is_workflow_linter_collectable("action.yaml")
    assert scan._is_workflow_linter_collectable(".github/dependabot.yml")
    assert scan._is_workflow_linter_collectable(".github/dependabot.yaml")
    assert scan._is_workflow_linter_collectable(".pre-commit-config.yaml")
    assert scan._is_workflow_linter_collectable(".pre-commit-hooks.yml")
    assert not scan._is_workflow_linter_collectable("README.md")
    assert not scan._is_workflow_linter_collectable(".github/workflows/notes.md")
    assert not scan._is_workflow_linter_collectable("docs/action.md")
    assert not scan._is_workflow_linter_collectable("../.github/workflows/ci.yml")
    assert not scan._is_workflow_linter_collectable("/abs/.github/workflows/ci.yml")
    assert not scan._is_workflow_linter_collectable("foo.yml")


def test_workflow_linter_materialize_paths_sorted_deduped():
    collectable, sidecars = scan._workflow_linter_materialize_paths(
        [
            ".github/workflows/b.yml",
            ".github/workflows/a.yml",
            ".github/workflows/a.yml",
            "zizmor.yml",
            ".github/actionlint.yaml",
            "README.md",
        ]
    )
    assert collectable == [".github/workflows/a.yml", ".github/workflows/b.yml"]
    assert sidecars == [".github/actionlint.yaml", "zizmor.yml"]


def test_parse_actionlint_exit_1_is_not_crash():
    stdout = json.dumps(
        {
            "message": "shellcheck reported issue in this script: SC2086:info:1:1: double quote",
            "filepath": ".github/workflows/ci.yml",
            "line": 12,
            "column": 9,
            "kind": "shellcheck",
        }
    )
    parsed = scan._parse_actionlint_output(stdout)
    assert parsed is not None and len(parsed) == 1
    assert scan._actionlint_kind(parsed[0]) == "shellcheck"
    assert scan._actionlint_site(parsed[0]) == ".github/workflows/ci.yml:12"


def test_parse_actionlint_ndjson_and_kinds():
    rows = [
        {"kind": "syntax", "filepath": "a.yml", "line": 1},
        {"kind": "expression", "filepath": "b.yml", "line": 2},
        {"kind": "runner-label", "filepath": "c.yml", "line": 3},
    ]
    text = "\n".join(json.dumps(r) for r in rows)
    parsed = scan._parse_actionlint_output(text)
    assert parsed is not None and len(parsed) == 3
    msg = scan._summarize_actionlint(parsed, workflow_n=2)
    assert "syntax=1" in msg
    assert "expression=1" in msg
    assert "runner-label=1" in msg
    assert "a.yml:1" in msg


def test_parse_linter_malformed_json():
    assert scan._parse_actionlint_output("not-json {") is None
    assert scan._parse_zizmor_output("not-json {") is None


def test_summarize_zizmor_zero_based_row_and_severity():
    high = {
        "ident": "template-injection",
        "determinations": {"severity": "High"},
        "locations": [
            {
                "symbolic": {"key": {"Local": {"verbatim_path": "./.github/workflows/ci.yml"}}},
                "concrete": {"location": {"start_point": {"row": 6}}},
            }
        ],
    }
    medium = {
        "ident": "artipacked",
        "determinations": {"severity": "Medium"},
        "locations": [
            {
                "symbolic": {"key": {"Local": {"verbatim_path": "./.github/workflows/ci.yml"}}},
                "concrete": {"location": {"start_point": {"row": 20}}},
            }
        ],
    }
    assert scan._zizmor_site(high) == ".github/workflows/ci.yml:7"
    counted_high = [high]
    assert any(scan._zizmor_severity(i) == "high" for i in counted_high)
    msg = scan._summarize_zizmor(counted_high, "high")
    assert "template-injection=1" in msg
    assert ".github/workflows/ci.yml:7" in msg
    assert scan._zizmor_meets_min("medium", "high") is False
    assert scan._zizmor_meets_min("high", "high") is True
    assert scan._zizmor_meets_min("medium", "medium") is True
    counted_med = [i for i in [medium] if scan._zizmor_meets_min(scan._zizmor_severity(i), "high")]
    assert counted_med == []
    counted_med2 = [
        i for i in [medium] if scan._zizmor_meets_min(scan._zizmor_severity(i), "medium")
    ]
    assert counted_med2 == [medium]
    hk = "medium" if any(scan._zizmor_severity(i) == "high" for i in counted_med2) else "low"
    assert hk == "low"


def _cp(returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def test_run_actionlint_exit_1_parses(monkeypatch, tmp_path):
    payload = json.dumps({"kind": "syntax", "filepath": "ci.yml", "line": 1})

    def fake_run(*_a, **_k):
        return _cp(1, payload)

    monkeypatch.setattr(scan.subprocess, "run", fake_run)
    out = scan._run_actionlint("/bin/actionlint", tmp_path)
    assert out is not None and out[0]["kind"] == "syntax"


def test_run_actionlint_exit_2_is_error(monkeypatch, tmp_path):
    monkeypatch.setattr(scan.subprocess, "run", lambda *_a, **_k: _cp(2, "bad flags"))
    assert scan._run_actionlint("/bin/actionlint", tmp_path) is None


def test_run_zizmor_offline_argv_and_exit_14(monkeypatch, tmp_path):
    captured = {}
    items = [{"ident": "unpinned-uses", "determinations": {"severity": "High"}}]

    def fake_run(args, **kwargs):
        captured["args"] = list(args)
        captured["cwd"] = kwargs.get("cwd")
        return _cp(14, json.dumps(items))

    monkeypatch.setattr(scan.subprocess, "run", fake_run)
    out = scan._run_zizmor(
        "/bin/zizmor", tmp_path, persona="regular", min_severity="high"
    )
    assert out == items
    assert "--offline" in captured["args"]
    assert captured["args"][-1] == "."
    assert any(a.startswith("--persona=") for a in captured["args"])
    assert "owner/repo" not in captured["args"]


def test_run_zizmor_exit_3_empty(monkeypatch, tmp_path):
    monkeypatch.setattr(scan.subprocess, "run", lambda *_a, **_k: _cp(3, ""))
    assert scan._run_zizmor("/bin/zizmor", tmp_path, persona="regular", min_severity="high") == []


def test_scan_workflow_linters_skip_and_disabled(monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("should not resolve binaries")

    monkeypatch.setattr(scan, "_resolve_linter_binary", boom)
    findings, status = scan._scan_workflow_linters(
        "o", "r", [".github/workflows/ci.yml"], dict(scan.DEFAULT_WORKFLOW_LINTERS), skip=True
    )
    assert findings == []
    assert status["actionlint"] == "skipped"
    cfg = dict(scan.DEFAULT_WORKFLOW_LINTERS)
    cfg["enabled"] = False
    findings2, status2 = scan._scan_workflow_linters(
        "o", "r", [".github/workflows/ci.yml"], cfg, skip=False
    )
    assert findings2 == []
    assert status2["zizmor"] == "skipped"


def test_scan_workflow_linters_no_collectable_no_fetch(monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("should not fetch")

    monkeypatch.setattr(scan, "_resolve_linter_binary", boom)
    monkeypatch.setattr(scan, "_fetch_file_text_allow_large", boom)
    findings, status = scan._scan_workflow_linters(
        "o", "r", ["README.md", "go.mod"], dict(scan.DEFAULT_WORKFLOW_LINTERS), skip=False
    )
    assert findings == []
    assert status["actionlint"] == "no_collectable_files"


def test_scan_workflow_linters_both_binaries_missing(monkeypatch):
    fetched = []
    monkeypatch.setattr(scan, "_resolve_linter_binary", lambda *_a, **_k: None)
    monkeypatch.setattr(
        scan, "_fetch_file_text_allow_large", lambda *_a, **_k: fetched.append("x") or "x"
    )
    scan._reset_workflow_linter_missing_log()
    findings, status = scan._scan_workflow_linters(
        "o",
        "r",
        [".github/workflows/ci.yml"],
        dict(scan.DEFAULT_WORKFLOW_LINTERS),
        skip=False,
    )
    assert findings == []
    assert status["actionlint"] == "missing_binary"
    assert status["zizmor"] == "missing_binary"
    assert fetched == []


def test_scan_workflow_linters_one_binary_missing(monkeypatch):
    monkeypatch.setattr(
        scan,
        "_resolve_linter_binary",
        lambda _cfg, name: "/bin/zizmor" if name == "zizmor" else None,
    )
    monkeypatch.setattr(
        scan, "_fetch_file_text_allow_large", lambda *_a, **_k: "on: push\njobs: {}\n"
    )
    monkeypatch.setattr(
        scan,
        "_run_zizmor",
        lambda *_a, **_k: [
            {"ident": "template-injection", "determinations": {"severity": "High"}}
        ],
    )
    monkeypatch.setattr(
        scan.subprocess,
        "run",
        lambda *_a, **_k: _cp(0),  # git init
    )
    scan._reset_workflow_linter_missing_log()
    findings, status = scan._scan_workflow_linters(
        "o",
        "r",
        [".github/workflows/ci.yml"],
        dict(scan.DEFAULT_WORKFLOW_LINTERS),
        skip=False,
    )
    ids = {f["id"] for f in findings}
    assert ids == {"workflow_lint_zizmor"}
    assert findings[0]["severity"] == "medium"
    assert findings[0]["size"] == "suggest"
    assert status["actionlint"] == "missing_binary"
    assert status["zizmor"] == "ran"


def test_scan_workflow_linters_dropped_workflow_fetch_is_error(monkeypatch):
    """Tree listed workflows but Contents returned None — error, not no_workflows."""

    def fake_fetch(_o, _r, path):
        if path.endswith("ci.yml"):
            return None
        return "version: 2\n"

    def boom_actionlint(*_a, **_k):
        raise AssertionError("actionlint must not run on an incomplete tree")

    monkeypatch.setattr(
        scan,
        "_resolve_linter_binary",
        lambda _cfg, name: "/bin/actionlint" if name == "actionlint" else None,
    )
    monkeypatch.setattr(scan, "_fetch_file_text_allow_large", fake_fetch)
    monkeypatch.setattr(scan, "_run_actionlint", boom_actionlint)
    monkeypatch.setattr(scan.subprocess, "run", lambda *_a, **_k: _cp(0))
    scan._reset_workflow_linter_missing_log()
    findings, status = scan._scan_workflow_linters(
        "o",
        "r",
        [".github/workflows/ci.yml", ".github/dependabot.yml"],
        dict(scan.DEFAULT_WORKFLOW_LINTERS),
        skip=False,
    )
    assert findings == []
    assert status["actionlint"] == "error"
    assert status["zizmor"] == "missing_binary"


def test_scan_repo_hygiene_skip_workflow_linters(monkeypatch):
    seen: list[bool] = []

    def fake(_o, _r, _paths, _cfg, skip):
        seen.append(skip)
        return [], {"actionlint": "skipped", "zizmor": "skipped"}

    monkeypatch.setattr(scan, "_scan_workflow_linters", fake)
    _hygiene_row(monkeypatch, "configured")
    row = scan.scan_repo_hygiene("owner", "repo", skip_workflow_linters=True)
    assert True in seen
    assert row["workflow_linters"]["actionlint"] == "skipped"


def test_non_active_fork_keeps_suggest_size(monkeypatch):
    def fake_meta(path):
        if path.endswith("/code-scanning/default-setup"):
            return {"state": "configured", "query_suite": "extended", "languages": ["python"]}, None
        if path.endswith("/actions/workflows"):
            return {"workflows": []}, None
        if path.startswith("repos/"):
            return {
                "fork": True,
                "archived": False,
                "private": False,
                "default_branch": "main",
                "security_and_analysis": {
                    "secret_scanning": {"status": "enabled"},
                    "secret_scanning_push_protection": {"status": "enabled"},
                },
            }, None
        return None, "unavailable"

    monkeypatch.setattr(scan, "gh_api_object", fake_meta)
    monkeypatch.setattr(scan, "gh_api", lambda *a, **k: ([], None))
    monkeypatch.setattr(scan, "gh_api_status", lambda *a, **k: 204)
    monkeypatch.setattr(
        scan, "_repo_tree_paths", lambda *a, **k: [".github/workflows/ci.yml", "main.py"]
    )
    monkeypatch.setattr(scan, "_fetch_codeql_analyses", lambda *a, **k: [])
    monkeypatch.setattr(scan, "_detect_ecosystems", lambda p: {"pip", "github-actions"})
    monkeypatch.setattr(scan, "_default_branch_protection", lambda *a, **k: None)
    monkeypatch.setattr(scan, "_repo_rulesets", lambda *a, **k: [])
    monkeypatch.setattr(scan, "_actions_workflow_permissions", lambda *a, **k: None)
    monkeypatch.setattr(
        scan,
        "_scan_workflow_linters",
        lambda *_a, **_k: (
            [scan._finding("workflow_lint_zizmor", "medium", "suggest", "zizmor: 1")],
            {"actionlint": "missing_binary", "zizmor": "ran"},
        ),
    )
    row = scan.scan_repo_hygiene("owner", "repo")
    lint = [f for f in row["findings"] if f["id"] == "workflow_lint_zizmor"]
    assert lint and lint[0]["size"] == "suggest"
    other = [f for f in row["findings"] if f["id"] != "workflow_lint_zizmor"]
    assert other
    assert all(f["size"] == "park" for f in other)


def test_workflow_linter_path_skip_note():
    assert scan._workflow_linter_path_skip_note([]) is None
    ran_only = [{"workflow_linters": {"actionlint": "ran"}}]
    assert scan._workflow_linter_path_skip_note(ran_only) is None
    note = scan._workflow_linter_path_skip_note(
        [
            {"workflow_linters": {"actionlint": "missing_binary", "zizmor": "ran"}},
            {"workflow_linters": {"actionlint": "missing_binary", "zizmor": "missing_binary"}},
        ]
    )
    assert note == (
        "workflow linters: actionlint skipped (not on PATH), zizmor skipped (not on PATH)"
    )
