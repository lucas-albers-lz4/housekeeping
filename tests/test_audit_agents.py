"""Pure-function tests for opt-in instruction-surface audit.

No network, no `gh` mocking — classify / fingerprint / notes / argparse only.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import audit_agents as aa  # noqa: E402


def test_parse_repo_list_empty():
    assert aa.parse_repo_list(None) == []
    assert aa.parse_repo_list("") == []
    assert aa.parse_repo_list("  , , ") == []


def test_parse_repo_list_dedupes():
    assert aa.parse_repo_list("fwlive, fwlive, regexproof") == ["fwlive", "regexproof"]


def test_build_parser_requires_repos():
    ap = aa.build_parser()
    with pytest.raises(SystemExit) as ei:
        ap.parse_args([])
    assert ei.value.code == 2


def test_main_empty_repos_exits_2():
    assert aa.main(["--repos", "", "--owner", "nobody"]) == 2
    assert aa.main(["--repos", " , ", "--owner", "nobody"]) == 2


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("AGENTS.md", "agents_root"),
        ("pkg/AGENTS.md", "agents_nested"),
        ("CLAUDE.md", "claude"),
        ("GEMINI.md", "gemini"),
        (".cursorrules", "cursorrules"),
        (".github/copilot-instructions.md", "copilot"),
        ("copilot-instructions.md", "copilot"),
        (".github/instructions/foo.md", "gh_instructions"),
        (".cursor/rules/owner-scope.mdc", "cursor_rule"),
        (".cursor/skills/housekeeping/SKILL.md", "cursor_skill"),
        (".claude/skills/ringer/SKILL.md", "claude_skill"),
        ("README.md", None),
        (".cursor/skills/housekeeping/reference.md", None),
        ("src/main.py", None),
    ],
)
def test_classify_path(path, kind):
    assert aa.classify_path(path) == kind


def test_fingerprint_stable_and_order_independent():
    a = [
        {"path": "b.md", "sha": "bbb"},
        {"path": "a.md", "sha": "aaa"},
    ]
    b = [
        {"path": "a.md", "sha": "aaa"},
        {"path": "b.md", "sha": "bbb"},
    ]
    assert aa.fingerprint(a) == aa.fingerprint(b)
    changed = [{"path": "a.md", "sha": "ccc"}, {"path": "b.md", "sha": "bbb"}]
    assert aa.fingerprint(a) != aa.fingerprint(changed)
    assert aa.fingerprint(a, skill_version="1") != aa.fingerprint(a, skill_version="2")


def test_no_missing_agents_finding_on_empty():
    notes = aa.mechanical_notes([], "empty-repo", long_form_repos=set())
    assert notes == []
    ids = {n["id"] for n in notes}
    assert "agents_md_missing" not in ids


def test_routing_gap_only_with_rules_or_skills_and_no_root():
    with_rule = [{"path": ".cursor/rules/x.mdc", "kind": "cursor_rule", "sha": "1", "lines": 10}]
    notes = aa.mechanical_notes(with_rule, "happycow")
    assert any(n["id"] == "routing_gap" for n in notes)

    with_root = with_rule + [
        {
            "path": "AGENTS.md",
            "kind": "agents_root",
            "sha": "2",
            "lines": 5,
            "text": "- x\n",
        }
    ]
    notes2 = aa.mechanical_notes(with_root, "happycow")
    assert not any(n["id"] == "routing_gap" for n in notes2)

    claude_only = [{"path": "CLAUDE.md", "kind": "claude", "sha": "3", "lines": 4}]
    notes3 = aa.mechanical_notes(claude_only, "mcp")
    assert not any(n["id"] == "routing_gap" for n in notes3)


def test_long_form_skips_line_budget():
    bloated = [
        {
            "path": "AGENTS.md",
            "kind": "agents_root",
            "sha": "x",
            "lines": 122,
            "text": "x\n" * 122,
        }
    ]
    over = aa.mechanical_notes(bloated, "housekeeping", long_form_repos=set())
    assert any(n["id"] == "agents_md_over_budget" for n in over)
    skipped = aa.mechanical_notes(bloated, "housekeeping", long_form_repos={"housekeeping"})
    assert not any(n["id"] == "agents_md_over_budget" for n in skipped)


def test_claude_duplicate_note():
    text = "# AGENTS\n\n" + ("rule\n" * 40)
    files = [
        {
            "path": "AGENTS.md",
            "kind": "agents_root",
            "sha": "a",
            "lines": 42,
            "text": text,
        },
        {
            "path": "CLAUDE.md",
            "kind": "claude",
            "sha": "c",
            "lines": 42,
            "text": text,
        },
    ]
    notes = aa.mechanical_notes(files, "dup", long_form_repos={"dup"})
    assert any(n["id"] == "claude_md_duplicate" for n in notes)


def test_assert_repos_in_owner():
    assert aa.assert_repos_in_owner(["a"], {"a", "b"}) == []
    assert aa.assert_repos_in_owner(["a", "z"], {"a", "b"}) == ["z"]


def test_audit_named_repos_refuses_outside_owner(tmp_path: Path):
    code, report = aa.audit_named_repos(
        owner="me",
        gitroot=tmp_path,
        names=["other"],
        owned={"mine"},
        long_form_repos=set(),
        cache={"repos": {}},
    )
    assert code == 2
    assert report["outside"] == ["other"]


def test_audit_named_repos_empty_surface_no_missing_id(tmp_path: Path):
    repo = tmp_path / "quiet"
    repo.mkdir()
    (repo / ".git").mkdir()
    code, report = aa.audit_named_repos(
        owner="me",
        gitroot=tmp_path,
        names=["quiet"],
        owned={"quiet"},
        long_form_repos=set(),
        cache={"repos": {}},
        list_meta_by_name={"quiet": {"name": "quiet"}},
    )
    assert code == 0
    row = report["repos"][0]
    assert row["notes"] == []
    assert all(n.get("id") != "agents_md_missing" for n in row["notes"])
    assert row["files"] == []


def test_cache_hit_requires_matching_fingerprint_and_audit():
    fp = "abc"
    assert aa.cache_hit(None, fp, owner="me") is None
    assert (
        aa.cache_hit({"skill_version": aa.SKILL_VERSION, "fingerprint": fp}, fp, owner="me") is None
    )
    assert (
        aa.cache_hit(
            {
                "owner": "me",
                "skill_version": "0",
                "fingerprint": fp,
                "audit": {"score": 1},
            },
            fp,
            owner="me",
        )
        is None
    )
    assert aa.cache_hit(
        {
            "owner": "me",
            "skill_version": aa.SKILL_VERSION,
            "fingerprint": fp,
            "audit": {"score": 12},
        },
        fp,
        owner="me",
    ) == {"score": 12}


def test_cache_hit_rejects_other_owner():
    fp = "abc"
    entry = {
        "owner": "alice",
        "skill_version": aa.SKILL_VERSION,
        "fingerprint": fp,
        "audit": {"score": 9},
    }
    assert aa.cache_hit(entry, fp, owner="bob") is None
    assert aa.cache_hit(entry, fp, owner="alice") == {"score": 9}


def test_apply_save_merges_audit(tmp_path: Path):
    report = {
        "owner": "me",
        "repos": [{"repo": "fwlive", "fingerprint": "fp1"}],
    }
    cache: dict = {"repos": {}}
    save = tmp_path / "audit.json"
    save.write_text(json.dumps({"score": 14, "keep": ["x"], "remove": []}))
    aa.apply_save(cache, report, save)
    key = aa.cache_key("me", "fwlive")
    assert cache["repos"][key]["audit"]["score"] == 14
    assert cache["repos"][key]["fingerprint"] == "fp1"
    assert cache["repos"][key]["owner"] == "me"


def test_owner_login_matches():
    assert aa.owner_login_matches("me", {"owner": {"login": "me"}})
    assert aa.owner_login_matches("Me", {"owner": {"login": "me"}})
    assert not aa.owner_login_matches("me", {"owner": {"login": "other"}})
    assert not aa.owner_login_matches("me", {})


def test_inventory_error_does_not_look_empty(tmp_path: Path, monkeypatch):
    def boom(*_a, **_k):
        raise aa.InventoryError("failed to fetch git tree")

    monkeypatch.setattr(aa, "inventory_repo", boom)
    code, report = aa.audit_named_repos(
        owner="me",
        gitroot=tmp_path,
        names=["fwlive"],
        owned={"fwlive"},
        long_form_repos=set(),
        cache={"repos": {}},
    )
    assert code == 2
    assert report["error"] == "inventory failed"
    assert "repos" not in report or "fwlive" not in str(report.get("repos"))


def test_local_fingerprint_tracks_dirty_working_tree(tmp_path: Path):
    repo = tmp_path / "r"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    (repo / "AGENTS.md").write_text("one\n")
    subprocess.run(["git", "add", "AGENTS.md"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "i"], cwd=repo, check=True, capture_output=True)
    clean = aa._inventory_local(repo)
    (repo / "AGENTS.md").write_text("one\ntwo\n")
    dirty = aa._inventory_local(repo)
    assert aa.fingerprint(clean) != aa.fingerprint(dirty)
    assert dirty[0]["lines"] == 2


def test_local_inventory_includes_untracked_instruction_files(tmp_path: Path):
    repo = tmp_path / "r"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    (repo / "README.md").write_text("hi\n")
    subprocess.run(["git", "add", "README.md"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "i"], cwd=repo, check=True, capture_output=True)
    (repo / "AGENTS.md").write_text("- local only\n")
    files = aa._inventory_local(repo)
    paths = {f["path"] for f in files}
    assert "AGENTS.md" in paths
    assert any(f["kind"] == "agents_root" for f in files)
