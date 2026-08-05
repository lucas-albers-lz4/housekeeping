# AGENTS

This workspace is the **housekeeping** toolkit: multi-repo GitHub hygiene for
**one configured owner** (see `config.toml` `owner`).

## Owner scope (sane default — keep in forks)

These defaults are intentional. Forkers may rewrite them, but the shipped
baseline is **not** a general-purpose “suggest hygiene to any repo on GitHub”
tool.

1. **Single owner only.** Scan and triage only repos under `config.toml`
   `owner` (or `--owner`). Never point `gh` / scans / fix PRs at arbitrary
   third-party users or orgs you do not administer.
2. **`gh` is for your account.** Authenticate as the operator who owns or
   administers that `owner`. Do not use this toolkit to mass-comment, open
   drive-by issues/PRs, or “helpfully” spam suggestions across the public
   network.
3. **Forks stay constrained.** If someone forks this repo for reuse, the
   default remains: set **their** `owner`, scan **their** repos only. That
   constraint is the irrevocable product intent of these agent rules unless
   they deliberately change the rules files.
4. **`--repos` narrows, never expands.** A repo list must be a subset of the
   configured owner’s repos — never a way to reach outside `owner`.

## Must follow

1. Read `.cursor/skills/housekeeping/SKILL.md` (and `reference.md`) for scan /
   triage / cross-repo work.
2. Prefer `python3 scripts/scan.py` and `python3 scripts/triage_queue.py` over
   ad-hoc `gh` loops (alerts + repo hygiene + verdicts).
3. Do **not** treat pipeline-labeled issues/PRs (labels in `config.toml`
   `pipeline_labels`, repos in `pipeline_repos`) as cleanup debt.
4. Before editing another project: `move_agent_to_root` into that checkout under
   `gitroot` — do not edit sibling repos from this workspace.
5. Hygiene findings (missing Dependabot.yml / security settings / Node 20
   action-runtime pins) are **config debt** — use `templates/` for fix-direct
   PRs; do not confuse with open CVE piles.
6. Forks in `config.toml` `active_forks` are maintained — fix hygiene, do not park.
7. Repos in `config.toml` `parked_repos` are explicitly parked (e.g. class clones).
8. **Archived** repos: park hygiene, PRs, issues, and alerts — do not suggest
   `batch-pr` merges.
9. Scans are **read-only**. No force-push, mass-close, or bulk alert dismiss
   without an explicit user request. Never merge PRs with labels in
   `never_merge_labels` (e.g. `miner-eval`). Never delete remote branches
   from `stale_merged_branches` / suggest-only findings without an explicit ask.
   `readme_badges_thin` / `about_metadata_thin` are also suggest-only (no auto
   README/About edits).

## Commands

```bash
python3 scripts/scan.py              # full report → out/scan-latest.json
python3 scripts/triage_queue.py      # verdict-sorted queue from latest report
python3 scripts/scan.py --skip-hygiene
python3 scripts/scan.py --skip-workflow-pins
python3 scripts/scan.py --skip-branch-cleanup
python3 scripts/scan.py --skip-readme-polish
python3 scripts/scan.py --repos irr,fwlive
```

## Layout

| Path | Role |
|------|------|
| `config.toml` / `config.example.toml` | owner, gitroot, pipeline labels, `active_forks`, `branch_cleanup`, `readme_polish`, Node 20 mins |
| `scripts/scan.py` | owner-wide scan |
| `scripts/triage_queue.py` | queue printer |
| `scripts/hygiene_verdicts.py` | park / tier2 / suggest_only / active_fork / ship_only |
| `templates/` | security-only Dependabot, dependency-review |
| `.cursor/skills/housekeeping/` | Cursor skill |
| `.cursor/rules/owner-scope.mdc` | Always-on owner-scope agent rule |

## CLAUDE.md vs AGENTS.md

- **`AGENTS.md`** (this file) — shared agent instructions (Cursor and others).
- **`CLAUDE.md`** — Claude Code looks for this name; keep it a short pointer to
  `AGENTS.md`, not a full duplicate. Do not symlink unless you intentionally want
  one file for both tools; a thin `CLAUDE.md` is clearer when Claude-specific
  notes appear later.
