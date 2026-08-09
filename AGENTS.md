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

## Quick start (new operator)

1. **Configure**: `cp config.example.toml config.toml`, set `owner` (your
   GitHub user/org) and `gitroot` (parent dir of your local checkouts, so
   dirty-tree status works; or always pass `--skip-local`).
2. **Scan**: `python3 scripts/scan.py` → full report at `out/scan-latest.json`
   + stdout summary. Narrow with `--repos a,b`; skip passes with
   `--skip-alerts` / `--skip-hygiene` / `--skip-workflow-pins` /
   `--skip-branch-cleanup` / `--skip-readme-polish`.
3. **Triage**: `python3 scripts/triage_queue.py` → verdict-sorted queues
   (fix-direct / suggest-only / park).
4. **Fix**: settings first (table below), then PR-able items, then file
   suggest-only items as issues. **Re-scan after every fix** — settings
   changes clear immediately; PR-branch findings clear on merge.

## Findings → what to do

| Class | Findings | Action |
|-------|----------|--------|
| **Settings toggle (REST)** | `vuln_alerts_off`, `dependabot_security_updates_off`, `delete_branch_on_merge_off`, `code_scanning_not_configured`, `codeql_default_query_suite`, `workflow_permissions_write`, `branch_unprotected` | `gh api` PUT/PATCH per `.cursor/skills/housekeeping/reference.md` recipes; **re-query each setting after applying** (a PUT returning 0 is not proof). Code-scanning default-setup PATCH is **async** — returns `202` + `run_id` (applied by an Actions run); poll the GET 1–3 min before trusting it. |
| **Settings toggle (UI-only — no REST endpoint)** | `secret_scanning_off`, `push_protection_off`, `secret_validity_checks_off`, `secret_nonprovider_patterns_off` | **Manual per repo**: Settings → Code security → Secret scanning / Push protection. There is **no API path** to enable these (verified: not in the current OpenAPI spec; the old `security-and-analysis` endpoint is gone; org/enterprise code-security configurations don't exist for User accounts). Do not attempt API writes — they 404. Flag the exact repos to the user as a manual step. |
| **PR-able (fix-direct)** | `missing_dependabot_yml`, `node20_action_runtime`, `codeql_workflow_disabled`, `codeql_workflow_inert`, `codeql_workflow_no_security_events`, `codeql_workflow_paths_ignored`, `codeql_action_major_old`, `missing_security_policy` | Add the `templates/` file or edit the workflow, open a PR, leave it for user review. |
| **Suggest (file as issues)** | `codeql_language_gap`, `codeql_workflow_default_queries`, `stale_merged_branches`, `readme_badges_thin`, `about_metadata_thin` | File a GitHub issue with acceptance criteria + “found by housekeeping scan”; never auto-apply. |
| **Park** | archived repos, non-`active_forks` forks | Skip; list for visibility only. |

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
10. **Settings changes need explicit approval + verification.** Enabling repo
    settings (branch protection, Dependabot, code scanning) is a write action —
    batch only after the user says so, and re-query each setting after applying.
    **Secret scanning / push protection cannot be set via API** — when a scan
    flags them, tell the user it's a manual Settings → Code security toggle
    (see the findings table). See
    `.cursor/skills/housekeeping/reference.md` → "Batch-applying settings" for
    the guardrails that prevent solo-owner lockout and bricked merges.

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
| `config.toml` / `config.example.toml` | owner, gitroot, pipeline labels, `active_forks`, `branch_cleanup`, `branch_protection`, `readme_polish`, Node 20 mins, `[codeql] required_query_suite` |
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
