---
name: housekeeping
description: >-
  Multi-repo GitHub cleanup for one configured owner (config.toml): scan
  Dependabot, code/secret scanning, repo hygiene/automation config (including
  Node 20 action-runtime pins), open PRs/issues, and gitroot dirty trees;
  classify fix-direct vs batch-PR vs issue/PR vs pipeline; produce a triage
  board. Use when this housekeeping workspace is open and the user asks to scan
  repos, clean up alerts/PRs/issues, audit Dependabot/security settings, or run a
  cross-repo hygiene pass.
---

# Housekeeping (repo cleanup)

Read-only scan first. Fix only after the user picks a queue item. Never treat
pipeline-labeled work (`pipeline_repos` / `pipeline_labels`) as cleanup debt.

## Owner scope

Target **only** `config.toml` `owner` (or `--owner`). `gh` is for that
operator’s repos. Do not use this toolkit to spam suggestions, issues, or PRs
at arbitrary third-party repositories. Forks of this project inherit the same
default: configure **their** owner and stay inside it (see `AGENTS.md` and
`.cursor/rules/owner-scope.mdc`).

## Before anything else

1. Confirm workspace is `housekeeping` (this project).
2. Read `config.toml` for owner, gitroot, pipeline labels.
3. Run the scan scripts (do not re-invent ad-hoc `gh` loops unless scripts fail).
4. Present a triage queue; wait for the user to choose what to fix.
5. Before editing another project: `move_agent_to_root` into that checkout under
   `gitroot`, then fix there — do not edit sibling repos from this workspace.

## Commands

```bash
# Full scan → out/scan-<ts>.json + out/scan-latest.json + stdout summary
python3 scripts/scan.py

# Compact queue from latest report
python3 scripts/triage_queue.py

# Narrow / faster
python3 scripts/scan.py --repos irr,rke2setup,fwlive
python3 scripts/scan.py --skip-alerts   # PRs/issues/local (+ hygiene) only
python3 scripts/scan.py --skip-hygiene  # skip config/automation audit
python3 scripts/scan.py --skip-workflow-pins  # skip Node 20 action-runtime pin fetch
python3 scripts/scan.py --skip-branch-cleanup  # skip suggest-only stale branch check
python3 scripts/scan.py --skip-readme-polish  # skip suggest-only README/About polish
python3 scripts/scan.py --skip-local
```

Instruction-surface audit is **not** part of the default scan. Do not run it
unless the user names repo(s). Skill: `.cursor/skills/agents-md/`.

```bash
python3 scripts/audit_agents.py --repos fwlive
```

Requires authenticated `gh` with access to the owner’s repos (including private).

## Classification (size tags)

| Tag | Meaning | Action |
|-----|---------|--------|
| `fix-direct` | Tiny (workflow permissions, single dep bump, trivial UX) | Fix in place; still prefer a PR if non-trivial |
| `batch-pr` | Many Dependabot alerts or group bumps | One PR / merge existing Dependabot PRs after CI |
| `issue-pr` | Real design/bug work | Issue → PR → review |
| `pipeline` | Agent workflow queue (labels) | Leave alone unless user asks |
| `never-merge` | e.g. `miner-eval` | Do not merge |
| `suggest` | Ambiguous polish or destructive (README badges, About, stale merged branches) | List only; act only if user explicitly asks |
| `park` | Fork noise / archived / low-value / deferred | Skip |

**Repo hygiene** findings (`repo_hygiene` in the report) are missing automation
config (Dependabot.yml, push protection, CodeQL default setup, etc.) — not the
same as open alert debt. Prefer fix-direct PRs using `templates/`. Forks default
to `park` unless you actively maintain them.

Heuristics in scripts are starting points — adjust with judgment.

## Pipeline safety (sre-ai-llm-work)

Issues/PRs with labels in `config.toml` `pipeline_labels` (and repos in
`pipeline_repos`) are **work for Miner / Smith / Assayer / Prospector**, not
human cleanup backlog. Examples: `source-note`, `guide-update`, `mining-queued`,
`pipeline`, `no-triage`, `miner-eval`.

- Do **not** close them to “clean up”.
- Do **not** merge `miner-eval` PRs.
- Only touch them when the user explicitly wants pipeline/ops changes.

Details: [reference.md](reference.md).

## Safety rules

- Scans are **read-only**. No force-push, no mass-close, no bulk dismiss of alerts
  without explicit user request.
- Do **not** delete remote branches from `stale_merged_branches` / suggest-only
  findings unless the user explicitly asks (and confirm the branch list first).
- Do not commit secrets; do not paste secret-scanning payloads into chat/canvas.
- **Never merge a PR without explicit user approval** (your own fix PRs
  included) — open it, report it, wait. Exception: green Dependabot group
  PRs merged inside an already-approved `batch-pr` pass.
- Prefer merging green Dependabot PRs over hand-editing lockfiles when
  possible (within an approved `batch-pr` pass).
- After picking a target repo: update its working copy (`git fetch`/`pull` as
  needed), then `move_agent_to_root` before edits.
- For canvases: put triage boards under this project’s `canvases/` only when the
  workspace is `housekeeping`; embed scan data inline (no live fetch in canvas).
- **Batch settings only with explicit user approval, then verify each write**
  (re-query the setting after each write — a PUT exit 0 is not proof). On
  **single-owner repos**, branch protection must use `enforce_admins: false`,
  must follow `[branch_protection] require_approving_reviews` (default
  **false** — GitHub blocks self-approve → owner merges brick without
  `--admin`), and must **not** require status checks that only run on
  push/tags (they never report on PRs → all merges brick). GHAS sub-feature
  toggles (`secret_scanning_validity_checks`,
  `secret_scanning_non_provider_patterns`) are **UI-only on User accounts** —
  do not attempt via API. Full detail: `reference.md` → "Batch-applying
  settings".

## Deliverable shape

1. Run `scan.py` → summarize counts.
2. Run `triage_queue.py` (or build an equivalent canvas from `scan-latest.json`).
3. Ask which item to do next.
4. Move into that repo and fix with the agreed size process.

## Files

- `scripts/scan.py` — owner-wide scan (alerts + hygiene + PRs/issues + local)
- `scripts/audit_agents.py` — opt-in instruction-surface inventory (`--repos` required)
- `scripts/triage_queue.py` — queue printer
- `templates/` — security-only Dependabot + dependency-review snippets
- `config.toml` — owner, gitroot, pipeline allowlists
- `out/scan-latest.json` — latest report (gitignored)
