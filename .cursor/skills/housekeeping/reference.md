# Repo cleanup reference

## Owner scope

Housekeeping targets **one** GitHub `owner` from `config.toml`. Agents must not
scan or open drive-by issues/PRs outside that owner. Forks of this toolkit keep
the same default (set their own `owner`). See `AGENTS.md` and
`.cursor/rules/owner-scope.mdc`.

## Pipeline labels (sre-ai-llm-work)

Configured in `config.toml`. Non-exhaustive meanings:

| Label | Role |
|-------|------|
| `new-source` / `new-seed` | Awaiting Prospector triage |
| `source-submission` | Human submission |
| `pre-screen:pass` / `rejected` | Tier-1 screening |
| `no-triage` | Internal/pipeline/bug — skip Prospector |
| `triaged:text` / `triaged:failure` / `triaged:repo` | Routed to Miner / failure path / Repo Scout |
| `mining-queued` / `mining-complete` / `miner-blocked` | Miner lifecycle |
| `source-note` | Miner PR — triggers Assayer |
| `guide-update` | Smith guide PR — Assayer review |
| `miner-eval` | Eval PR — **never merge** |
| `pipeline` | Throughput / agent meta work |
| `mine-attempt-*` / `sn-rework-*` / `gu-rework-*` | Retry / rework rounds |

When scanning account-wide, list these under **pipeline**, not open debt.

## Repo hygiene baselines (Tier 1)

Hygiene findings come from `scan_repo_hygiene` in `scripts/scan.py`. They flag
**missing automation**, not open CVEs. Fix with settings toggles and/or a PR
that adds files from `templates/`.

| Expectation | Good state |
|-------------|------------|
| Vulnerability alerts | Enabled |
| Dependabot security updates | Enabled |
| `.github/dependabot.yml` | Present; ecosystems cover detected manifests + `github-actions` when workflows exist |
| Secret scanning | Enabled on **public** repos (private needs GitHub Advanced Security) |
| Push protection | Enabled on **public** repos (same GHAS limit for private) |
| Code scanning | Default setup `configured` **or** CodeQL/osv workflow |
| CI | At least one workflow when the repo has code |
| Node 20 action runtime | First-party JS actions on Node-24 majors (`checkout`/`setup-node` **v5+**, `setup-python` **v6+**, etc.) |

Finding `node20_action_runtime` (medium, fix-direct): workflows still pin
majors whose **action runtime** is Node 20 (CI warns they are forced onto
Node 24). Fix by bumping `uses:` majors in a PR — **not** by changing job
`node-version:` / language toolchain. Allowlist of min majors is
`[node20_action_min_majors]` in `config.toml`. Skip with
`python3 scripts/scan.py --skip-workflow-pins`.

Finding `stale_merged_branches` (low, **suggest-only**): remote heads of PRs
merged more than `merged_retention_days` ago (default 30) that still exist.
Filters out default branch, `protected_names` / `protected_prefixes`, and any
branch that is head or base of an open PR. Skipped for `pipeline_repos`,
`parked_repos`, and non-`active_forks`. Config: `[branch_cleanup]`. Skip with
`--skip-branch-cleanup`. **Never delete** these branches unless the user
explicitly asks after reviewing the list (prefer enabling “auto-delete head
branches” for the future via `delete_branch_on_merge_off`).

Finding `readme_badges_thin` / `about_metadata_thin` (low, **suggest-only**):
README badge gaps (CI / license when applicable) and thin GitHub About
metadata (missing description and/or topics). Inspired by common shields.io +
Actions badge rows — detection only; scan never edits READMEs or repo
settings. Package-registry badges are **not** required (manifests ≠ published
packages). Skipped for `pipeline_repos`, `parked_repos`, non-`active_forks`,
and repos without code. Config: `[readme_polish]`. Skip with
`--skip-readme-polish`.

Private repos without GHAS: the scanner records `secret_scanning` /
`push_protection` as `unavailable_private` and does **not** emit
`secret_scanning_off` / `push_protection_off`. Dependabot security updates are
only flagged when explicitly `disabled` (or alerts are off and status is missing).

**Default Dependabot style:** security-only (see
`templates/dependabot.security-only.yml`): weekly schedule,
`open-pull-requests-limit: 0`, ignore all version-update types — relies on
Dependabot **security updates** for PRs. Do not dual-run Renovate + Dependabot
version updates.

**Tier 2 (low severity in scan):** auto-delete head branches; dependency-review
workflow when lockfiles exist (`templates/dependency-review.yml`).

Forks and archived repos score `park` — **except** forks listed in
`config.toml` `active_forks`, which triage as **Active fork — fix** (same
Dependabot/settings bar as owned repos). Stale-branch suggestions on active
forks still use the **suggest_only** verdict.

Archived repos: hygiene findings, open PRs/issues, and security alerts are
**parked** (not suggested as `batch-pr` / fix-direct). The scanner still lists
open PRs/issues under an archived-park section so nothing is invisible.

Current `active_forks`: cert-manager-webhook-duckdns, helm-whatup,
docker-duckdns, jobs-filterer-for-linkedin, NorseWorld-Ragnarok,
easy-aws-login.

## Size playbook

### fix-direct

- CodeQL `actions/missing-workflow-permissions` — add `permissions:` blocks
- Single high/medium Dependabot on an active repo you already have checked out
- Tiny UX/copy issues with clear acceptance criteria
- Merge a green single-package Dependabot PR after glancing at the diff
- Hygiene: add `dependabot.yml` from templates, enable push protection / security
  updates, turn on CodeQL default setup
- Hygiene: bump Node-20-runtime action pins (`actions/checkout@v5`,
  `actions/setup-python@v6`, …) — see `node20_action_runtime` finding

Still use a branch + PR if the change is more than a few lines or CI is flaky.

### batch-pr

- Repos with dozens of Dependabot alerts (`mattermost-*`, old forks, etc.)
- Prefer existing Dependabot group PRs; rebase/recreate if stale
- Clone under `gitroot` if missing before editing

### issue-pr

- Multi-file design, infra, or review-tracking issues (e.g. MCR findings,
  Cilium networking review, QEMU smoke re-enable)
- Keep discussion on the GitHub issue; PR references the issue

### suggest (human confirm)

- `stale_merged_branches`: show the candidate list; delete only after explicit
  user approval (one repo / named branches). Do not bulk-delete across the owner.
- `readme_badges_thin` / `about_metadata_thin`: note badge or About gaps; human
  decides whether to add shields/Actions badges or set description/topics.
  Do not auto-PR README/About changes from housekeeping.

### park

- Archived repos (open Dependabot PRs, leftover issues — skip, do not batch-merge)
- `hermes-agent`-style osv-scanner floods on forks you are not actively shipping
- Optional-later design issues already marked deferred
- Upstream/vendor checkouts under `gitroot` that you do not own

## Known gotchas

- `gh api …/secret-scanning/alerts` returns 404 when disabled — scripts treat
  that as unavailable, not “3 secrets”.
- Dependabot `severity` lives under `security_vulnerability.severity`, not the
  top-level `severity` field (often null).
- `gh api --paginate` returns one JSON array; do not `jq -s add` unless you
  know pages were concatenated as multiple arrays.
- Local `gitroot` mixes owned remotes and upstream clones — `owned` in the
  local scan is substring match on `origin` URL vs owner login.
- Ansible major bumps (e.g. 8→12) can break roles — smoke before merge even if
  tagged fix-direct.

## Canvas triage board

When producing a visual board, use a Cursor canvas in this workspace:

- Embed data from `out/scan-latest.json` (inline constants).
- Separate sections: hygiene by **verdict** (exclusions first), quick wins,
  Dependabot piles, PRs, issues, pipeline, dirty locals.
- Hygiene finding counts must be sorted/grouped via
  `scripts/hygiene_verdicts.py` (park archived → park fork → parked_repos →
  tier2 skip → pipeline skip → suggest_only → ship only → active_fork) so
  exclusions are obvious.
- Link to GitHub URLs; do not dump huge alert tables (summarize by repo + severity).
- Hygiene ≠ alert debt — keep a dedicated “Hygiene gaps” / verdict table.

## Extending config

```toml
pipeline_repos = ["sre-ai-llm-work"]
pipeline_labels = ["pipeline", "no-triage", "source-note", "guide-update", "miner-eval"]
never_merge_labels = ["miner-eval"]
```

Add labels as new agent workflows appear.
