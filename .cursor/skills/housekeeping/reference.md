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
| Code scanning | Default setup `configured` **or** active CodeQL/osv workflow. Private repos without GHAS are recorded `unavailable_private` and not flagged (same gate as secret scanning). When configured: query suite must be `security-extended`/`security-and-quality`; advanced workflows must be active, trigger on push/PR or schedule, cover the default branch, declare `security-events: write`, and not blanket-ignore paths |
| Branch protection | Default branch protected **or** repo rulesets present. Required reviews are **off by default** for solo owners (`[branch_protection] require_approving_reviews`); set `true` only for team repos. Only checked on owned non-fork repos with code |
| Workflow permissions | Actions default = `read` (least privilege). `write` default is flagged on repos with code |
| Secret scanning extras | GHAS repos: validity checks + non-provider patterns should be enabled (low) |
| SECURITY.md | Required only for repos in `config.toml` `security_repos` (disclosure policy) |
| CI | At least one workflow when the repo has code, **unless** the repo is in `config.toml` `no_ci_repos` (ships nothing) |
| Node 20 action runtime | First-party JS actions on Node-24 majors (`checkout`/`setup-node` **v5+**, `setup-python` **v6+**, etc.) |

Finding `node20_action_runtime` (medium, fix-direct): workflows still pin
majors whose **action runtime** is Node 20 (CI warns they are forced onto
Node 24). Fix by bumping `uses:` majors in a PR — **not** by changing job
`node-version:` / language toolchain. Allowlist of min majors is
`[node20_action_min_majors]` in `config.toml`. Skip with
`python3 scripts/scan.py --skip-workflow-pins`.

CodeQL configuration findings (deep checks, read-only): once code scanning is
present, the scan validates its **quality**, not just existence. Default-setup
repos are checked against the `[codeql] required_query_suite` floor
(`codeql_default_query_suite`, medium/fix-direct — PATCH default-setup) and
for languages present in the tree but absent from the analysis list
(`codeql_language_gap`, low/suggest — auto-detection usually self-heals on
push). Advanced-setup workflows (committed `codeql.yml`) are validated via the
workflows API state and file content: disabled workflows
(`codeql_workflow_disabled`), missing push/PR/schedule triggers or branch
filters that exclude the default branch (`codeql_workflow_inert`), missing
`permissions: security-events: write` (`codeql_workflow_no_security_events`),
no `queries:`/`packs:` suite (default suite only, `codeql_workflow_default_queries`,
low/suggest), `github/codeql-action` pinned below v3
(`codeql_action_major_old`), and blanket `paths-ignore: ['**']`
(`codeql_workflow_paths_ignored`). All medium findings are fix-direct; the
low/suggest pair is filed as issues per housekeeping convention.

Finding `stale_merged_branches` (low, **suggest-only**): remote heads of PRs
merged more than `merged_retention_days` ago (default 30) that still exist.
Filters out default branch, `protected_names` / `protected_prefixes`, and any
branch that is head or base of an open PR. Skipped for `pipeline_repos`,
`parked_repos`, and non-`active_forks`. Config: `[branch_cleanup]`. Skip with
`--skip-branch-cleanup`. **Never delete** these branches unless the user
explicitly asks after reviewing the list (prefer enabling “auto-delete head
branches” for the future — that clears the `delete_branch_on_merge_off` finding).

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

Current `active_forks` is defined in `config.toml` (the authoritative list).

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

## Batch-applying settings (guardrails)

When the user approves batch-applying repo settings (branch protection,
Dependabot toggles, secret scanning), these guardrails prevent the two real
failure modes seen in practice: **locking the solo owner out of their own
repos**, and **bricking merges with un-runnable required checks**.

### Branch protection on a single-owner repo

Config: `[branch_protection] require_approving_reviews` in `config.toml`
(default **`false`**). Controls both hygiene findings and batch-apply advice.

- **`require_approving_reviews = false` (solo default)** — do **not** add
  required reviews when applying protection; `branch_unprotected` must not
  suggest them. If a repo already has `required_approving_review_count >= 1`,
  emit `branch_requires_reviews` (fix-direct). GitHub forbids self-approve,
  so count≥1 bricks every owner/agent merge without `--admin`.
- **`require_approving_reviews = true` (team)** — unprotected finding may
  suggest required reviews + status checks; do not emit
  `branch_requires_reviews`.
- **`enforce_admins: false`** — keep false for solo-owner repos so other
  rules remain bypassable if needed. Protection still governs future
  collaborators.
- **Do NOT require status checks that don't run on PRs.** A check that only
  fires on `push` to main or on tags (release/publish workflows) never reports
  on a PR, so a required check name that never runs **blocks every merge
  forever**. Only require checks verified to run on `pull_request` events
  (query `check-runs` on a recent PR head, not just the workflow list).
- Safe baseline for solo repos: protection with force-push/deletion blocked +
  `enforce_admins: false` + **no** required approving reviews; no required
  status checks until CI-on-PR is confirmed.
- Private repos without GitHub Pro: the branch-protection and rulesets APIs
  return **403** (`Upgrade to GitHub Pro or make this repository public`).
  Report `branch_protection: null` (unknown) and do **not** emit a finding —
  the scanner already does this via the `rulesets is None` fail-closed path.

### GHAS sub-features are UI-only on User accounts

`secret_scanning_validity_checks` and `secret_scanning_non_provider_patterns`
are **NOT settable via REST for a personal User account** (the account type of
most `owner` values here). The only writable endpoints in the current OpenAPI
spec are org/enterprise **code security configurations**
(`/orgs/{org}/code-security/configurations/...`), which do not exist for a
User. The old repo-level `PATCH /repos/{o}/{r}/security-and-analysis` is gone
from the spec.

- On a User account these toggles are **one UI click per repo**
  (Settings → Code security), not a scriptable one-liner.
- The scanner reflects this: `owner_is_user_account()` downgrades the two GHAS
  findings to `suggest` with a UI pointer. Do not try to "fix" them via API —
  it will 404.
- On an org owner they stay `fix-direct` (settable via code security configs).

### Verification after applying

- Re-query each setting after the write (`gh api … --jq` on the field you
  changed, or `-i` for a 204/404 status check) — a PUT that exits 0 is not
  proof the setting took.
- Re-run the scan on the touched repos and confirm the expected findings
  cleared (and none appeared).

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
