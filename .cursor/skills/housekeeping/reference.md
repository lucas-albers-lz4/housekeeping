# Repo cleanup reference

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

## Size playbook

### fix-direct

- CodeQL `actions/missing-workflow-permissions` — add `permissions:` blocks
- Single high/medium Dependabot on an active repo you already have checked out
- Tiny UX/copy issues with clear acceptance criteria
- Merge a green single-package Dependabot PR after glancing at the diff

Still use a branch + PR if the change is more than a few lines or CI is flaky.

### batch-pr

- Repos with dozens of Dependabot alerts (`mattermost-*`, old forks, etc.)
- Prefer existing Dependabot group PRs; rebase/recreate if stale
- Clone under `gitroot` if missing before editing

### issue-pr

- Multi-file design, infra, or review-tracking issues (e.g. MCR findings,
  Cilium networking review, QEMU smoke re-enable)
- Keep discussion on the GitHub issue; PR references the issue

### park

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
- Separate sections: quick wins, Dependabot piles, PRs, issues, pipeline, dirty locals.
- Link to GitHub URLs; do not dump huge alert tables (summarize by repo + severity).

## Extending config

```toml
pipeline_repos = ["sre-ai-llm-work"]
pipeline_labels = ["pipeline", "no-triage", "source-note", "guide-update", "miner-eval"]
never_merge_labels = ["miner-eval"]
```

Add labels as new agent workflows appear.
