# housekeeping

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Cross-repo GitHub hygiene toolkit for one owner. It scans Dependabot, code
scanning, secrets, repo automation config (Dependabot.yml, secret scanning,
CodeQL, Node 20 action-runtime pins), open PRs and issues, and dirty trees
under a local gitroot. It then triages what to fix-direct vs batch vs leave
to pipelines.

## Requirements

- [`gh`](https://cli.github.com/) authenticated (`gh auth status`)
- Python 3.11+ (uses `tomllib`)
- Local checkouts optional; default root `~/gitroot`
- Optional: [`actionlint`](https://github.com/rhysd/actionlint) and
  [`zizmor`](https://github.com/zizmorcore/zizmor) on `PATH` for
  suggest-only workflow-linter findings. If a binary is not on PATH, that
  linter is skipped (not a clean bill).

## Quick start (your account)

```bash
git clone <this-repo>
cd housekeeping
cp config.example.toml config.toml   # set owner = "YOUR_GITHUB_USER_OR_ORG"
python3 scripts/scan.py
python3 scripts/triage_queue.py
```

Or without editing the file: `python3 scripts/scan.py --owner YOUR_USER`.

Reports land in `out/scan-latest.json` (gitignored; includes `repo_hygiene`).

Copy-paste baselines live under `templates/` (security-only Dependabot, Actions-only
snippet, optional dependency-review workflow).

## For another GitHub user or org

1. Copy [`config.example.toml`](config.example.toml) → `config.toml` and set `owner`.
2. Leave `pipeline_repos` / `pipeline_labels` / `active_forks` empty unless you
   have agent pipelines or maintained forks.
3. Run `python3 scripts/scan.py` with a `gh` token that can read that owner’s repos.
4. Optional: point `--gitroot` at your local checkouts for dirty-tree status.

**Scope default:** this toolkit only targets the configured `owner`. It is not
for spamming hygiene suggestions across unrelated public repos. Agent rules in
[`AGENTS.md`](AGENTS.md), [`.cursor/rules/owner-scope.mdc`](.cursor/rules/owner-scope.mdc),
and [`CLAUDE.md`](CLAUDE.md) encode that; forkers may rewrite them, but the
shipped sane default stays owner-scoped.

Personal allowlists (`pipeline_*`, `active_forks`) should stay in your local
`config.toml` — for a public fork, prefer `config.example.toml` in git and keep
`config.toml` uncommitted (or use a private fork).

## Configuration

Edit [`config.toml`](config.toml) (see example):

| Key | Purpose |
|-----|---------|
| `owner` | GitHub user/org to scan (**required**) |
| `gitroot` | Local checkouts root |
| `pipeline_repos` / `pipeline_labels` | Leave labeled workflow queue alone |
| `active_forks` | Forks you maintain (not parked) |
| `no_ci_repos` | Repos that ship nothing — skip the `missing_ci_workflow` finding |
| `security_repos` | Repos that must have a `SECURITY.md` — emits `missing_security_policy` when absent |
| `never_merge_labels` | e.g. `miner-eval` |
| `node20_action_min_majors` | Min majors for Node-24-capable first-party actions |
| `[branch_protection] require_approving_reviews` | Suggest/require PR reviews (default `false` for solo owners) |
| `[codeql] required_query_suite` | Default-setup suite floor: `extended` (default) / stronger passes; `default` triggers `codeql_default_query_suite`; set `"default"` to disable |
| `[instruction_audit] long_form_repos` | Opt-in AGENTS.md audit only (`audit_agents.py --repos`). Not read by `scan.py`. |
| `[workflow_linters]` | Suggest-only actionlint + zizmor (`enabled`, paths, `zizmor_min_severity`, persona `regular`/`pedantic`/`auditor`). Each tool is skipped if it is not on PATH |

## Project skill

When this repo is the Cursor workspace root, the agent skill at
`.cursor/skills/housekeeping/` is available. It tells the agent to use these
scripts, respect `pipeline_repos` / labels from config, and
`move_agent_to_root` into a target checkout before editing.

Instruction-surface audit (AGENTS.md / Cursor rules / skills) is **opt-in**
and **not** part of `scan.py`. Use `.cursor/skills/agents-md/` only when the
operator names repos: `python3 scripts/audit_agents.py --repos <name>`.

Agent entrypoints: [`AGENTS.md`](AGENTS.md) (canonical), [`CLAUDE.md`](CLAUDE.md)
(Claude Code pointer).

## Layout

```
config.example.toml         # starter config for any owner
config.toml                 # your local/owner settings (may be personal)
scripts/scan.py             # full read-only scan (alerts + hygiene)
scripts/audit_agents.py     # opt-in instruction audit (--repos required)
scripts/triage_queue.py     # verdict-sorted queue from latest report
scripts/hygiene_verdicts.py # park / active_fork / tier2 / ship_only
templates/                  # Dependabot / dependency-review snippets
.cursor/skills/housekeeping/
.cursor/skills/agents-md/   # opt-in AGENTS.md / rules / skills audit
out/                        # generated reports (gitignored)
```

## Safety

Scans are read-only. Do not mass-close issues, force-push, or dismiss alerts
without an explicit ask. Never merge PRs labeled in `never_merge_labels`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
