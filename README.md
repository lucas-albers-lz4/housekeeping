# housekeeping

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Cross-repo GitHub hygiene toolkit: scan Dependabot / code scanning / secrets,
**repo automation config** (Dependabot.yml, secret scanning, CodeQL, Node 20
action-runtime pins, etc.), open PRs & issues, and dirty trees under a local
gitroot, then triage what to fix-direct vs batch vs leave to pipelines.

## Requirements

- [`gh`](https://cli.github.com/) authenticated (`gh auth status`)
- Python 3.11+ (uses `tomllib`)
- Local checkouts optional; default root `~/gitroot`

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
| `never_merge_labels` | e.g. `miner-eval` |
| `node20_action_min_majors` | Min majors for Node-24-capable first-party actions |

## Project skill

When this repo is the Cursor workspace root, the agent skill at
`.cursor/skills/housekeeping/` is available. It tells the agent to use these
scripts, respect `pipeline_repos` / labels from config, and
`move_agent_to_root` into a target checkout before editing.

Agent entrypoints: [`AGENTS.md`](AGENTS.md) (canonical), [`CLAUDE.md`](CLAUDE.md)
(Claude Code pointer).

## Layout

```
config.example.toml         # starter config for any owner
config.toml                 # your local/owner settings (may be personal)
scripts/scan.py             # full read-only scan (alerts + hygiene)
scripts/triage_queue.py     # verdict-sorted queue from latest report
scripts/hygiene_verdicts.py # park / active_fork / tier2 / ship_only
templates/                  # Dependabot / dependency-review snippets
.cursor/skills/housekeeping/
out/                        # generated reports (gitignored)
```

## Safety

Scans are read-only. Do not mass-close issues, force-push, or dismiss alerts
without an explicit ask. Never merge PRs labeled in `never_merge_labels`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
