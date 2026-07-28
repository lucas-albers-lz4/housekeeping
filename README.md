# housekeeping

Cross-repo hygiene toolkit for [lucas-albers-lz4](https://github.com/lucas-albers-lz4):
scan Dependabot / code scanning / secrets, **repo automation config** (Dependabot.yml,
secret scanning, CodeQL, etc.), open PRs & issues, and dirty trees under `~/gitroot`,
then triage what to fix-direct vs batch vs leave to pipelines.

## Requirements

- [`gh`](https://cli.github.com/) authenticated (`gh auth status`)
- Python 3.11+ (uses `tomllib`)
- Local checkouts optional; default root `~/gitroot`

## Quick start

```bash
git clone git@github.com:lucas-albers-lz4/housekeeping.git
cd housekeeping
python3 scripts/scan.py
python3 scripts/triage_queue.py
```

Reports land in `out/scan-latest.json` (gitignored; includes `repo_hygiene` and
feeds the triage canvas).

Copy-paste baselines live under `templates/` (security-only Dependabot, Actions-only
snippet, optional dependency-review workflow).

## Configuration

Edit [`config.toml`](config.toml):

| Key | Purpose |
|-----|---------|
| `owner` | GitHub user/org to scan |
| `gitroot` | Local checkouts root |
| `pipeline_repos` / `pipeline_labels` | Leave labeled workflow queue alone |
| `active_forks` | Forks you maintain (not parked) |
| `never_merge_labels` | e.g. `miner-eval` |

## Project skill

When this repo is the Cursor workspace root, the agent skill at
`.cursor/skills/housekeeping/` is available. It tells the agent to use these
scripts, respect pipeline labels (especially `sre-ai-llm-work`), and
`move_agent_to_root` into a target checkout before editing.

Agent entrypoints: [`AGENTS.md`](AGENTS.md) (canonical), [`CLAUDE.md`](CLAUDE.md)
(Claude Code pointer).

## Layout

```
config.toml                 # owner, gitroot, pipeline labels, active_forks
scripts/scan.py             # full read-only scan (alerts + hygiene)
scripts/triage_queue.py     # verdict-sorted queue from latest report
scripts/hygiene_verdicts.py # park / active_fork / tier2 / ship_only
templates/                  # Dependabot / dependency-review snippets
.cursor/skills/housekeeping/
out/                        # generated reports (gitignored)
```

## Safety

Scans are read-only. Do not mass-close issues, force-push, or dismiss alerts
without an explicit ask. Never merge PRs labeled `miner-eval`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
