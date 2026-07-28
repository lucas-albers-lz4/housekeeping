# housekeeping

Cross-repo hygiene toolkit for [lucas-albers-lz4](https://github.com/lucas-albers-lz4):
scan Dependabot / code scanning / secrets, open PRs & issues, and dirty trees
under `~/gitroot`, then triage what to fix-direct vs batch vs leave to pipelines.

## Requirements

- `gh` authenticated (`gh auth status`)
- Python 3.11+ (uses `tomllib`)
- Local checkouts optional; default root `~/gitroot`

## Quick start

```bash
python3 scripts/scan.py
python3 scripts/triage_queue.py
```

Reports land in `out/scan-latest.json`.

## Project skill

When this repo is the Cursor workspace root, the agent skill at
`.cursor/skills/housekeeping/` is available. It tells the agent to use these
scripts, respect pipeline labels (especially `sre-ai-llm-work`), and
`move_agent_to_root` into a target checkout before editing.

## Layout

```
config.toml                 # owner, gitroot, pipeline labels
scripts/scan.py             # full read-only scan
scripts/triage_queue.py     # queue from latest report
.cursor/skills/housekeeping/
out/                        # generated reports (gitignored)
```

## Safety

Scans are read-only. Do not mass-close issues, force-push, or dismiss alerts
without an explicit ask. Never merge PRs labeled `miner-eval`.
