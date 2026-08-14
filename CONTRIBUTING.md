# Contributing

This is a personal cross-repo hygiene toolkit for `lucas-albers-lz4`. Contributions
are welcome if they keep the scanner **read-only by default** and respect pipeline
safety for `sre-ai-llm-work`.

## Setup

```bash
git clone git@github.com:lucas-albers-lz4/housekeeping.git
cd housekeeping
# Requires: gh (authenticated), Python 3.11+
gh auth status
python3 scripts/scan.py --help
```

## Making changes

1. Prefer extending `scripts/scan.py`, `scripts/triage_queue.py`, or
   `scripts/hygiene_verdicts.py` over one-off `gh` loops. Instruction-surface
   audit is a separate opt-in script (`scripts/audit_agents.py`); do not fold
   it into the default scan.
2. Keep scans read-only. Write actions (merge, enable settings, open PRs) only
   when the operator explicitly asks.
3. Update `.cursor/skills/housekeeping/` when agent behavior should change.
4. Put Dependabot / workflow snippets under `templates/`.
5. Do not commit `out/` scan JSON (gitignored) or secret-scanning payloads.

## Agent docs

- **`AGENTS.md`** — canonical instructions for Cursor / coding agents in this repo.
- **`CLAUDE.md`** — Claude Code entrypoint; defers to `AGENTS.md` (not a duplicate).

## License

MIT — see [LICENSE](LICENSE).
