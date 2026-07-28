# AGENTS

This workspace is the **housekeeping** toolkit for multi-repo GitHub hygiene under
`lucas-albers-lz4`.

## Must follow

1. Read `.cursor/skills/housekeeping/SKILL.md` (and `reference.md`) for scan /
   triage / cross-repo work.
2. Prefer `python3 scripts/scan.py` and `python3 scripts/triage_queue.py` over
   ad-hoc `gh` loops (alerts + repo hygiene + verdicts).
3. Do **not** treat `sre-ai-llm-work` pipeline-labeled issues/PRs as cleanup debt
   (labels in `config.toml` `pipeline_labels`).
4. Before editing another project: `move_agent_to_root` into that checkout under
   `~/gitroot` — do not edit sibling repos from this workspace.
5. Hygiene findings (missing Dependabot.yml / security settings) are **config
   debt** — use `templates/` for fix-direct PRs; do not confuse with open CVE piles.
6. Forks in `config.toml` `active_forks` are maintained — fix hygiene, do not park.
7. Scans are **read-only**. No force-push, mass-close, or bulk alert dismiss
   without an explicit user request. Never merge `miner-eval` PRs.

## Commands

```bash
python3 scripts/scan.py              # full report → out/scan-latest.json
python3 scripts/triage_queue.py      # verdict-sorted queue from latest report
python3 scripts/scan.py --skip-hygiene
python3 scripts/scan.py --repos irr,fwlive
```

## Layout

| Path | Role |
|------|------|
| `config.toml` | owner, gitroot, pipeline labels, `active_forks` |
| `scripts/scan.py` | owner-wide scan |
| `scripts/triage_queue.py` | queue printer |
| `scripts/hygiene_verdicts.py` | park / tier2 / active_fork / ship_only |
| `templates/` | security-only Dependabot, dependency-review |
| `.cursor/skills/housekeeping/` | Cursor skill |

## CLAUDE.md vs AGENTS.md

- **`AGENTS.md`** (this file) — shared agent instructions (Cursor and others).
- **`CLAUDE.md`** — Claude Code looks for this name; keep it a short pointer to
  `AGENTS.md`, not a full duplicate. Do not symlink unless you intentionally want
  one file for both tools; a thin `CLAUDE.md` is clearer when Claude-specific
  notes appear later.
