# Claude Code — housekeeping

Follow [`AGENTS.md`](AGENTS.md) for all cross-repo hygiene rules. This file is only
the Claude Code entrypoint (same pattern as `sre-ai-llm-work`).

## Claude-specific notes

- Prefer `python3 scripts/scan.py` / `triage_queue.py` over ad-hoc API loops.
- Before editing another repo under `~/gitroot`, use `move_agent_to_root` into
  that checkout.
- Do not close or “clean up” labeled `sre-ai-llm-work` pipeline issues/PRs.
- Hygiene findings ≠ CVE debt. Use `templates/` for Dependabot baselines.
- Forks listed in `config.toml` `active_forks` are maintained — fix them; other
  forks default to park.
- Archived repos: park PRs/issues/alerts — do not treat as cleanup debt.

## Quick commands

```bash
python3 scripts/scan.py
python3 scripts/triage_queue.py
python3 scripts/scan.py --repos fwlive,irr --skip-local
```

Skill details: `.cursor/skills/housekeeping/SKILL.md` and `reference.md`.
