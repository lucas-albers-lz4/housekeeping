# Claude Code — housekeeping

Follow [`AGENTS.md`](AGENTS.md) for all cross-repo hygiene rules (including
**Owner scope**). This file is only the Claude Code entrypoint.

## Claude-specific notes

- Prefer `python3 scripts/scan.py` / `triage_queue.py` over ad-hoc API loops.
- Before editing another repo under `gitroot`, use `move_agent_to_root` into
  that checkout.
- Target only `config.toml` `owner` — never third-party repos outside that
  owner. Forks of this toolkit keep the same default.
- Do not close or “clean up” pipeline-labeled issues/PRs
  (`pipeline_repos` / `pipeline_labels`).
- Hygiene findings ≠ CVE debt. Use `templates/` for Dependabot baselines;
  bump Node-20-runtime action majors when `node20_action_runtime` fires.
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
Cursor always-on rule: `.cursor/rules/owner-scope.mdc`.
