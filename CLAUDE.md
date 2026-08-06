# Claude Code — housekeeping

Follow [`AGENTS.md`](AGENTS.md) for all cross-repo hygiene rules (including
**Owner scope**). This file is only the Claude Code entrypoint. It does not
duplicate `AGENTS.md`.

## Claude-specific notes

- Prefer `python3 scripts/scan.py` / `triage_queue.py` over ad-hoc API loops.
- Before editing another repo under `gitroot`, use `move_agent_to_root` into
  that checkout.

Skill details: `.cursor/skills/housekeeping/SKILL.md` and `reference.md`.
Cursor always-on rule: `.cursor/rules/owner-scope.mdc`.
