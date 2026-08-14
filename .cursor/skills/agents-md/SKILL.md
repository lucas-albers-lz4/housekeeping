---
name: agents-md
description: >-
  Audit AGENTS.md, CLAUDE.md, Cursor rules, and skills for named repos under
  the housekeeping owner. Use ONLY when the user explicitly asks to audit
  agent or instruction files for specific repo name(s). Never run during a
  default housekeeping scan, triage_queue.py, or an owner-wide pass.
---

# Instruction-surface audit (opt-in)

Housekeeping wrapper around the AGENTS.md authoring rubric in
[reference.md](reference.md). **Not part of `python3 scripts/scan.py`.**

## When to use

Only after the user names one or more repos (e.g. “audit AGENTS.md in fwlive”).
Do not inventory the owner’s fleet. Do not infer that a hygiene scan includes
this pass.

## Command

```bash
python3 scripts/audit_agents.py --repos fwlive
python3 scripts/audit_agents.py --repos fwlive,regexproof --save out/tmp-audit.json
```

`--repos` is required. Missing or empty list must fail. The script never lists
all owned repos as targets.

## Workflow

1. Confirm named repos are under `config.toml` `owner`. `--repos` narrows; it
   never expands outside `owner`.
2. Run `python3 scripts/audit_agents.py --repos <names>`. Read the JSON
   (inventory, fingerprint, mechanical notes, cached qualitative audit if
   fresh).
3. On a **cache hit**, present the stored score / keep / remove / draft. Do
   not re-read the files unless the user asks to refresh.
4. On a **cache miss**, read only the listed instruction files. Score with
   [reference.md](reference.md). Skills and Cursor rules are **not** scored
   with the brownfield ~20-line AGENTS.md budget (skills may be long; check
   frontmatter, triggers, and duplication of root AGENTS.md instead).
5. Repos in `[instruction_audit] long_form_repos` may keep a long root
   `AGENTS.md` (operator toolkit / the file is the product).
6. Suggest before editing. Wait. If approved, `move_agent_to_root` into that
   checkout under `gitroot` before any edit. Never merge without an explicit
   user ask.
7. Save the qualitative blob with `--save` so the next ask can skip re-analysis.

## Mechanical notes (script)

- **Absence of AGENTS.md is valid.** Never emit `agents_md_missing` as debt.
- `routing_gap`: rules or skills exist, but there is no root `AGENTS.md`
  pointer. List as suggest-only; never auto-write a stub.
- `claude_md_duplicate`: `CLAUDE.md` is a near-copy of `AGENTS.md` instead of
  a thin pointer.
- `agents_md_over_budget`: root `AGENTS.md` over 40 lines, unless the repo is
  in `long_form_repos`.

## Output

For the qualitative pass, follow the reference.md output contract (score,
keep, remove/compress, proposed draft). Do not dump drafts into `scan.py`
stdout or `scan-latest.json`.
