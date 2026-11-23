# Install matrix

Where each agent harness looks for skills, and how `./install.sh` reaches it.
The installer copies every `skills/<name>/` directory (SKILL.md plus its
`references/`) into the harness's skills dir as a directory-scoped unit —
nothing is symlinked, and an existing copy is replaced via `trash` (or
skipped with a warning if no trash command exists).

Detection means "the harness's config dir exists on this machine."
`./install.sh --list` shows this table live on your system.

| Harness | Skills dir | Detection | Notes |
|---|---|---|---|
| Claude Code | `~/.claude/skills/` — plus `./.claude/skills/` when a project `.claude/` exists | `~/.claude` | Native `SKILL.md` support. Project-local install scopes the skills to one repo. |
| Codex CLI | `~/.agents/skills/` | `~/.codex` | Skills live on the shared `~/.agents` path — `~/.codex` itself has no skills subdir; config and instructions live in `AGENTS.md`, which Codex auto-reads at repo root. |
| Cursor | `~/.cursor/skills/` | `~/.cursor` | `.cursor-plugin/plugin.json` also registers this repo as a plugin. |
| Gemini CLI | `~/.gemini/skills/` | `~/.gemini` | Also reads the shared `~/.agents/skills/` dir. `gemini-extension.json` registers this repo as an extension. |
| Devin | `~/.config/devin/skills/` | `~/.config/devin` | Auto-reads repo-root `AGENTS.md`, so a checkout alone already gives context. |
| Windsurf | `~/.codeium/windsurf/skills/` | `~/.codeium` | |
| Kiro | `~/.kiro/skills/` | `~/.kiro` | |
| OpenCode | `~/.config/opencode/skills/` | `~/.config/opencode` | |
| Factory | `~/.factory/skills/` | `~/.factory` | Factory's native format is flat `.md` files under `droids/` and `commands/` — verify your droid setup picks up directory skills. |
| Amp | `~/.config/amp/skills/` | `~/.config/amp` | Also reads `~/.agents/skills/` and `~/.claude/skills/` natively — a Claude or Codex install already covers Amp. |

Harnesses that auto-read `AGENTS.md` at repo root (Codex, Devin, Amp, and
most others above) get the repo contract for free on a checkout; the skills
dirs are what make the `SKILL.md` playbooks invocable.

Not covered by `install.sh`:

- **Aider** — no directory-skills concept; it reads flat files listed under
  `read:` in `~/.aider.conf.yml`.
- Any harness not in the table — manual fallback:
  `cp -R skills/<name> <your harness skills dir>/`.

## skillswitch (optional companion)

[skillswitch](https://github.com/nikolas-sapa/skillswitch) manages, not
installs: once the skills are on disk, `npm i -g skillswitch` gives you one
CLI to scan, enable, and disable skill sets across Claude, Gemini, Codex,
Factory, Amp, and Aider. Its adapters are the source of truth for the paths
above.
