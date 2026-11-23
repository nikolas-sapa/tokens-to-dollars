#!/usr/bin/env bash
# install.sh — copy skills/* into detected agent-harness skill dirs.
#
#   ./install.sh                  install all skills into every detected harness
#   ./install.sh --only claude    install into one harness only
#   ./install.sh --list           show harnesses, target dirs, detected status
#   ./install.sh --dry-run        print what would happen, change nothing
#
# Skills are directory-scoped: each skills/<name>/ (SKILL.md + references)
# is copied as a unit to <harness skills dir>/<name>/.
# Replacing an existing skill dir goes through `trash` (macOS Trash).
# If no trash command exists, that dir is skipped with a warning.
# Nothing is ever removed with rm/rmdir.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SKILLS_DIR="$ROOT/skills"

# harness|detect_dir|skills_target  (one row per installable target;
# a harness may have several rows, e.g. user-level + project-level)
TARGETS=(
  "claude|$HOME/.claude|$HOME/.claude/skills"
  "claude|$PWD/.claude|$PWD/.claude/skills"
  "codex|$HOME/.codex|$HOME/.agents/skills"
  "cursor|$HOME/.cursor|$HOME/.cursor/skills"
  "gemini|$HOME/.gemini|$HOME/.gemini/skills"
  "devin|$HOME/.config/devin|$HOME/.config/devin/skills"
  "windsurf|$HOME/.codeium|$HOME/.codeium/windsurf/skills"
  "kiro|$HOME/.kiro|$HOME/.kiro/skills"
  "opencode|$HOME/.config/opencode|$HOME/.config/opencode/skills"
  "factory|$HOME/.factory|$HOME/.factory/skills"
  "amp|$HOME/.config/amp|$HOME/.config/amp/skills"
)
HARNESSES="claude codex cursor gemini devin windsurf kiro opencode factory amp"

ONLY=""
DRY=0
LIST=0
while [ $# -gt 0 ]; do
  case "$1" in
    --only)
      ONLY="${2:?--only needs a harness name ($HARNESSES)}"
      shift 2 ;;
    --list)    LIST=1; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "unknown flag '$1' (want: --only <harness> | --list | --dry-run)" >&2; exit 2 ;;
  esac
done

if [ -n "$ONLY" ]; then
  case " $HARNESSES " in
    *" $ONLY "*) ;;
    *) echo "unknown harness '$ONLY' (want: $HARNESSES)" >&2; exit 2 ;;
  esac
fi

TRASH=""
for c in trash safe-trash /usr/bin/trash; do
  if command -v "$c" >/dev/null 2>&1; then TRASH="$c"; break; fi
done

if [ "$LIST" = 1 ]; then
  printf '%-12s %-44s %s\n' "harness" "skills dir" "status"
  seen="|"
  for row in "${TARGETS[@]}"; do
    IFS='|' read -r name detect dest <<< "$row"
    [ -n "$ONLY" ] && [ "$name" != "$ONLY" ] && continue
    case "$seen" in *"|$dest|"*) continue ;; esac
    seen="$seen$dest|"
    if [ -d "$detect" ]; then status="detected"; else status="not found ($detect)"; fi
    printf '%-12s %-44s %s\n' "$name" "$dest" "$status"
  done
  exit 0
fi

installed=()
skipped=()

install_into() {
  local dest_root="$1" label="$2"
  local src name dest
  for src in "$SKILLS_DIR"/*/; do
    name="$(basename "$src")"
    dest="$dest_root/$name"
    if [ "$DRY" = 1 ]; then
      if [ -e "$dest" ]; then
        if [ -n "$TRASH" ]; then
          echo "would trash existing $dest (via $TRASH), then copy"
        else
          echo "would SKIP $dest (exists, no trash command on PATH)"
        fi
      else
        echo "would copy skills/$name -> $dest"
      fi
      continue
    fi
    if [ -e "$dest" ]; then
      if [ -n "$TRASH" ]; then
        "$TRASH" "$dest"
      else
        echo "skip: $dest exists and no trash command found; move it aside manually" >&2
        skipped+=("$label: $name")
        continue
      fi
    fi
    mkdir -p "$dest_root"
    cp -R "$src" "$dest"
    installed+=("$label: $name -> $dest")
  done
}

matched=0
seen="|"
for row in "${TARGETS[@]}"; do
  IFS='|' read -r name detect dest <<< "$row"
  [ -n "$ONLY" ] && [ "$name" != "$ONLY" ] && continue
  matched=1
  # dedupe rows that resolve to the same skills dir (e.g. run from $HOME)
  case "$seen" in *"|$dest|"*) continue ;; esac
  [ -d "$detect" ] || { echo "skip: $name not detected ($detect missing)"; continue; }
  seen="$seen$dest|"
  install_into "$dest" "$name"
done

if [ "$matched" = 0 ]; then
  echo "unreachable: --only validation should have caught this" >&2; exit 2
fi

if [ "$DRY" = 1 ]; then
  echo "dry run: nothing changed"
  exit 0
fi

if [ ${#installed[@]} -eq 0 ]; then
  echo "nothing installed. Either no harness was detected, or every target was skipped."
  echo "manual fallback: cp -R skills/<name> <your harness skills dir>/   (see docs/install-matrix.md)"
  [ ${#skipped[@]} -gt 0 ] && exit 1
  exit 1
fi
printf 'installed: %s\n' "${installed[@]}"
[ ${#skipped[@]} -gt 0 ] && printf 'skipped: %s\n' "${skipped[@]}"
exit 0
