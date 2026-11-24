#!/usr/bin/env python3
import argparse
import json
import shutil
import sys
from pathlib import Path

FILES = {
    "memory/lessons/platforms.md": """# lessons/platforms - cross-program platform lessons
# What yields and what burns per platform (HackerOne, Immunefi, Intigriti, VRPs, ...).
# Append-dominant: correct by striking through the old line, never silent edits.
""",
    "memory/lessons/engagement-types.md": """# lessons/engagement-types - what actually yields per engagement type
# Append-dominant: correct by striking through the old line, never silent edits.
""",
    "memory/lessons/technique-yield.md": """# lessons/technique-yield - yield ledger: playbook ids and check categories, ranked
# Recomputed from memory/ledger.md via tools/ledger/ledger.py; drives intent routing.
# Append-dominant: correct by striking through the old line, never silent edits.
""",
    "memory/engagements.md": """# engagements - index of closed engagements
# Row format: | date | host | type | outcome | memory-updated |

| date | host | type | outcome | memory-updated |
|------|------|------|---------|----------------|
""",
    "memory/ledger.md": """# ledger - append-only token spend + payout accounting (see skills/token-ledger)
# Intent rows: one per closed intent. est-$ bare = from real usage, 'e' suffix = estimated.
# Payout rows: one per finding status change. Never edit rows; corrections are new rows.

| date | program | intent-id | worker | model | in-tokens | out-tokens | est-$ | outcome | finding-id |
|------|---------|-----------|--------|-------|-----------|------------|-------|---------|------------|

| date | program | finding-id | status | amount |
|------|---------|------------|--------|--------|
""",
}

DIRS = ["memory/targets", "reports", "data", "knowledge"]

RECON_TOOLS = ("subfinder", "nuclei", "katana", "ffuf", "dnsx", "gau",
               "trufflehog")

# install spec per tool: brew formula on darwin, upstream go module as fallback
INSTALL = {
    "subfinder":  {"brew": "subfinder",
                   "go": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"},
    "nuclei":     {"brew": "nuclei",
                   "go": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"},
    "katana":     {"brew": "katana",
                   "go": "github.com/projectdiscovery/katana/cmd/katana"},
    "ffuf":       {"brew": "ffuf", "go": "github.com/ffuf/ffuf/v2"},
    "dnsx":       {"brew": "dnsx",
                   "go": "github.com/projectdiscovery/dnsx/cmd/dnsx"},
    "gau":        {"go": "github.com/lc/gau/v2/cmd/gau"},
    "trufflehog": {"brew": "trufflehog"},
}

BREW_ALL = "brew install subfinder nuclei httpx katana ffuf dnsx trufflehog"

CONFIG_FILE = Path.home() / ".config" / "tokens-to-dollars" / "config.json"

# optional keys `t2d setup` writes under config.env; key -> what it unlocks
OPTIONAL_KEYS = {
    "GITHUB_TOKEN": "radar/git extras + higher GitHub API limits",
    "SOLODIT_API_KEY": "live audit-findings corpus at solodit.xyz "
                       "(register -> settings -> API)",
}


def install_hint(tool):
    spec = INSTALL[tool]
    if sys.platform == "darwin" and "brew" in spec:
        hint = "brew install %s" % spec["brew"]
        if "go" in spec:
            hint += "  (or: go install %s@latest)" % spec["go"]
        return hint
    if "go" in spec:
        return "go install %s@latest" % spec["go"]
    if sys.platform.startswith("linux"):
        return ("brew install %s (linuxbrew) or release binary from "
                "github.com/trufflesecurity/trufflehog" % spec["brew"])
    return "see github.com/trufflesecurity/trufflehog releases"


def check_skeleton(root):
    missing = 0
    for rel in FILES:
        if (root / rel).is_file():
            print("ok       %s" % rel)
        else:
            print("missing  %s" % rel)
            missing += 1
    for rel in DIRS:
        if (root / rel).is_dir():
            print("ok       %s/" % rel)
        else:
            print("missing  %s/" % rel)
            missing += 1
    if missing:
        print("fix: run tools/bootstrap.py to create the skeleton")


def check_tools():
    missing = [t for t in RECON_TOOLS if shutil.which(t) is None]
    if not missing:
        print("ok       recon tools on PATH: %s" % ", ".join(RECON_TOOLS))
        return
    print("warning: recon tools not on PATH "
          "(tools/wrap shells out to these): %s" % ", ".join(missing))
    for t in missing:
        print("         %-10s %s" % (t, install_hint(t)))
    if sys.platform == "darwin":
        print("         install all: %s && go install %s@latest"
              % (BREW_ALL, INSTALL["gau"]["go"]))
    else:
        cmds = ["go install %s@latest" % INSTALL[t]["go"]
                for t in missing if "go" in INSTALL[t]]
        if cmds:
            print("         install all: %s" % " && ".join(cmds))


def check_config():
    present = set()
    if CONFIG_FILE.is_file():
        try:
            data = json.loads(CONFIG_FILE.read_text())
        except (OSError, ValueError):
            print("warning: %s unreadable or not json" % CONFIG_FILE)
            data = {}
        env = data.get("env")
        if isinstance(env, dict):
            present = {k for k, v in env.items() if v}
        present |= {k for k, v in data.items() if k in OPTIONAL_KEYS and v}
    for key, unlock in OPTIONAL_KEYS.items():
        if key not in present:
            print("missing  %s -> %s; set via `t2d setup` or add to %s"
                  % (key, unlock, CONFIG_FILE))


def main():
    ap = argparse.ArgumentParser(description="Create the gitignored local-state skeleton.")
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[1]),
                    help="repo root (default: parent of tools/)")
    ap.add_argument("--doctor", action="store_true",
                    help="check skeleton, tools, and config keys; create nothing")
    args = ap.parse_args()
    root = Path(args.root)

    if args.doctor:
        check_skeleton(root)
    else:
        for rel, content in FILES.items():
            p = root / rel
            if p.exists():
                print("skipped  %s (exists)" % rel)
                continue
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
            print("created  %s" % rel)
        for rel in DIRS:
            p = root / rel
            if p.exists():
                print("skipped  %s/ (exists)" % rel)
            else:
                p.mkdir(parents=True, exist_ok=True)
                print("created  %s/" % rel)
    check_tools()
    check_config()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
