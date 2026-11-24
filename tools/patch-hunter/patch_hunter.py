#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

UA = "tokens-to-dollars-patch-hunter/0.1 (diff-seeded variant analysis)"
GIT_TIMEOUT = 120
CLONE_TIMEOUT = 600
MAX_TERM_LEN = 48
STORED_LINE_CAP = 80          # per hunk, added/removed each
DEFAULT_MAX_FILE_KB = 2048
SEEN_CAP = 500

# watch keyword gate — a fix commit announces itself in the subject/body;
# each hit becomes a kind:patch-seed trigger line for the orchestrator.
SECURITY_RE = re.compile(r"\b(fix|security|cve|overflow|bounds?|auth)\b", re.I)

DIFF_GIT_RE = re.compile(r"^diff --git a/(.+) b/(.+)$")
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@\s?(.*)$")
CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
IF_RE = re.compile(r"\bif\s*\(([^)]*)\)")
IDENT_RE = re.compile(r"\b[A-Za-z_]\w*\b")

KEYWORDS = {
    "if", "for", "while", "switch", "return", "sizeof", "defined", "catch",
    "do", "else", "case", "typeof", "alignof", "new", "delete", "and", "or",
    "not", "noexcept", "requires", "static_cast", "dynamic_cast", "true",
    "false", "none", "null", "goto", "typedef",
}
# directories never walked by variants (.git is the important one; the rest
# are checkout noise). vendor trees are NOT skipped — copied code is where
# CopyFail siblings live.
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__",
             ".tox", ".venv", "dist", "build"}

# Bug-class heuristic: keyword patterns (matched against message + patch
# lines) plus delta-shape boosts (what kind of line the fix ADDED).
CLASS_PATTERNS = {
    "bounds": [r"out[- ]of[- ]bounds", r"\bbounds?\b", r"\boob\b",
               r"off[- ]by[- ]one", r"\boverrun\b", r"index.*out",
               r"over[- ]?read", r"\bunderflow\b"],
    "null-deref": [r"null[- ]?(ptr|deref|pointer)", r"\bnull\b",
                   r"nullptr", r"\bis_err\b", r"dereferenc"],
    "uaf": [r"use[- ]after[- ]free", r"\buaf\b", r"\bk?free\b",
            r"\brefcount\b", r"dangling", r"use[- ]after[- ]return",
            r"double[- ]free"],
    "overflow": [r"overflow", r"wraparound", r"truncat",
                 r"\bmemcpy\b", r"\bmemmove\b", r"\bstrcpy\b",
                 r"\bstrcat\b", r"\bsprintf\b", r"\bsnprintf\b"],
    "injection": [r"inject", r"sanitiz", r"\bescap", r"\beval\b",
                  r"format[- ]string", r"(path|dir)[- ]traversal",
                  r"\bxss\b", r"\bsql\b", r"\bpopen\b", r"\bsystem\s*\("],
    "auth": [r"\bauth\w*", r"permission", r"privilege", r"capabilit",
             r"access[- ]control", r"\bbypass\b", r"\bcsrf\b",
             r"credential", r"\bacl\b"],
}
CLASS_RES = {k: [re.compile(p, re.I) for p in pats]
             for k, pats in CLASS_PATTERNS.items()}
# delta-shape signals: regexes applied to ADDED lines only
SHAPE_SIGNALS = [
    ("null-deref", re.compile(
        r"\bif\s*\([^)]*(!\s*\w|==\s*(NULL|nullptr|0)|!=\s*(NULL|nullptr))",
        re.I), 2),
    ("bounds", re.compile(
        r"\bif\s*\([^)]*\b(len|size|count|index|idx|off|offset|end|max|num|nr)\w*\b"
        r"[^)]*(>=|<=|>|<|==|!=)", re.I), 2),
    ("uaf", re.compile(
        r"\b(k?free|kfree_?\w*|release|_put|put_device|refcount_(dec|inc)|dec_ref)\s*\(",
        re.I), 2),
    ("overflow", re.compile(
        r"check_(add|mul)_overflow|array_size|struct_size|\boverflow\b", re.I), 3),
    ("injection", re.compile(
        r"sanitiz|escape|quote|validate|\bfilter\b", re.I), 2),
    ("auth", re.compile(
        r"capable\s*\(|ns_capable|access_ok|has_perm|may_\w+|can_access|"
        r"->\s*(uid|gid|cap)\b", re.I), 2),
]


def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def repo_host(url):
    """Host of a git remote: https://host/org/repo or git@host:org/repo."""
    url = (url or "").strip()
    m = re.match(r"^[\w.-]+@([\w.-]+):", url)
    if m:
        return m.group(1).lower()
    return (urlparse(url).hostname or "").lower()


def host_allowed(url, allowed):
    """Exact host match only — authorization names assets, never propagates."""
    return repo_host(url) in {h.lower().lstrip(".") for h in allowed}


def is_url(repo):
    return bool(re.match(r"^[a-z]+://", repo or "", re.I)
                or re.match(r"^[\w.-]+@[\w.-]+:", repo or ""))


def git(repo, *args, check=True, timeout=GIT_TIMEOUT):
    r = subprocess.run(["git", "-C", str(repo)] + list(args),
                       capture_output=True, text=True, timeout=timeout)
    if check and r.returncode:
        raise RuntimeError("git %s: %s" % (args[0], r.stderr.strip()[:300]))
    return r.stdout


def git_run(*args, check=True, timeout=CLONE_TIMEOUT):
    r = subprocess.run(["git"] + list(args),
                       capture_output=True, text=True, timeout=timeout)
    if check and r.returncode:
        raise RuntimeError("git %s: %s" % (args[0], r.stderr.strip()[:300]))
    return r.stdout


def require_git():
    try:
        git_run("--version", timeout=15)
    except (OSError, subprocess.SubprocessError) as e:
        sys.exit("error: git is required (subprocess only): %s" % e)


def emit_trigger(tdir, rec):
    """Append one trigger line to triggers.jsonl; ts is stamped here so every
    producer emits the same {kind, url, signal, ts} envelope."""
    rec = dict(rec)
    rec["ts"] = utcnow()
    Path(tdir).mkdir(parents=True, exist_ok=True)
    with (Path(tdir) / "triggers.jsonl").open("a") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")
    return rec


# --- diff parsing ------------------------------------------------------------

def parse_patch(text):
    files, cur, hunk = [], None, None
    for line in text.splitlines():
        m = DIFF_GIT_RE.match(line)
        if m:
            cur = {"old_path": m.group(1), "path": m.group(2),
                   "status": "modified", "adds": 0, "dels": 0, "hunks": []}
            files.append(cur)
            hunk = None
            continue
        if cur is None:
            continue
        if line.startswith("new file mode"):
            cur["status"] = "added"
            continue
        if line.startswith("deleted file mode"):
            cur["status"] = "deleted"
            continue
        if line.startswith("rename from "):
            cur["status"] = "renamed"
            cur["old_path"] = line[len("rename from "):].strip()
            continue
        if line.startswith("rename to "):
            cur["status"] = "renamed"
            cur["path"] = line[len("rename to "):].strip()
            continue
        if line.startswith("--- "):
            if line[4:].strip() == "/dev/null":
                cur["status"] = "added"
            continue
        if line.startswith("+++ "):
            p = line[4:].strip()
            if p == "/dev/null":
                cur["status"] = "deleted"
            else:
                cur["path"] = p[2:] if p.startswith("b/") else p
            continue
        m = HUNK_RE.match(line)
        if m:
            hunk = {"header": line, "context": m.group(1),
                    "added": [], "removed": [], "context_lines": []}
            cur["hunks"].append(hunk)
            continue
        if hunk is None or line.startswith("\\"):
            continue
        if line.startswith("-"):
            cur["dels"] += 1
            hunk["removed"].append(line[1:])
        elif line.startswith("+"):
            cur["adds"] += 1
            hunk["added"].append(line[1:])
        elif line.startswith(" "):
            # untouched call sites around the fix are part of the pre-patch
            # pattern — the misused API usually survives on context lines
            hunk["context_lines"].append(line[1:])
    for f in files:
        for h in f["hunks"]:
            h["added"] = h["added"][:STORED_LINE_CAP]
            h["removed"] = h["removed"][:STORED_LINE_CAP]
            h["context_lines"] = h["context_lines"][:STORED_LINE_CAP]
    return files


def context_func(ctx):
    names = [n for n in CALL_RE.findall(ctx or "")
             if n.lower() not in KEYWORDS and len(n) > 2]
    return names[-1] if names else None


def calls_in(lines):
    out = set()
    for l in lines:
        for n in CALL_RE.findall(l):
            if n.lower() not in KEYWORDS and 2 < len(n) <= MAX_TERM_LEN:
                out.add(n)
    return out


def guard_terms(added_lines):
    """Identifiers inside newly-added if-conditions — the fix's guard shape.
    A sibling site lacking these nearby is a pre-patch-shape candidate."""
    terms = set()
    for l in added_lines:
        m = IF_RE.search(l)
        if not m:
            continue
        for t in IDENT_RE.findall(m.group(1)):
            if t.lower() not in KEYWORDS and len(t) > 1:
                terms.add(t)
    return sorted(terms)


def classify_bug(subject, body, files):
    """Keyword patterns over message (w3), added (w1), removed (w1), plus
    delta-shape boosts for the kind of guard the patch introduced."""
    scores = {k: 0 for k in CLASS_RES}
    evidence = []
    msg = (subject or "") + "\n" + (body or "")
    added = [l for f in files for h in f["hunks"] for l in h["added"]]
    removed = [l for f in files for h in f["hunks"] for l in h["removed"]]
    for cls, res in CLASS_RES.items():
        for rx in res:
            if rx.search(msg):
                scores[cls] += 3
                evidence.append("%s:/%s/@msg" % (cls, rx.pattern))
            if any(rx.search(l) for l in added):
                scores[cls] += 1
                evidence.append("%s:/%s/@added" % (cls, rx.pattern))
            if any(rx.search(l) for l in removed):
                scores[cls] += 1
                evidence.append("%s:/%s/@removed" % (cls, rx.pattern))
    for cls, rx, w in SHAPE_SIGNALS:
        if any(rx.search(l) for l in added):
            scores[cls] += w
            evidence.append("%s:shape:%s" % (cls, rx.pattern[:60]))
    best = max(scores, key=lambda k: (scores[k], -list(scores).index(k)))
    return {"class": best if scores[best] > 0 else "unknown",
            "scores": scores,
            "evidence": sorted(set(evidence))[:40]}


def commit_meta(work, sha):
    out = git(work, "show", "-s", "--format=%H%x1f%P%x1f%an%x1f%aI%x1f%s%x1f%b",
              sha)
    parts = out.split("\x1f", 5)
    parts += [""] * (6 - len(parts))
    return {"sha": parts[0].strip(),
            "parents": parts[1].split(),
            "author": parts[2].strip(),
            "date": parts[3].strip(),
            "subject": parts[4].strip(),
            "body": parts[5].strip()[:2000]}


def diff_for_commit(work, commit):
    if ".." in commit:
        a, b = commit.split("..", 1)
        b = b or "HEAD"
        patch = git(work, "diff", a.strip(), b.strip())
        return patch, b.strip(), {"a": a.strip(), "b": b.strip()}
    patch = git(work, "show", "--format=", "--patch", commit)
    meta_sha = commit
    if not patch.strip():
        # merge commit or diffless rev: diff against first parent
        parents = git(work, "rev-list", "--parents", "-n", "1",
                      commit).split()
        if len(parents) > 1:
            patch = git(work, "diff", parents[1], parents[0])
            meta_sha = parents[0]
    return patch, meta_sha, None


def clone_dest(clone_dir, url):
    name = re.sub(r"[^a-z0-9]+", "-",
                  (urlparse(url).path or url).lower()).strip("-")
    name = name[:60] or "repo"
    key = hashlib.sha256(url.encode()).hexdigest()[:8]
    return Path(clone_dir) / ("%s-%s" % (name, key))


def resolve_repo(a):
    """Return (work_path, remote_url_or_None). Remote --repo values are cloned
    under --clone-dir; the remote host must be in --only-host (no allowlist,
    no traffic)."""
    if not is_url(a.repo):
        p = Path(a.repo)
        if not (p / ".git").exists():
            sys.exit("error: not a git repo: %s" % a.repo)
        return p, None
    allowed = set(a.only_host or [])
    if not host_allowed(a.repo, allowed):
        sys.exit("error: remote repo host %s not in --only-host allowlist"
                 % (repo_host(a.repo) or a.repo))
    if not a.clone_dir:
        sys.exit("error: --clone-dir is required when --repo is a URL")
    dest = clone_dest(a.clone_dir, a.repo)
    if not (dest / ".git").exists():
        Path(a.clone_dir).mkdir(parents=True, exist_ok=True)
        git_run("clone", "--quiet", a.repo, str(dest))
    return dest, a.repo


def do_seed(a):
    require_git()
    work, remote = resolve_repo(a)
    patch, meta_sha, rng = diff_for_commit(work, a.commit)
    if not patch.strip():
        sys.exit("error: no diff for %s (merge? root commit?)" % a.commit)
    meta = commit_meta(work, meta_sha)
    files = parse_patch(patch)
    added = [l for f in files for h in f["hunks"] for l in h["added"]]
    removed = [l for f in files for h in f["hunks"] for l in h["removed"]]
    ctx = [l for f in files for h in f["hunks"] for l in h["context_lines"]]
    funcs = []
    for f in files:
        for h in f["hunks"]:
            fn = context_func(h["context"])
            if fn and fn not in funcs:
                funcs.append(fn)
    r_calls, a_calls, c_calls = (calls_in(removed), calls_in(added),
                               calls_in(ctx))
    guards = guard_terms(added)
    bug = classify_bug(meta["subject"], meta["body"], files)
    keywords = sorted({m.lower() for m in
                       SECURITY_RE.findall(meta["subject"] + "\n" + meta["body"])})
    siblings = [{"kind": "same-file", "path": f["path"]} for f in files]
    siblings += [{"kind": "caller-of", "term": fn} for fn in funcs]
    siblings += [{"kind": "api-user", "term": c}
                 for c in sorted(r_calls | c_calls)]
    if guards:
        siblings.append({"kind": "missing-guard", "terms": guards})
    seed = {
        "tool": "patch-hunter", "version": "0.1", "generated_at": utcnow(),
        "repo": {"input": a.repo, "work_path": str(work), "remote": remote},
        "commit": meta, "range": rng,
        "files": files,
        "changed_functions": funcs,
        "calls": {"removed": sorted(r_calls), "added": sorted(a_calls),
                  "context": sorted(c_calls)},
        "added_guard_terms": guards,
        "bug_class": bug,
        "patch_keywords": keywords,
        "sibling_candidates": siblings,
    }
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(seed, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"ok": True, "seed": str(out), "commit": meta["sha"][:12],
                      "bug_class": bug["class"], "files": len(files),
                      "changed_functions": funcs,
                      "sibling_candidates": len(siblings)}, indent=2))
    return 0


# --- variants ----------------------------------------------------------------

def iter_text_files(root, max_kb):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            try:
                if p.stat().st_size > max_kb * 1024:
                    continue
                with p.open("rb") as f:
                    head = f.read(8192)
                if b"\x00" in head:
                    continue
                yield p
            except OSError:
                continue


def do_variants(a):
    require_git()
    seed = json.loads(Path(a.seed).read_text())
    work = Path(a.repo or seed["repo"]["work_path"])
    if not work.is_dir():
        sys.exit("error: repo path not found: %s" % work)
    changed = {f["path"] for f in seed.get("files", [])}
    calls = seed.get("calls") or {}
    terms = sorted(set(seed.get("changed_functions", []))
                   | set(calls.get("removed", []))
                   | set(calls.get("context", [])))
    terms = [t for t in terms if 2 < len(t) <= MAX_TERM_LEN]
    if not terms:
        sys.exit("error: seed has no search terms "
                 "(changed_functions + removed calls are empty)")
    guards = set(seed.get("added_guard_terms", []))
    term_re = re.compile(r"\b(%s)\b" % "|".join(re.escape(t) for t in terms))
    # the guard is an if-condition: a term used in the call args themselves
    # (e.g. `len`) only counts when it appears inside `if (...)` nearby
    guard_re = (re.compile(r"\bif\s*\([^)]*\b(%s)\b"
                           % "|".join(re.escape(g) for g in guards))
                if guards else None)
    window = a.window
    hits, scanned = [], 0
    for p in iter_text_files(work, a.max_file_kb):
        scanned += 1
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        rel = str(p.relative_to(work)) if p.is_relative_to(work) else str(p)
        for i, line in enumerate(lines):
            for m in term_re.finditer(line):
                lo, hi = max(0, i - window), min(len(lines), i + window + 1)
                near = "\n".join(lines[lo:hi])
                guarded = bool(guard_re and guard_re.search(near))
                hits.append({
                    "path": rel, "line": i + 1, "term": m.group(1),
                    "shape": "guarded-callsite" if guarded else "pre-patch-shape",
                    "candidate": ("same-file" if rel in changed else "api-user"),
                    "context": line.strip()[:200],
                    "bug_class": seed["bug_class"]["class"],
                    "commit": seed["commit"]["sha"][:12],
                })
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        for h in hits:
            f.write(json.dumps(h, sort_keys=True) + "\n")
    pre = sum(1 for h in hits if h["shape"] == "pre-patch-shape")
    print(json.dumps({"ok": True, "variants": str(out),
                      "files_scanned": scanned, "hits": len(hits),
                      "pre_patch_shape": pre, "guarded": len(hits) - pre,
                      "terms": terms, "guard_terms": sorted(guards)},
                     indent=2))
    return 0


# --- watch -------------------------------------------------------------------

def watch_key(entry):
    return hashlib.sha256((entry.get("url") or entry.get("path") or
                           "?").encode()).hexdigest()[:16]


def load_watch_state(tdir):
    p = Path(tdir) / "state.json"
    return json.loads(p.read_text()) if p.is_file() else {"repos": {}}


def save_watch_state(tdir, st):
    Path(tdir).mkdir(parents=True, exist_ok=True)
    (Path(tdir) / "state.json").write_text(
        json.dumps(st, indent=2, sort_keys=True) + "\n")


def new_commits(work, ref, prev_tip, lookback):
    """Shas newest->oldest to examine. prev_tip -> rev-list tip..ref; missing
    prev tip -> baseline, last `lookback` commits only."""
    revs = git(work, "rev-list", ref, "-n", "200").split()
    if prev_tip and prev_tip in revs:
        return revs[:revs.index(prev_tip)], False
    if prev_tip:
        # history rewound or tip fell off the window: trust seen-set, cap 50
        return revs[:50], True
    return (revs[:max(lookback, 0)] if lookback else []), False


def do_watch(a):
    require_git()
    manifest = json.loads(Path(a.manifest).read_text())
    tdir = Path(manifest.get("target")
                or Path(a.manifest).parent / "patch-hunter-state")
    clone_dir = Path(manifest.get("clone_dir") or tdir / "clones")
    allowed = {h.lower() for h in (manifest.get("only_hosts") or [])}
    allowed |= {h.lower() for h in (a.only_host or [])}
    st = load_watch_state(tdir)
    results, errors, n_triggers = {}, {}, 0
    for entry in manifest.get("repos") or []:
        url, path, ref = entry.get("url"), entry.get("path"), \
            entry.get("ref") or "HEAD"
        key = watch_key(entry)
        rec = st["repos"].setdefault(key, {"seen": []})
        try:
            work = Path(path) if path else clone_dest(clone_dir, url or "?")
            if not (work / ".git").exists():
                if not url:
                    raise RuntimeError("no url and not a git repo: %s" % work)
                if not host_allowed(url, allowed):
                    raise RuntimeError("host %s not allowlisted "
                                       "(manifest.only_hosts / --only-host)"
                                       % repo_host(url))
                clone_dir.mkdir(parents=True, exist_ok=True)
                git_run("clone", "--quiet", url, str(work))
            elif a.fetch and url:
                if not host_allowed(url, allowed):
                    raise RuntimeError("fetch refused: host %s not allowlisted"
                                       % repo_host(url))
                git(work, "fetch", "--quiet", "origin")
            head = git(work, "rev-parse", "--verify", ref).strip()
            revs, rewound = new_commits(work, ref, rec.get("tip"), a.lookback)
            seen = set(rec.get("seen") or [])
            fired = []
            for sha in reversed(revs):          # oldest first
                if sha in seen:
                    continue
                seen.add(sha)
                meta = commit_meta(work, sha)
                kws = sorted({m.lower() for m in SECURITY_RE.findall(
                    meta["subject"] + "\n" + meta["body"])})
                if not kws:
                    continue
                emit_trigger(tdir, {
                    "kind": "patch-seed",
                    "url": url or str(work),
                    "signal": ["keyword:" + k for k in kws],
                    "commit": sha, "subject": meta["subject"][:160],
                    "path": str(work), "ref": ref})
                fired.append(sha[:12])
                n_triggers += 1
            rec.update({"url": url, "path": str(work), "tip": head,
                        "seen": sorted(seen)[-SEEN_CAP:],
                        "last_checked": utcnow()})
            results[key] = {"url": url or str(work), "new": len(revs),
                            "seeds": fired, "tip": head[:12],
                            "history_rewound": rewound}
        except Exception as e:
            errors[key] = {"url": url or str(path), "error": str(e)[:300]}
    st["last_run"] = utcnow()
    save_watch_state(tdir, st)
    print(json.dumps({"target": str(tdir), "run": st["last_run"],
                      "repos": len(results) + len(errors),
                      "triggers": n_triggers,
                      "results": results, "errors": errors}, indent=2))
    # per-repo errors land in the summary's errors block — never fatal
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Diff-seeded variant analysis: every security fix commit "
                    "is a hunt seed (PatchSlop / CopyFail). seed parses a fix "
                    "diff, variants grep-hunts unpatched siblings, watch polls "
                    "repos for new fix commits and emits patch-seed triggers.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("seed", help="parse a fix commit diff -> seed.json")
    p.add_argument("--repo", required=True,
                   help="local repo path, or remote URL (needs --clone-dir + "
                        "--only-host)")
    p.add_argument("--commit", required=True,
                   help="fix commit sha, or a..b range (diff a b)")
    p.add_argument("--out", default="seed.json", help="seed.json output path")
    p.add_argument("--clone-dir", help="where URL repos get cloned")
    p.add_argument("--only-host", action="append", metavar="HOST",
                   help="exact git host allowed; repeatable. Required for "
                        "remote --repo — no allowlist, no traffic")

    p = sub.add_parser("variants", help="grep-grade sibling hunt -> JSONL")
    p.add_argument("--seed", required=True, help="seed.json from `seed`")
    p.add_argument("--repo", help="repo path (default: seed's work_path)")
    p.add_argument("--out", default="variants.jsonl", help="JSONL output path")
    p.add_argument("--max-file-kb", type=int, default=DEFAULT_MAX_FILE_KB)
    p.add_argument("--window", type=int, default=8,
                   help="lines around a callsite to look for the fix's guard")

    p = sub.add_parser("watch", help="poll repos for new fix commits -> "
                                     "kind:patch-seed triggers.jsonl lines")
    p.add_argument("manifest", help="watch manifest.json: {target, clone_dir?,"
                                    " only_hosts?, repos: [{url?, path?, ref?}]}")
    p.add_argument("--only-host", action="append", metavar="HOST",
                   help="extra allowed git hosts (manifest.only_hosts is the "
                        "persistent list); required for clone/fetch")
    p.add_argument("--fetch", action="store_true",
                   help="git fetch before polling (host-gated); without it "
                        "watch is fully offline on existing clones")
    p.add_argument("--lookback", type=int, default=0,
                   help="first run: scan last N commits instead of pure "
                        "baseline (default 0)")
    args = ap.parse_args()
    return {"seed": do_seed, "variants": do_variants,
            "watch": do_watch}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
