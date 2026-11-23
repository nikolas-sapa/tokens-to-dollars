#!/usr/bin/env python3
"""Strict evidence manifest writer/verifier for evidence/<finding-id>/ dirs.

Ported from clone-attack-security/clone_security/evidence.py (strict JSON
parser: 16KB cap, strict UTF-8, duplicate-key rejection, parse_constant
rejection, exact key-set match, sha256 bound at parse) and approval.py's
RunBinding (digest binding of every run field) adapted to this repo's
evidence dir layout: the manifest binds workspace/target/intent/rule/
verifier + timestamp + a sha256 for every captured file, and evidence.json
itself is digest-pinned by an evidence.sha256 sidecar.

Usage:
  store.py digest <file> [file...]   print sha256 for manifest authoring
  store.py write  <dir> < manifest   validate + write evidence.json/.sha256
  store.py verify <dir>              re-bind and check
Exit: 0 ok, 1 validation/verification failure, 2 usage/IO error.
"""
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path

_MAX_BYTES = 16384
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_FILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")  # no separators, no ".."
_HEX64_RE = re.compile(r"[0-9a-f]{64}")
_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"
_KEYS = frozenset({
    "schema_version", "finding_id", "workspace", "target", "intent",
    "rule", "verifier", "captured_at", "files",
})


class EvidenceError(ValueError):
    pass


def _object_no_dup(pairs):
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise EvidenceError("invalid evidence")
        seen.add(key)
    return dict(pairs)


def _reject_constant(value):
    raise EvidenceError("invalid evidence")


def _sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def _valid_id(v):
    return type(v) is str and _ID_RE.fullmatch(v) is not None


def _valid_ts(v):
    if type(v) is not str:
        return False
    try:
        return datetime.strptime(v, _TS_FMT).strftime(_TS_FMT) == v
    except ValueError:
        return False


def parse_manifest(raw):
    """Strict parse. Returns manifest dict; raises EvidenceError."""
    if type(raw) is not bytes or not (0 < len(raw) <= _MAX_BYTES):
        raise EvidenceError("manifest missing or >16KB")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise EvidenceError("manifest not strict UTF-8")
    try:
        obj = json.loads(text, object_pairs_hook=_object_no_dup,
                         parse_constant=_reject_constant)
    except EvidenceError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError):
        raise EvidenceError("manifest not valid strict JSON")
    if type(obj) is not dict or set(obj.keys()) != _KEYS:
        raise EvidenceError("manifest keys != %s" % sorted(_KEYS))
    if type(obj["schema_version"]) is not int or obj["schema_version"] != 1:
        raise EvidenceError("schema_version must be 1")
    for k in ("finding_id", "workspace", "target", "intent", "rule",
              "verifier"):
        if not _valid_id(obj[k]):
            raise EvidenceError("%s fails id grammar" % k)
    if not _valid_ts(obj["captured_at"]):
        raise EvidenceError("captured_at must be UTC YYYY-MM-DDTHH:MM:SSZ")
    files = obj["files"]
    if type(files) is not dict or not files:
        raise EvidenceError("files must be a non-empty map")
    for name, digest in files.items():
        if _FILE_RE.fullmatch(name) is None:
            raise EvidenceError("unsafe filename in files: %r" % name)
        if type(digest) is not str or _HEX64_RE.fullmatch(digest) is None:
            raise EvidenceError("bad sha256 for %r" % name)
    return obj


def _check_files(man, d):
    """Re-hash every bound file. Returns list of (name, ok, detail)."""
    out = []
    for name, want in sorted(man["files"].items()):
        p = d / name
        if not p.is_file():
            out.append((name, False, "missing"))
            continue
        got = _sha256(p.read_bytes())
        out.append((name, got == want,
                    "ok" if got == want else "digest %s != %s" % (got, want)))
    return out


def cmd_digest(paths):
    for p in paths:
        fp = Path(p)
        if not fp.is_file():
            print("error: not a file: %s" % p, file=sys.stderr)
            return 2
        print("%s  %s" % (_sha256(fp.read_bytes()), fp.name))
    return 0


def cmd_write(d):
    d = Path(d).resolve()
    if not d.is_dir():
        print("error: not a directory: %s" % d, file=sys.stderr)
        return 2
    ev = d / "evidence.json"
    if ev.exists():
        print("error: %s exists — evidence is append-once" % ev,
              file=sys.stderr)
        return 1
    raw = sys.stdin.buffer.read()
    try:
        man = parse_manifest(raw)
    except EvidenceError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    if man["finding_id"] != d.name:
        print("error: finding_id %r != dir name %r" % (man["finding_id"], d.name),
              file=sys.stderr)
        return 1
    checks = _check_files(man, d)
    for name, ok, detail in checks:
        if not ok:
            print("error: %s: %s" % (name, detail), file=sys.stderr)
            return 1
    ev.write_bytes(raw)
    digest = _sha256(raw)
    (d / "evidence.sha256").write_text("%s  evidence.json\n" % digest)
    print(json.dumps({"ok": True, "finding_id": man["finding_id"],
                      "files": len(man["files"]),
                      "evidence_digest": digest}))
    return 0


def cmd_verify(d):
    d = Path(d).resolve()
    ev, side = d / "evidence.json", d / "evidence.sha256"
    if not d.is_dir() or not ev.is_file() or not side.is_file():
        print("error: need <dir>/evidence.json + evidence.sha256",
              file=sys.stderr)
        return 2
    raw = ev.read_bytes()
    checks = []
    parts = side.read_text().split()
    stored = parts[0] if parts else ""
    checks.append(("sidecar-digest",
                   stored == _sha256(raw),
                   "%s vs %s" % (stored, _sha256(raw))))
    try:
        man = parse_manifest(raw)
        checks.append(("manifest-schema", True, "strict parse ok"))
    except EvidenceError as e:
        man = None
        checks.append(("manifest-schema", False, str(e)))
    if man:
        checks.append(("finding-id-binds-dir",
                       man["finding_id"] == d.name,
                       "%s vs %s" % (man["finding_id"], d.name)))
        checks.extend(("file:%s" % n, ok, det)
                      for n, ok, det in _check_files(man, d))
    ok = all(c[1] for c in checks)
    print(json.dumps({
        "ok": ok, "dir": str(d),
        "checks": [{"check": c, "ok": o, "detail": det}
                   for c, o, det in checks]}, indent=2))
    return 0 if ok else 1


def main():
    if len(sys.argv) < 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    cmd, rest = sys.argv[1], sys.argv[2:]
    if cmd == "digest" and rest:
        return cmd_digest(rest)
    if cmd == "write" and len(rest) == 1:
        return cmd_write(rest[0])
    if cmd == "verify" and len(rest) == 1:
        return cmd_verify(rest[0])
    print(__doc__.strip(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
