#!/usr/bin/env python3
"""broker.py — session vault + token broker, the fleet's auth layer.

Design note. Workers never see secrets: a worker emits an *untagged*
request and the egress/injection proxy — the only component permitted
to run `token` — reads the live token here and stamps Authorization /
Cookie on the outbound request. Secrets therefore never enter model
context, worker env, tool argv, or logs. The vault file
(memory/sessions.json, inside the gitignored memory/ tree, mode 0600)
is the single material store; `creds_ref` names an env/keychain *key*,
never the value; this broker is the only reader.

  register --program X --auth-type cookie|bearer|jwt|basic
           [--token T | --creds-env ENV | --creds-ref env:E|keychain:S/A]
           [--account a|b] [--expires-at ISO | --ttl SECONDS]
           [--refresh-url U [--refresh-method M]] [--probe-url U]
           [--auth-endpoint U] [--totp-seed BASE32] [--max-failures N]
  token    --program X [--account a|b]      -> prints the live token
  inject   --program X --tool httpx [--account a|b]
                                            -> prints the stamped argv
                                               fragment (JSON list) for
                                               that tool's header flag
  refresh  --program X [--account a|b]      -> runs the refresh_url flow
  status   [--json]                         -> liveness probe per program
  expire-check --program X --status N [--location U] [--account a|b]
                                            -> 401/403/302-login hook
  totp     --program X                      -> current 6-digit TOTP code
  unpark   --program X                      -> reset the circuit breaker

`--account` may be spelled `--slot` on any verb that takes it. The
second slot (`b`) exists for IDOR work: two victims, two sessions, same
program — the proxy picks the slot per request.

Circuit breaker: `expire-check` and a rejected `refresh` count
consecutive auth failures per slot; at --max-failures (default 3) the
program is parked — `token` and `refresh` refuse until `unpark` or a
fresh `register`.

Exit codes: 0 ok · 2 usage · 3 unknown program/record · 4 expired or
auth-dead · 5 parked · 6 upstream/parse error.
"""
import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(os.environ.get(
    "T2D_ROOT") or Path(__file__).resolve().parent.parent.parent).resolve()
DEFAULT_VAULT = ROOT / "memory" / "sessions.json"

AUTH_TYPES = ("cookie", "bearer", "jwt", "basic")
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
DEFAULT_MAX_FAILURES = 3
DEFAULT_TIMEOUT = 20
TOKEN_JSON_KEYS = ("access_token", "id_token", "token", "session_token",
                   "session", "jwt")
# A redirect to any of these is a dead session, not content.
LOGIN_RE = re.compile(r"(?i)(login|signin|sign-in|log-?in|sso|oauth2?"
                      r"|session/new|forgot)")


def die(code, msg):
    print("broker: %s" % msg, file=sys.stderr)
    sys.exit(code)


def now():
    return datetime.now(timezone.utc)


def parse_iso(s):
    try:
        d = datetime.fromisoformat(str(s))
    except ValueError:
        d = datetime.strptime(str(s), "%Y-%m-%dT%H:%M:%SZ")
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def env_cred_name(program):
    return "T2D_CRED_" + re.sub(r"[^A-Z0-9]", "_", program.upper())


def load_vault(path):
    if not os.path.exists(path):
        return {"version": 1, "programs": {}}
    try:
        with open(path, encoding="utf-8") as f:
            v = json.load(f)
    except (OSError, ValueError) as e:
        die(6, "vault %s unreadable — fail closed: %s" % (path, e))
    v.setdefault("version", 1)
    v.setdefault("programs", {})
    return v


def save_vault(path, vault):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".sessions-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(vault, f, indent=2, sort_keys=True)
            f.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.chmod(path, 0o600)


def slot_of(rec, account):
    """Slot `a` is the record's top-level token/expires_at fields; slot
    `b` lives under `second_account` — same shape, for the IDOR pair."""
    if account == "b":
        if "second_account" not in rec:
            die(3, "program %r has no b account — register --account b"
                % rec["program"])
        return rec["second_account"]
    return rec


def resolve_creds_ref(ref):
    """Dereference a creds_ref to secret material, or None. env:NAME
    reads the environment; keychain:SERVICE[/ACCOUNT] asks macOS
    security(1) for a generic password. The ref is a key name — the
    vault stores where the secret lives, never a second copy it was
    not asked to hold."""
    if not ref:
        return None
    if ref.startswith("env:"):
        return os.environ.get(ref[4:])
    if ref.startswith("keychain:"):
        svc, _, acct = ref[len("keychain:"):].partition("/")
        argv = ["/usr/bin/security", "find-generic-password", "-s", svc]
        if acct:
            argv += ["-a", acct]
        argv += ["-w"]
        try:
            p = subprocess.run(argv, capture_output=True, text=True,
                               timeout=10, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout.strip()
    return None


def jwt_exp(token):
    """exp claim of a JWT, as ISO, or None — lets register derive
    expires_at for jwt auth_type when nothing was declared."""
    parts = str(token or "").split(".")
    if len(parts) < 2:
        return None
    try:
        seg = parts[1] + "=" * (-len(parts[1]) % 4)
        exp = json.loads(base64.urlsafe_b64decode(seg)).get("exp")
    except (ValueError, TypeError):
        return None
    if not isinstance(exp, (int, float)):
        return None
    return datetime.fromtimestamp(exp, timezone.utc).isoformat()


def auth_header(auth_type, token):
    """The one header an egress point stamps, in 'Name: value' form —
    single source of truth for inject fragments and urllib stamping."""
    if auth_type == "cookie":
        return "Cookie: " + token
    if auth_type == "basic":
        return "Authorization: Basic " + token
    return "Authorization: Bearer " + token


def stamp_auth(req, auth_type, token):
    name, _, val = auth_header(auth_type, token).partition(": ")
    req.add_header(name, val)


def detect(status, location):
    """Name the session-expiry shape in a proxied response, or None.
    Called by `expire-check` (egress-proxy hook) and by `status`
    probes — one detector, one failure accounting."""
    if status in (401, 403):
        return "auth_rejected"
    if status in (301, 302, 303, 307, 308) and location \
            and LOGIN_RE.search(location):
        return "login_redirect"
    return None


def bump_failure(rec, account, vault_path, vault):
    """Count one consecutive auth failure; park at max_failures.
    Returns 'parked' | 'expired'."""
    f = rec.setdefault("failures", {})
    f[account] = f.get(account, 0) + 1
    if f[account] >= rec.get("max_failures", DEFAULT_MAX_FAILURES):
        rec["parked"] = True
        save_vault(vault_path, vault)
        return "parked"
    save_vault(vault_path, vault)
    return "expired"


def get_rec(vault, program):
    rec = vault["programs"].get(program)
    if rec is None:
        die(3, "unknown program %r — register first" % program)
    return rec


def check_parked(rec):
    if rec.get("parked"):
        die(5, "program %r parked after %d consecutive auth failures "
               "— investigate, then unpark or re-register"
            % (rec["program"], rec.get("max_failures",
                                       DEFAULT_MAX_FAILURES)))


def slot_creds_ref(rec, account):
    if account == "b":
        return rec.get("second_account", {}).get("creds_ref") \
            or rec.get("creds_ref")
    return rec.get("creds_ref")


def live_token(rec, account):
    sl = slot_of(rec, account)
    tok = sl.get("token")
    if not tok:
        tok = resolve_creds_ref(slot_creds_ref(rec, account))
    return tok


def expiry_state(sl):
    exp = sl.get("expires_at")
    if exp and now() >= parse_iso(exp):
        return "expired", exp
    return "live", exp


def totp_code(seed, at=None, digits=6, step=30):
    key = base64.b32decode(re.sub(r"\s", "", seed), casefold=True)
    ctr = int((at if at is not None else time.time()) // step).to_bytes(8, "big")
    mac = hmac.new(key, ctr, hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = int.from_bytes(mac[off:off + 4], "big") & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def cmd_register(a):
    vault = load_vault(a.vault)
    rec = vault["programs"].get(a.program) or {
        "program": a.program,
        "auth_endpoints": [],
        "failures": {"a": 0, "b": 0},
    }
    rec["auth_type"] = a.auth_type
    rec["max_failures"] = a.max_failures
    rec["parked"] = False
    if a.creds_env:
        rec["creds_ref"] = "env:" + a.creds_env
    elif a.creds_ref:
        rec["creds_ref"] = a.creds_ref
    elif env_cred_name(a.program) in os.environ:
        rec["creds_ref"] = "env:" + env_cred_name(a.program)

    sl = rec if a.account == "a" else rec.setdefault("second_account", {})
    if a.account == "b" and a.creds_env:
        sl["creds_ref"] = "env:" + a.creds_env
    elif a.account == "b" and a.creds_ref:
        sl["creds_ref"] = a.creds_ref

    # Secret material: explicit --token, else the creds_ref target, else
    # a tty prompt. Whatever we obtain lands in the slot's token field —
    # the vault's job is holding the live token. Source creds stay
    # where they were: only creds_ref (the key name) is recorded.
    token = a.token or resolve_creds_ref(slot_creds_ref(rec, a.account))
    if token is None and sys.stdin.isatty():
        token = getpass.getpass(
            "token for %s [%s] (not echoed, stored in vault): "
            % (a.program, a.account))
    if token:
        sl["token"] = token
    if a.expires_at:
        sl["expires_at"] = a.expires_at
    elif a.ttl is not None:
        sl["expires_at"] = (now() + timedelta(seconds=a.ttl)).isoformat()
    elif token and a.auth_type == "jwt":
        exp = jwt_exp(token)
        if exp:
            sl["expires_at"] = exp

    if a.refresh_url:
        rec["refresh_url"] = a.refresh_url
        rec["refresh_method"] = (a.refresh_method or "POST").upper()
        if a.refresh_url not in rec["auth_endpoints"]:
            rec["auth_endpoints"].append(a.refresh_url)
    for u in a.auth_endpoint or []:
        if u not in rec["auth_endpoints"]:
            rec["auth_endpoints"].append(u)
    if a.probe_url:
        rec["probe_url"] = a.probe_url
    seed = a.totp_seed or os.environ.get(
        "T2D_TOTP_" + re.sub(r"[^A-Z0-9]", "_", a.program.upper()))
    if seed:
        try:
            base64.b32decode(re.sub(r"\s", "", seed), casefold=True)
        except (ValueError, TypeError) as e:
            die(2, "--totp-seed is not base32: %s" % e)
        rec["totp_seed"] = re.sub(r"\s", "", seed)
    rec["updated_at"] = now().isoformat()
    vault["programs"][a.program] = rec
    save_vault(a.vault, vault)
    print("registered %s [%s] auth_type=%s token=%s expires=%s"
          % (a.program, a.account, a.auth_type,
             "set" if sl.get("token") else "ref-only",
             sl.get("expires_at") or "unknown"))
    return 0


def cmd_token(a):
    vault = load_vault(a.vault)
    rec = get_rec(vault, a.program)
    check_parked(rec)
    sl = slot_of(rec, a.account)
    state, exp = expiry_state(sl)
    if state == "expired":
        die(4, "%s token for %r expired at %s — run refresh"
            % (a.account, a.program, exp))
    tok = live_token(rec, a.account)
    if not tok:
        die(3, "no token material for %r account %s (creds_ref %r "
               "did not resolve)" % (a.program, a.account,
                                     slot_creds_ref(rec, a.account)))
    print(tok)
    return 0


# Tools whose CLI takes a repeated "Name: value" header flag. Anything
# not listed cannot carry stamped auth — passive collectors (gau,
# waybackurls) hit third parties and would leak the session; DNS/local
# tools have no header to stamp. Refusing is the fail-safe.
HEADER_FLAGS = {"httpx": "-H", "nuclei": "-H", "katana": "-H",
                "ffuf": "-H", "x8": "-H", "arjun": "--headers"}


def cmd_inject(a):
    """Print the argv fragment that stamps this program's session onto
    the named tool — one JSON list, e.g. ["-H", "Authorization: Bearer
    .."]. The egress point (wrap.py, a proxy) appends it verbatim, so
    the tool-header mapping lives here, not in every caller."""
    flag = HEADER_FLAGS.get(a.tool)
    if flag is None:
        die(3, "tool %r cannot carry injected auth (header-capable: %s)"
            % (a.tool, ", ".join(sorted(HEADER_FLAGS))))
    vault = load_vault(a.vault)
    rec = get_rec(vault, a.program)
    check_parked(rec)
    sl = slot_of(rec, a.account)
    state, exp = expiry_state(sl)
    if state == "expired":
        die(4, "%s token for %r expired at %s — run refresh"
            % (a.account, a.program, exp))
    tok = live_token(rec, a.account)
    if not tok:
        die(3, "no token material for %r account %s (creds_ref %r "
               "did not resolve)" % (a.program, a.account,
                                     slot_creds_ref(rec, a.account)))
    header = auth_header(rec.get("auth_type"), tok)
    if "\n" in header or "\r" in header:
        die(6, "token material for %r contains CR/LF — refusing to stamp"
            % a.program)
    print(json.dumps([flag, header]))
    return 0


def extract_token(auth_type, status, headers, body):
    """Pull new token material out of a refresh response: a JSON body
    field, else the Set-Cookie header for cookie-type sessions. Returns
    (token, expires_at|None)."""
    try:
        data = json.loads(body)
    except ValueError:
        data = None
    if isinstance(data, dict):
        for k in TOKEN_JSON_KEYS:
            if isinstance(data.get(k), str) and data[k]:
                exp = None
                if isinstance(data.get("expires_in"), (int, float)):
                    exp = (now() + timedelta(
                        seconds=data["expires_in"])).isoformat()
                elif auth_type == "jwt" or "." in data[k]:
                    exp = jwt_exp(data[k])
                return data[k], exp
    cookies = headers.get_all("Set-Cookie") if headers else None
    if cookies:
        return "; ".join(c.split(";", 1)[0] for c in cookies), None
    return None, None


def cmd_refresh(a):
    vault = load_vault(a.vault)
    rec = get_rec(vault, a.program)
    check_parked(rec)
    url = rec.get("refresh_url")
    if not url:
        die(3, "program %r has no refresh_url — re-register with one"
            % a.program)
    method = (a.method or rec.get("refresh_method") or "POST").upper()
    # no-real-transactions rule: a mutating refresh may only hit an
    # endpoint registered as auth-only. refresh_url registers itself.
    if method not in SAFE_METHODS \
            and url not in (rec.get("auth_endpoints") or []):
        die(4, "refusing mutating %s to %r: not marked auth-only for %r"
            % (method, url, a.program))
    tok = live_token(rec, a.account)
    if not tok:
        die(3, "no token material for %r account %s to refresh with"
            % (a.program, a.account))
    req = urllib.request.Request(
        url, method=method,
        data=(b"" if method in ("POST", "PUT", "PATCH") else None))
    stamp_auth(req, rec["auth_type"], tok)
    try:
        resp = urllib.request.urlopen(req, timeout=a.timeout)
        status, headers = resp.status, resp.headers
        body = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status, headers = e.code, e.headers
        body = e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as e:
        die(6, "refresh fetch failed for %r: %s" % (a.program, e))
    kind = detect(status, headers.get("Location"))
    if kind:
        state = bump_failure(rec, a.account, a.vault, vault)
        n = rec["failures"][a.account]
        if state == "parked":
            print("parked [%s] %r account %s — %d/%d consecutive auth "
                  "failures" % (kind, a.program, a.account, n,
                                rec.get("max_failures",
                                        DEFAULT_MAX_FAILURES)))
            return 5
        print("expired [%s] %r account %s — refresh rejected, failure "
              "%d/%d" % (kind, a.program, a.account, n,
                         rec.get("max_failures", DEFAULT_MAX_FAILURES)))
        return 4
    new_tok, new_exp = extract_token(rec["auth_type"], status, headers,
                                     body)
    if not new_tok:
        die(6, "refresh for %r returned status %s with no token "
               "material" % (a.program, status))
    sl = slot_of(rec, a.account)
    sl["token"] = new_tok
    if new_exp:
        sl["expires_at"] = new_exp
    rec["failures"][a.account] = 0
    rec["updated_at"] = now().isoformat()
    save_vault(a.vault, vault)
    print("refreshed %s [%s] expires=%s"
          % (a.program, a.account, sl.get("expires_at") or "unknown"))
    return 0


def cmd_status(a):
    vault = load_vault(a.vault)
    progs = vault["programs"]
    if not progs:
        print("no programs registered")
        return 0
    rows, worst = [], 0
    for name in sorted(progs):
        rec = progs[name]
        accounts = ["a"] + (["b"] if rec.get("second_account") else [])
        for acct in accounts:
            sl = slot_of(rec, acct)
            state, exp = expiry_state(sl)
            has_tok = bool(sl.get("token") or slot_creds_ref(rec, acct))
            probe = "skipped"
            url = rec.get("probe_url")
            if url and has_tok and not rec.get("parked") \
                    and state != "expired":
                tok = live_token(rec, acct)
                req = urllib.request.Request(url, method="GET")
                stamp_auth(req, rec["auth_type"], tok or "")
                try:
                    r = urllib.request.urlopen(req, timeout=a.timeout)
                    p_status, p_loc = r.status, r.headers.get("Location")
                    r.read()
                except urllib.error.HTTPError as e:
                    p_status, p_loc = e.code, e.headers.get("Location")
                except (urllib.error.URLError, OSError) as e:
                    probe = "unreachable(%s)" % e
                    p_status = p_loc = None
                if p_status is not None:
                    kind = detect(p_status, p_loc)
                    if kind:
                        bump = bump_failure(rec, acct, a.vault, vault)
                        probe = "%s(%s)" % (kind, p_status)
                        state = "parked" if bump == "parked" \
                            else "expired"
                    else:
                        probe = "alive(%s)" % p_status
            rows.append({"program": name, "account": acct,
                         "auth_type": rec.get("auth_type"),
                         "expires_at": exp, "probe": probe,
                         "state": "parked" if rec.get("parked") else
                                  (state if has_tok else "no-material")})
            s = rows[-1]["state"]
            if s == "parked":
                worst = max(worst, 5)
            elif s == "expired" and worst < 5:
                worst = max(worst, 4)
    if a.json:
        print(json.dumps(rows, indent=2))
    else:
        for r in rows:
            print("%s [%s] %s expires=%s probe=%s state=%s"
                  % (r["program"], r["account"], r["auth_type"],
                     r["expires_at"] or "unknown", r["probe"], r["state"]))
    return worst


def cmd_expire_check(a):
    """Egress-proxy hook: the proxy reports the status line (and
    redirect target) it just saw; we decide whether the session died.
    Prints a verdict the proxy can act on — refresh on `expired`,
    stop dispatching on `parked`."""
    vault = load_vault(a.vault)
    rec = get_rec(vault, a.program)
    slot_of(rec, a.account)
    kind = detect(a.status, a.location)
    if kind is None:
        print("alive [no_auth_signal] %s [%s] status %d"
              % (a.program, a.account, a.status))
        return 0
    state = bump_failure(rec, a.account, a.vault, vault)
    n = rec["failures"][a.account]
    if state == "parked":
        print("parked [%s] %s [%s] — %d/%d consecutive auth failures; "
              "proxy must stop dispatching" % (kind, a.program, a.account,
              n, rec.get("max_failures", DEFAULT_MAX_FAILURES)))
        return 5
    print("expired [%s] %s [%s] — failure %d/%d; proxy should refresh "
          "and retry once" % (kind, a.program, a.account, n,
                              rec.get("max_failures",
                                      DEFAULT_MAX_FAILURES)))
    return 4


def cmd_totp(a):
    vault = load_vault(a.vault)
    rec = get_rec(vault, a.program)
    seed = rec.get("totp_seed") or resolve_creds_ref(
        rec.get("totp_ref", ""))
    if not seed:
        die(3, "program %r has no totp_seed — register --totp-seed"
            % a.program)
    code = totp_code(seed, at=a.at, digits=a.digits)
    if a.at is not None:
        print(code)
    else:
        print("%s (%ds remaining)" % (code, 30 - int(time.time() % 30)))
    return 0


def cmd_unpark(a):
    vault = load_vault(a.vault)
    rec = get_rec(vault, a.program)
    rec["parked"] = False
    rec["failures"] = {"a": 0, "b": 0}
    rec["updated_at"] = now().isoformat()
    save_vault(a.vault, vault)
    print("unparked %s — failure counters reset" % a.program)
    return 0


def main(argv):
    ap = argparse.ArgumentParser(prog="broker.py",
                                 description=__doc__.splitlines()[0])
    ap.add_argument("--vault", default=str(DEFAULT_VAULT),
                    help="vault file (default: memory/sessions.json "
                         "under T2D_ROOT)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--program", required=True)
        p.add_argument("--account", "--slot", choices=["a", "b"],
                       default="a")

    p = sub.add_parser("register")
    common(p)
    p.add_argument("--auth-type", required=True, choices=AUTH_TYPES)
    p.add_argument("--token", help="token material; else creds_ref/env "
                                   "lookup, else tty prompt")
    p.add_argument("--creds-env", help="env var name holding material "
                                       "(stored as env:NAME)")
    p.add_argument("--creds-ref", help="key name: env:NAME or "
                                       "keychain:SERVICE[/ACCOUNT]")
    p.add_argument("--expires-at", help="ISO-8601 expiry")
    p.add_argument("--ttl", type=int, help="seconds until expiry")
    p.add_argument("--refresh-url")
    p.add_argument("--refresh-method")
    p.add_argument("--probe-url", help="read-only liveness endpoint")
    p.add_argument("--auth-endpoint", action="append",
                   help="mark an endpoint auth-only (repeatable)")
    p.add_argument("--totp-seed", help="base32 TOTP seed (vault-stored)")
    p.add_argument("--max-failures", type=int,
                   default=DEFAULT_MAX_FAILURES)
    p.set_defaults(fn=cmd_register)

    p = sub.add_parser("token")
    common(p)
    p.set_defaults(fn=cmd_token)

    p = sub.add_parser("inject")
    common(p)
    p.add_argument("--tool", required=True,
                   help="wrapped tool name (header-capable: %s)"
                        % ", ".join(sorted(HEADER_FLAGS)))
    p.set_defaults(fn=cmd_inject)

    p = sub.add_parser("refresh")
    common(p)
    p.add_argument("--method", help="override refresh_method")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.set_defaults(fn=cmd_refresh)

    p = sub.add_parser("status")
    p.add_argument("--json", action="store_true")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("expire-check")
    common(p)
    p.add_argument("--status", type=int, required=True,
                   help="HTTP status the proxy observed")
    p.add_argument("--location", help="Location header on redirects")
    p.set_defaults(fn=cmd_expire_check)

    p = sub.add_parser("totp")
    p.add_argument("--program", required=True)
    p.add_argument("--at", type=float, help="epoch seconds (clock-skew "
                                            "debugging / tests)")
    p.add_argument("--digits", type=int, default=6)
    p.set_defaults(fn=cmd_totp)

    p = sub.add_parser("unpark")
    p.add_argument("--program", required=True)
    p.set_defaults(fn=cmd_unpark)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
