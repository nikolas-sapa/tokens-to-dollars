# tools/session-broker — the fleet's auth layer

Workers never see secrets. A worker emits an *untagged* request; the
egress/injection proxy — the only component allowed to call `token` —
reads the live token from the vault and stamps `Authorization` /
`Cookie` on the outbound request. Secrets never enter model context,
worker env, tool argv, or logs. Thacker/XBOW/Strix-style separation:
the capability (a logged-in session) is held by infrastructure, not
handed to the agent.

## Architecture: vault / broker / proxy boundary

```
worker            egress proxy              broker.py            vault
  |  untagged req  |                         |                    |
  |--------------->|  token --program X ---->|  reads 0600 file ->|
  |                |<------------------------|                    |
  |                | stamps Authorization /  |                    |
  |                | Cookie, forwards        |                    |
  |  resp status   |                         |                    |
  |<---------------|  expire-check feeds     |                    |
  |                |  status back ----------> | counts failures    |
```

- **Vault** — `memory/sessions.json`. Lives under the gitignored
  `memory/` tree, written atomically, mode 0600 enforced on every save.
  The single material store.
- **Broker** — this script. The only reader/writer of the vault.
  Registers programs, emits tokens, runs refreshes, probes liveness,
  enforces the circuit breaker.
- **Proxy** — reads `token --program X` output, stamps auth, calls
  `expire-check` on every response. Never hands the token downstream.
- **Workers** — hold no credential, ever. A compromised or hijacked
  worker can still send *requests*, but cannot leak a session it was
  never given.

## Per-program cred record

```json
{"program": "acme",
 "auth_type": "cookie",
 "creds_ref": "env:ACME_SESSION",
 "token": "<live slot-a token>",
 "expires_at": "2026-01-01T00:00:00+00:00",
 "second_account": {"token": "<slot-b>", "expires_at": "...",
                    "creds_ref": "env:ACME_SESSION_B"},
 "refresh_url": "https://id.acme.example/token/refresh",
 "refresh_method": "POST",
 "probe_url": "https://api.acme.example/me",
 "auth_endpoints": ["https://id.acme.example/token/refresh"],
 "totp_seed": "JBSWY3DPEHPK3PXP",
 "failures": {"a": 0, "b": 0},
 "max_failures": 3,
 "parked": false}
```

- `creds_ref` is a **key name**, not a secret: `env:NAME` resolves the
  environment at read time; `keychain:SERVICE[/ACCOUNT]` asks macOS
  `security(1)` for a generic password. Registering never copies source
  creds beyond the live token field.
- `token`/`expires_at` are slot `a`; `second_account` is slot `b` —
  the IDOR pair, same program, two victims (`--account b`).
- `totp_seed` is the base32 MFA seed, stored in the vault (0600, not
  the worker env). `totp --program X` emits the current code; a proxy
  sidecar fills OTP prompts without the seed entering context.

## Auth-only endpoint marking + no-real-transactions rule

`auth_endpoints` marks endpoints that exist purely to mint/refresh
sessions. The rule: **the broker never sends a mutating call to an
unmarked endpoint** — `refresh` refuses a POST/PUT/PATCH whose URL is
not in `auth_endpoints` (registering `--refresh-url` marks it
automatically; `--auth-endpoint` marks more). A session refresh must
never become a purchase, a transfer, or a state change — an auth
endpoint mints sessions and does nothing else. `probe_url` stays
read-only (GET) by construction.

## Circuit breaker

`expire-check` (proxy hook) and rejected `refresh` calls count
consecutive auth failures per slot. At `max_failures` (default 3) the
program is **parked**: `token` and `refresh` refuse (exit 5) until a
human investigates and runs `unpark` or re-`register`s. A fleet that
keeps hammering a dead session reads as credential-stuffing; parking
stops that before it starts.

## Verbs

| verb | effect | exit |
|---|---|---|
| `register` | create/update a program record (token via `--token`, `--creds-env`, creds_ref, or tty prompt) | 0 |
| `token` | print the live token — for the proxy, not workers | 0 / 3 no material / 4 expired / 5 parked |
| `refresh` | call `refresh_url`, extract new token (JSON field or Set-Cookie), reset failures | 0 / 4 rejected / 5 parked / 6 fetch error |
| `status` | per-program expiry + GET `probe_url` liveness check | 0 healthy / 4 any expired / 5 any parked |
| `expire-check` | feed an observed `--status`/`--location`; detects 401/403 and 302→login | 0 alive / 4 expired / 5 parked |
| `totp` | emit the current TOTP code (`--at`, `--digits` for tests) | 0 / 3 no seed |
| `unpark` | clear `parked` and reset failure counters | 0 |

## DBSC / SSO caveats (integration point)

Device Bound Session Credentials and Google-class SSO bind the session
to a real browser profile — cookies carry DBSC keys, login needs a WebAuthn
passkey or an interactive consent flow that no vault file can hold. For
those targets the session lives on a **real Chrome node** (a profile
dir, a headed browser, an extension relay); the broker's `refresh_url`
then points at a local bridge that asks the node for a fresh cookie
rather than minting one itself. Mark such programs `auth_type: cookie`,
set `probe_url` aggressively, and expect `expire-check` to park them —
re-auth there is a human-in-the-browser flow, not a POST.
