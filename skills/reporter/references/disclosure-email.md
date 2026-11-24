# Email disclosure — companion to `reporter`

Channel reference for programs that report by email instead of a
platform form. The skeleton and quality gate in `../SKILL.md` still
govern content; this covers addressing, packaging, send checks. The
skill still never sends — it drafts, a human mails.

## When email is the channel

- **VDP / self-hosted program** — only path is an address in
  `/.well-known/security.txt` or a diodb `contact_url`, not a form.
- **No platform presence** — cataloged via security.txt/diodb, no
  platform page.
- **Coordinated-disclosure fallback** — platform scope excludes the
  asset, the platform declined, or the finding spans vendors.

If a platform route exists and fits, use it — email is not a way around
a triage queue.

## Contact discovery order

Manifest `contact` block first (scope-parser already fetched). If empty,
resolve in order and stop at the first hit:

1. **`roe-manifest.md` contact fields** — unless the manifest is stale.
2. **`/.well-known/security.txt`** (or `/security.txt`) — the `Contact:`
   field (`mailto:` preferred); note `Preferred-Languages:`/`Encryption:`.
3. **diodb `contact_url`** — an address, or a policy page naming one.
4. **The program's policy/security page** — the address beside the
   safe-harbor text.

**Never guess an address.** `security@`/`abuse@`/`support@` patterns are
not discovery; no source means an `unknowns` entry that blocks the
draft. One address per report — the designated one, no CC list.

## Email template

One template, plain text only — no HTML, no images, no tracking links;
clients strip all three. `[Security]` stays literal so filters catch it;
severity tag optional. Fill, don't restructure:

```text
Subject: [Security] <finding summary> — <program>

Summary: <3 lines — what, where, why it matters. No greeting preamble.>

Affected asset: <asset + environment — prod/staging, version or commit
if known, manifest scope line>

Actively exploited: <yes | no | unknown — evidence of in-the-wild use or
scanner hits; "yes" may start the vendor's EU CRA clocks>

Reproduction:
1. <setup — own test account, role, starting state>
2. <verbatim request or action from evidence/<finding-id>/>
3. <observable result that proves the bug>
<numbered, self-contained — reader has a browser, a shell, nothing of yours>

Impact: attacker <who + access> can <action>; victim <who>; loss
<quantified — records, funds at risk, privilege gained>.

Evidence (attached): <file list — request.txt, response.txt, poc.ext;
by filename, never pasted inline>

Suggested fix: <concrete — check X before Y; not "sanitize input">

Disclosure timeline: I plan to publish <program-stated window, else 90
days> from this mail; adjustable for a reasonable remediation timeline —
tell me what you need.

Reporter: <name/handle>. Reply to this address; PGP fingerprint <fp> if
you encrypt. Research under <policy URL>, test account <id>.
```

Wrap ~72 chars, ASCII; match `Preferred-Languages` if given.

The 90-day figure is a declining ceiling, not a standard — Google P0
already moved 90 to 60 to 30 days for exploited bugs. Never promise a
window longer than the vendor's own published policy; when the policy
states one, quote it instead.

## Safety and packaging

- **PGP offered? Note it, don't implement.** An `Encryption:` key goes
  in draft header and checklist; encrypting is the submitter's call.
- **Evidence rules apply to attachments.** Own test accounts only, no
  real user data, secrets redacted per the `evidence` skill. Mail can't
  be edited after send — over-collected screenshots are worse here.
- **Attachments as files, not inline.** Named in the body; nothing
  pasted over a line. Rename PoCs `.txt` if the gateway strips `.py`.
- **One address, one finding per mail.** No CC chains, no batch digests.

## Escalation ladder — when the vendor channel is dead

The designated address is the first rung, not the only one. When the
published contact is absent, bouncing, or silent past its window:

1. **Vendor, one retry** — same thread, ~7 days. Silence past the
   vendor's stated window (or 45 days total) moves you up a rung.
2. **National CERT/CC** — CERT/CC or your national CSIRT; they run
   vendor-finding when the published contact is stale or missing.
3. **CISA VINCE-NT** — file when the vendor is unresponsive or no
   channel exists at all. CISA coordinates the disclosure and is a
   CNA, so the case can mint the CVE the vendor never issued.

Each rung gets ~45 days before you climb — checkpoints, not
ultimatums. Escalating is not disclosing: the draft still ships no
public detail until the coordinated window closes or a rung authorizes
it. Log every rung change in `memory/ledger.md` like a submission.

## Always-rejected — email additions

The list in `../SKILL.md` applies unchanged. Email adds three:

| Finding class | Why rejected |
|---|---|
| "Found by scanner" output without a built exploit | Unverified noise — worse by email, where no triage queue absorbs it |
| Mass-mailed templated findings | The spray pattern — same body to dozens of contacts — is why programs stopped reading `security@` |
| Payment request in the first email | A compensation ask before triage reads as extortion — request payment only when the program publicly advertises rewards; policy silent on rewards means no compensation language at all |

All three burn the address itself — programs abandon published contacts.

## SUBMIT-CHECKLIST — email variant

The line keeps its shape and gains the channel:

```text
- [ ] <finding-id> — <class> on <surface> — severity <tier> — evidence ok — dedupe clean — channel:email to <address> — pending human send
```

Five pre-send checks:

1. **Recipient verified from a policy source?** Address from
   security.txt, diodb, or policy page via the manifest — no guesses.
2. **Evidence attached as files?** Every claim maps to an attachment;
   nothing inline, no real-user data.
3. **Timeline stated?** The program's stated window — or the 90-day
   fallback — is in the body; never longer than the vendor's own policy.
   A mail without a timeline reads as a threat.
4. **PGP if offered?** Published key noted in the draft; encrypt-or-not
   was the submitter's explicit call.
5. **Exploitation declared?** `Actively exploited` is filled. `yes` may
   start the vendor's EU CRA clocks (24h early warning, 72h
   notification) — say it plainly, don't bury it.

Log the send like a platform submission: `submitted`, channel `email`,
in `memory/ledger.md`.
