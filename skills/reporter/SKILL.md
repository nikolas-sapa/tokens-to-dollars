---
name: reporter
description: Convert a validated, evidence-bound finding into a platform-calibrated, submission-ready report draft for human review. Drafts only, never submits.
---

# Reporter

Turn one validated finding into a draft a human can review and submit in
minutes. Inputs: finding notes, `evidence/<finding-id>/` (see `evidence`
skill), program manifest + severity table (see `scope-parser`), dedupe
verdict (see `dedupe-check`).

Outputs:

- `reports/<program>/<finding-id>.md` — the report draft
- `reports/<program>/SUBMIT-CHECKLIST.md` — one appended line per draft

Hard rule: this skill never submits. No platform write APIs, no
"ready-to-send" flag, no auto-fill of submission forms. A human reads the
draft, checks the box, and hits submit.

## Universal report skeleton

Every draft carries these sections, in this order:

1. **Title** — `[Bug class] on <asset> allows <concrete impact>`
2. **Summary** — three sentences max: what the bug is, where it lives,
   why it matters. No preamble.
3. **Severity justification** — argued against the program's own severity
   or payout table, cited line for line.
4. **Steps to reproduce** — numbered, imperative, copy-pasteable. Assume
   the triager has a browser and a shell and nothing of yours.
5. **Impact** — attacker, victim, loss (see formula below).
6. **Evidence references** — paths into `evidence/<finding-id>/`.
7. **Suggested remediation** — concrete fix, not "sanitize input".
8. **Suggested mitigation** — when the vuln class is edge-blockable, a
   WAF rule sketch for programs that cannot patch immediately. Omit
   when no edge rule covers the class.
9. **Scope citation** — the manifest line covering asset + bug class.

Draft markdown skeleton (fill, don't restructure):

```markdown
# [Bug class] on <asset> allows <impact>

## Summary
<what> in <where> lets <attacker> do <action>, causing <loss> for <victim>.

## Severity
<tier> — per program severity table: "<cited tier line>". Claimed
<first-pass estimate>; calibrated <tier> after the discount rule.
<1-2 sentences mapping evidence to tier criteria. CVSS vector if required:>

## Steps to reproduce
1. <setup: account, role, starting state>
2. <trigger — verbatim request from evidence/<finding-id>/request.txt>
3. <observable result that proves the bug>

## Impact
Attacker: <who + required access>. Action: <what>. Victim: <who>.
Loss: <quantified — records, funds at risk, privilege gained>.

## Evidence
- evidence/<finding-id>/request.txt, response.txt
- evidence/<finding-id>/repro.<ext> — minimal runnable repro script
- evidence/<finding-id>/capture.<ext> — screenshot/transcript with the
  canary or OAST hit visible
- evidence/<finding-id>/poc.<ext>
- evidence/<finding-id>/notes.md

## Remediation
<concrete fix: check X before Y, rate-limit Z, validate bound on N>

## Suggested mitigation
<only when the class is edge-blockable: WAF rule sketch — match
<pattern> on <inbound request | outbound response>, covering the
variant family, not one payload. For programs that cannot patch
immediately; omit the section otherwise.>

## Scope
Asset: <manifest line id>. Bug class: <manifest line id>.
Dedupe: <verdict + corpus checked>. Account: <test account + role>.
```

## AI-methodology block (conditional)

Emitted only when the manifest's `ai_disclosure` is `required` or
`incentivized` — omit the section entirely on `not-required`/`unstated`.
One block, placed before Scope:

```markdown
## Methodology
Tooling: AI-assisted recon + manual verification and reproduction.
Attestation: every claim in this report was manually verified and
reproduced by the named researcher.
```

The attestation is a claim the submitter stands behind. If the finding
was never manually reproduced, the draft fails the quality gate — the
block does not launder an unverified finding.

Attribution hygiene: when AI tooling assisted, the report format stays
honest — no "found by <model>" bylines, no inflated discoverer claims.
The named human operator owns the submission and every claim in it
(HackerOne's Hackbots policy: a human account, a human attestation).
The methodology block states assistance; it never assigns authorship
to a tool.

## Steps-to-reproduce rules

- Every request is pasted verbatim from `evidence/<finding-id>/request.txt`.
  If the triager can't paste it, it isn't a step.
- Name the test account and role used. Never real user data.
- Core trigger lands in the first 3 steps; setup and cleanup go last.
- If the PoC needs a script or HTML file, inline it and reference `poc.*`.
- A video PoC is a supplement, never a replacement: <=2 minutes, stored
  under `evidence/<finding-id>/`, and the report must still repro from
  the written steps alone.
- Written steps alone do not ship. Every draft carries
  `evidence/<finding-id>/repro.<ext>` — a minimal runnable script that
  fires the trigger
  (single file, standard tooling, no framework setup) — plus a captured
  artifact: screenshot or transcript with the proof visible (canary
  token, OAST callback, the state change itself). Prose steps
  describe; artifacts prove.
- End with the observable result: what the triager sees that proves the bug.

## Impact statement formula

`Attacker` (who, and the access they need) → `action` (what they can do
that they should not) → `victim` (who pays) → `loss` (quantified: records
exposed, funds at risk, privilege gained). Assert only what your evidence
demonstrates. "Could potentially" is a banned phrase.

## Patch offer

Remediation is the triage bottleneck — the Codename MDASH lesson: a
report carrying a minimal, regression-tested patch gets merged far
faster than one that only describes the bug (55 of 99 patched reports
in the GitHub-MS pilot were accepted upstream). When the finding allows:

- Under Remediation, append a minimal diff or precise fix guidance —
  the smallest change that closes the hole, in the project's own style.
- Include a regression test the program can run itself: the before/after
  case, kept as small as the PoC.
- Label the patch a suggestion, not verified against their production
  tree — you tested the pattern, not their deploy.
- Never auto-file PRs. The draft carries the patch; the human decides
  what leaves the machine.

Same economics after submission: retest requests and NMI replies carry
response-time expectations, and fast human follow-up is tracked (Google
VRP's 1.2x multiplier scores replies inside ~3 workdays). The checklist
line is a promise to stay reachable, not the end of the work.

Beyond the patch: when the vuln class is edge-blockable, the draft also
carries the Suggested mitigation block — a WAF rule sketch naming the
pattern to match and the direction it applies to (inbound request,
outbound response), stated against the variant family, not one payload
(the exploit→WAF pattern: ship a block while the patch lands). It
serves programs that cannot patch immediately and is a sketch for their
infra team, not a shipped ruleset. A class no edge rule can cover omits
the block — a non-functional mitigation reads worse than none.

## Per-platform calibration

| Platform | Severity model | Title convention | Required extras | Watch out for |
|---|---|---|---|---|
| HackerOne | Program's own severity table; weakness dropdown must match report class | `[Class] on <host> allows <impact>` | Weakness (CWE) field, impact text box | Severity inflation is the #1 credibility killer with H1 triage |
| Bugcrowd | VRT — cite the VRT node and resulting P-level | Same as H1 | VRT category, target picker, CVSS if asked | Wrong VRT node = bounce before technical review |
| Intigriti | Program severity table, CVSS fallback | `[asset] - [vuln] - /endpoint` | Endpoint + weakness fields, researcher notes | Programs here run lean triage; sloppy repro = instant N/A. Validate the PoC on a fresh account / clean instance before drafting |
| YesWeHack | CVSS score + vector required in the form | Same as H1, French accepted on FR programs | CVSS base + vector string, CWE | Form blocks submission without a valid vector |
| Immunefi | Impact tiers priced in USD of funds at risk | `[Contract/function] <class> leads to <fund impact>` | Fork-test PoC at pinned block, decoded tx trace, funds-at-risk math, chain + block stated | "Theoretical" impact tiers are rejected; price from on-chain state, show the math |
| GHSA (GitHub private advisory) | Reporter picks a severity label; maintainer may override | `[Bug class] in <component>: <impact>` | Affected version/commit range, CWE optional, PoC in body | Markdown IS rendered here (unlike email plaintext — use it); advisory stays private until maintainer publishes; don't also file a public issue |

### Hard schema constraints — bounce-on-upload limits

- **Intigriti:** minimal-dependency PoC scripts (no framework setup); raw
  HTTP request/response pairs mandatory in the body — raw TCP dumps where
  the bug is non-HTTP. AI-use disclosure block is mandatory platform-wide:
  treat `ai_disclosure` as always `required` here.
- **Bugcrowd:** 25k-char description cap — tighten prose, move dumps to
  attachments; VRT-mapped severity; up to 20 attachments, each <400MB;
  files >100MB go on Vimeo only.
- **HackerOne:** direct uploads only — third-party hosting (YouTube,
  Imgur, Drive links) is a CoC violation on every platform; video-only
  PoC is ineligible, written steps must stand alone.
- **YesWeHack:** structured fields, not one body blob — assets,
  endpoints, payloads, environment, auth context each get their field.
- **Immunefi:** English only; local-fork runnable PoC (Foundry/Hardhat
  project, runs end-to-end); dashboard-only submission, no email channel.

Evidence hygiene, all platforms: never host evidence on third-party
platforms — direct upload or it does not ship; redact cookies, tokens,
and third-party PII from captures before upload. Answer NMI
(needs-more-info) in precise human prose, fast — Google VRP's 1.2x
multiplier wants replies inside ~3 workdays.

## Channel: email vs platform

The skeleton and gate above assume a platform form. A large share of
catalog programs take reports by email instead: VDPs and self-hosted
programs publishing a security.txt contact or diodb `contact_url`,
programs with no platform presence, and coordinated-disclosure cases
where the platform path does not apply.

Channel decision:

- Platform page exists and the asset is in its scope — platform draft,
  calibrated per the table above.
- Otherwise — email draft. Addressing, the template, and packaging rules
  live in `references/disclosure-email.md`. What differs from a platform
  draft:
  - Recipient comes only from the manifest `contact` block
    (security.txt, diodb, policy page). A guessed address is an
    `unknowns` entry, and it blocks the draft.
  - When the policy page itself is missing, resolve asset→contact via
    the lookup.disclose.io index (its API/`disclose` client) before
    declaring the recipient unknown — a hit counts as a policy-source
    address, a miss stays `unknowns`.
  - Output is a plain-text mail plus attachment list, not form fields.
    Subject: `[Security] <finding summary> — <program>`.
  - A disclosure timeline (90-day default) goes in the body — a mail
    without one reads as extortion.
  - The checklist line gains `channel:email to <address>` plus five
    pre-send checks.

Same quality gate, same evidence rules, same never-submits rule. The
always-rejected list below applies to email too, plus three email-only
additions in the reference.

## Always-rejected list

The following are N/A or Informational on every major platform unless the
exception applies. Checking this list before writing saves a rejection.

| Finding class | Why rejected | Exception cases |
|---|---|---|
| Self-XSS | Victim must attack themselves | Chained into stored/reflected delivery, or login CSRF pairing |
| Missing SPF/DMARC/DKIM | Mail config, not an exploitable bug | Program scope explicitly lists email spoofing |
| Clickjacking on non-auth / non-sensitive page | No security impact | Demonstrated on a state-changing action |
| Missing rate limiting (generic) | Best practice, not a vulnerability | Working brute-force shown on auth, OTP, or token endpoint |
| Password complexity / no 2FA enforcement | Policy preference | Never report |
| Logout CSRF | No impact | Never report |
| Best-practice-only (headers, banners, version disclosure) | Hardening advice | Chained to a demonstrated exploit |
| Scanner output without exploit | Unverified noise | You built the exploit — then it's a real finding |
| "Possible" / speculative findings | Triagers reject maybes | Prove the code path, or don't file |

## Multi-finding audit format

Single-finding submissions use the skeleton above. Engagement-level
output — a code review, an audit pass, an internal findings digest — uses
the format exemplar in `references/finding-format.md` (adapted from
cinder's BUG-REPORT.md). Its load-bearing conventions:

- **Every finding is tagged.** `CONFIRMED` = the exact path was traced
  end to end; `SUSPECTED` = strong evidence, plausible trigger, not fully
  exercised. The tag sits in the heading — `### 3. CONFIRMED — <what>`
  — so a reader skims truth-weight, not just titles. Never upgrade a
  SUSPECTED to CONFIRMED by softening the language; upgrade it by
  exercising the trigger.
- **Ranked by likelihood × severity**, not by discovery order. Finding 1
  is the one the triager should read first.
- **Each entry carries trigger + blast radius + `file:line`.** The
  trigger states what input or sequence fires it; the blast radius
  states what else dies or leaks when it does; every claim is anchored
  to `path:line` citations a reviewer can grep. Vague locality ("in the
  auth module") is not a citation.
- **An "Areas cleared cleanly" section closes the report.** List what
  was audited and found sound, with the check that cleared it —
  "frame codec: length checked before allocation, `frame.rs:83-111`".
  Triagers trust a report that proves negative coverage; silence on a
  component reads as "not looked at", not "clean".
- **A one-line-per-finding summary table** between the ranked detail and
  the cleared section gives the second reader the whole report in ten
  lines.
- **Status tags are honest about partiality.** A code defect confirmed
  in source whose trigger was not exercised is recorded as
  "CONFIRMED as a code defect, trigger SUSPECTED" — the two halves of
  the claim keep their own weights.

The full skeleton — section order, heading grammar, the cleared-cleanly
block — lives in `references/finding-format.md`.

## Reportability gate — 7 questions

Runs FIRST, before the quality gate and before any drafting. Ask and
answer each; if the answer to all seven is no, do not report — but never
delete the finding. It stays in notes as evidence for later chains.

1. **Can a real person be harmed?** Stealing their account, session,
   private data, acting as them, or deleting what is theirs — counts only
   if you did it and captured the proof. "An attacker could" is not proof.
2. **Can the platform itself be harmed or misused?** Reading data never
   meant public, reaching internal systems/files, executing actions that
   should need permission, or making it crash or stop serving.
3. **If it is a leaked credential: was it meant to ship to every visitor?**
   A credential is reportable only when it unlocks data or actions a
   normal visitor cannot reach — show what it unlocked, not just that it
   exists. Publishable keys (Stripe `pk_`, Supabase publishable, analytics
   tokens, Google API client keys) are not secrets.
4. **"This helps me learn the target" is a note, not a report.** Recon
   yield stays in notes forever; it is never submitted alone.
5. **Does the weakness only matter in combination?** Report only after the
   combination is completed. Until then it is half a finding — keep the
   half, finish the chain, report the whole.
6. **In doubt, downgrade — do not drop.** Real-but-small impact files at
   the honest small tier. The gate removes noise, not honest small finds
   — and small money is still money: a verified $50 bug ships as a $50
   report, never discarded for tier size.
7. **Rejection here never means the surface is finished.** A finding that
   fails the gate today is often the opening move of the one that passes
   tomorrow — keep hunting the same surface from the new angle.

This gate removes reports, never observations. A failed gate routes to
notes (the memory layer in `../orchestrator`), not to the trash.

## Quality gate — 9 questions

A draft may only be written after all nine pass. Any fail routes the
finding back to validation, not to prose workarounds.

Before the nine, one paragraph settles the security-vs-ordinary-bug
line — the post-slop failure class is accurate hundreds-of-line reports
that misjudge it. Write "why this is a security bug": who loses what,
under which trust-boundary crossing, and why the behavior is not what
the system intends. If the paragraph cannot name a concrete attacker
benefit crossing a boundary, hold the report — nothing gets drafted.
That paragraph is what separates valid from accurate-but-rejected.

1. **Attacker real?** Named actor + required access level, not "anyone".
2. **User harm real?** Named victim + concrete loss, not "bad practice".
3. **In scope?** Asset and bug class both inside the manifest; cite the line.
4. **Reproducible?** Core trigger fires in 3 numbered steps or fewer.
5. **Evidence attached?** Every claim maps to a file in
   `evidence/<finding-id>/`; claims without files get deleted, not softened.
6. **Dedupe clean?** `dedupe-check` ran and returned no-match; record the
   verdict in the draft footer.
7. **Impact priced by the program's own table?** Severity argued against
   this program's published tiers, not a generic scale.
8. **Expected vs actual stated?** The draft names what the system should
   do and what it actually does — not just "a bug exists".
9. **Environment asserted?** Prod vs staging (and version/commit) is
   declared, including any severity multiplier the program applies to
   production impact.

## Triager-simulation pass

Nine questions passed is necessary, not sufficient. Before a draft
reaches the human, run one judge pass simulating the platform's triage
order — scope fit → dedupe against known reports → replicate the steps
on a clean account → VRT/severity-table mapping → impact scoring — and
rate submit-worthiness 1–5. Below the threshold (default 4) the draft
returns to verification with the failing stage named; it never reaches
the human's checklist. The nine questions ask "is this draft correct" —
the simulation asks "would a triager accept it," which fails on
different things: weak repro, a wrong VRT node, a class on the
always-rejected list. Record the score and stage in the draft footer;
they calibrate `../../evals/fprate`.

## Calibration notes

- Write for the triager's 5-minute read: provable by minute 3, fix obvious
  by minute 5. Put the impact line in the first paragraph.
- No AI-slop tells: no "revolutionary", "critical!!!", "sophisticated
  attacker", no severity adjectives doing work evidence should do, no
  hedging ("it appears", "may allow"). Sloppy triage-read reports burn
  reputation per program.
- Severity: map the program's own severity/payout table first and cite the
  matching tier. CVSS 3.1/4.0 is the fallback when the table is silent;
  YesWeHack requires the vector regardless. Always include the full vector
  string, not just the score.
- Severity inflation discount: AI-found severity claims skew high — a
  VulnCheck audit found 91.5% claimed Critical/High vs 51.3%
  maintainer-confirmed. So the draft states both numbers: the claimed
  severity (first-pass estimate) and the calibrated severity (what the
  executed evidence supports). Without an executed impact proof — the
  trigger run end to end against the real target — the report's ask
  defaults one tier below the model's first estimate. Two flags force
  the downgrade regardless of estimate: the attack needs an
  already-privileged role, or it needs uncommon user interaction (the
  Immunefi precondition rule, which generalizes). A calibrated-down
  severity that holds beats an inflated one that burns program trust.
- Immunefi severity = USD at risk. Price from on-chain state at a stated
  block, show the arithmetic, distinguish direct theft from griefing /
  unclaimed-yield classes — they map to different tiers.
- One finding per report. Chained bugs file as one finding only when every
  link is needed for the impact; otherwise split.
- Match program language (English default; French on FR YesWeHack scopes).

## Submission-channel bars — per-program hard formats

Some programs reject on format before content is read. Check the manifest
for these before drafting the artifact:

- **Google (VRP + Cloud VRP):** final reward multiplies ×0.8 / ×1.0 / ×1.2
  on the seven-dimension rubric (see `../hunt/references/playbooks.md`
  PART 2 — description, preconditions, impact, repro steps, target info,
  repro output, responsiveness). "Exceptional" wants an **automated PoC
  when possible**: must run in a Debian-based env (they sandbox-run it —
  Cloud Shell), minimal deps (prefer Python `requests` over exotic libs —
  they may ask you to rewrite if they can't verify dependency safety),
  **no Selenium/browser automation** (they want the underlying API calls),
  and it must accept **their own cookies/credentials** — never embed yours.
  Short unlisted-YouTube video is a bonus. "AI slop" — non-technical or
  factually wrong responses — is a scored-down responsiveness dimension.
- **Plaintext-channel programs (e.g. Safe Foundation):** email channel
  with **no attachments, no external links — auto-rejected**. The entire
  report body + PoC must be inline plain text. Manifest `contact` block
  carries the format flag.
- **Email-channel reports are STRICT ASCII plaintext — zero markdown
  syntax.** No `##`/`#` headers (use `N. Title` or `SECTION NAME:`), no
  `**bold**`, no ``` fences (paste code/log output as bare lines), no
  backticks (identifiers stay bare), no `—`/`–`/`‖`/`→` unicode
  (use `-`, `||`, `->`). The file must be truly copy-paste: line 1
  `To:`, line 2 `Subject:`, then the body — no placeholders, no
  signature block, no internal notes. Verify with a residue grep
  (`[`*#—‖`]`) before presenting.
- **Version-pinned scope (Safe-style):** scope lists exact contract/module
  versions — a bug already fixed in a newer released version is excluded.
  Check the deployed/released version against the pinned list before
  drafting; a mismatch kills the report.
- **Fee-gated submissions (e.g. Lombard on Immunefi):** a non-refundable
  submission fee is required for the report to be reviewed — flag to the
  human before drafting; paying a platform fee is their decision, never
  the tool's.
- **KYC-before-payout (most Immunefi programs):** noted in the manifest;
  surface it in the checklist line so the human knows the payout path
  needs identity docs.

## Triage economics — platform precision gates (Nov 2026)

Every platform now gates throughput on rolling precision. The pipeline
must score an account's standing before each submission and feed the
numbers to the orchestrator's circuit breakers. N/A elimination matters
more than duplicate elimination — dups cost $0 but mostly spare the
account; N/A/invalid closures trigger the cliffs.

| Platform | Gate (rolling) | Break-even precision | Consequence below | Recovery lane |
|---|---|---|---|---|
| HackerOne | Signal slider −1.0…7.0; 3 shared trial reports below gate | p ≥ (S+5)/12 (S=0→41.7%, 1→50%, 2→58.3%, 7→100%) | 3rd trial submit → 90-day pause on gated programs | Any Triaged/Resolved (incl. VDP) resets trials to 3, lifts pause |
| Bugcrowd | >50% accuracy over 90d at ≥10 subs; **N/A counts as rejection** since Oct 2026 | >50% | 6 subs/wk cap ≥7 days; 10 consecutive invalid → review + 30-day suspension | VDPs exempt from throttle; rebuild via unique P1–P3 on VDP |
| Intigriti | Validity Ratio over last-20 processed (Informative neutral) | <20%→1 slot; 20–40%→3; 40–60%→5; 60–80%→7; **≥80%→Unlimited** | Concurrency cap on open Triage reports (Little's Law: at 5d triage, 70% validity ≈ <10 subs/wk) | Unmanaged VDPs don't consume slots; clear NMI threads fast (they hold slots) |
| YesWeHack | Credits: −1C submit; +2C accepted (+sev bonus); −3C invalid/OOS; −4C spam | ~43–48% acceptance solvency | Balance 0 → 15-day freeze; AI-slop = Severity 7 (all ethical points gone) | Dojo challenges KYC-exempt; dup/informative refund +1C (net 0) |

Standing rules:
- **Human-in-the-loop is mandatory** — H1 bans fully autonomous
  submission, Intigriti requires disclosed AI use + human replies to
  triagers (no raw LLM text in replies), YWH Sev-7 for unverified slop,
  Bugcrowd expects AI but bans farming. The human reviews and sends —
  always.
- **Duplicates pay $0 cash everywhere** but mostly don't damage the
  account (YWH refunds the credit; H1 refunds the trial report if
  pre-disclosure; Intigriti counts valid dups positive). First-valid
  wins — never race a stub.
- **Pay-on-triage > pay-on-resolution** for cash velocity: exposure
  debt means >60% of criticals sit unresolved months; on
  pay-on-resolution programs cash strands and unpatched bugs multiply
  dup collisions. Prefer pay-on-triage targets when ranking.
- **All money is acceptable.** The gate rejects non-bugs, not small
  bounties — a real $50 bug is reported honestly at $50 severity. Never
  discard a verified finding because the payout tier is low; bundle it
  or report it solo at its honest size. The filter is the harm gate
  (real person/platform harmed), not the dollar figure.
- **Fee stakes:** Sherlock $250 USDC/submission (refunded if valid;
  dup-refund unclear — check brief), Decred-style DCR deposits —
  surface before the human pays anything.

## Report-format economics

The artifact is an executable interface for two readers: a machine
validator (Hai Agentic Exploitation sandbox, Elastic-style 5-min Docker
runner, Bugcrowd's text-only triage LLM) and a human with a 5–10 minute
repro budget (3s title scan, 15s impact, 30s raw-request check).

- **Text-first PoC, always.** Video-only reports = automatic N/A on
  HackerOne (−5 rep). Bugcrowd's triage AI cannot see images/video at
  all. Attach 3–5 redacted screenshots as *supplement*, never payload.
  "Sheet of paper" test: printable plaintext must carry the whole bug.
- **Title ≤140 chars, three tokens:** `[class] + [exact endpoint] +
  [concrete impact]` — it's the dedupe/severity index the triager hits
  first. `IDOR on GET /api/v2/invoices/{id} leaks cross-tenant PII`.
- **300–800 words**, zero LLM-padding; atomic numbered steps (one action
  each, zero implicit browser state, verified twice from clean session);
  Expected-vs-Actual contrast; strictly separate executed / observed /
  inferred.
- **Copy-paste executable PoC:** raw HTTP pairs in fenced blocks +
  single-command curl/python/HTML. Must run in <5 min (Elastic-style
  sandboxes hard-timeout at 5:00). Ready-to-run HTML CSRF PoCs measurably
  speed payout. Two researcher-owned accounts for authz bugs.
- **Metric-by-metric severity:** full CVSS vector + one factual sentence
  per metric, or the exact VRT entry on Bugcrowd (elevation argument at
  top). Unargued "Critical" = inflation flag.
- **Pre-flight lint before Bugcrowd** — report bodies are uneditable
  post-submit (corrections live in comments). Strip scanner signatures
  (nuclei/ffuf/Burp-Scanner strings — Brave-class programs reject raw
  tool output); redact cookies/PII/tokens.
- **Platform overlays:** Intigriti auto-append AI-usage disclosure +
  testing IP; H1 needs no video-only; Google wants Debian-runnable PoC.
- **Impact anchoring:** state attacker privilege → action → capability
  → scale in ≤3 sentences at the top; minimal non-destructive proof
  (one own-account record, `/etc/hostname`, `id`) — never bulk data.
- Repeat submissions to one program compound (HSI: avg bounty rises
  monotonically across a researcher's sequential valids on a target) —
  bundle related findings honestly, don't inflate one-by-one.

## Output contract

After writing the draft, append exactly one line to
`reports/<program>/SUBMIT-CHECKLIST.md`:

```
- [ ] <finding-id> — <class> on <surface> — severity <tier> — evidence ok — repro ok — dedupe clean — pending human submit
```

The skill's job ends at that checklist line. Submission is the human's.
