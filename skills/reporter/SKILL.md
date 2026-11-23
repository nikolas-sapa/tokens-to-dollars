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
8. **Scope citation** — the manifest line covering asset + bug class.

Draft markdown skeleton (fill, don't restructure):

```markdown
# [Bug class] on <asset> allows <impact>

## Summary
<what> in <where> lets <attacker> do <action>, causing <loss> for <victim>.

## Severity
<tier> — per program severity table: "<cited tier line>".
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
- evidence/<finding-id>/poc.<ext>
- evidence/<finding-id>/notes.md

## Remediation
<concrete fix: check X before Y, rate-limit Z, validate bound on N>

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

## Steps-to-reproduce rules

- Every request is pasted verbatim from `evidence/<finding-id>/request.txt`.
  If the triager can't paste it, it isn't a step.
- Name the test account and role used. Never real user data.
- Core trigger lands in the first 3 steps; setup and cleanup go last.
- If the PoC needs a script or HTML file, inline it and reference `poc.*`.
- A video PoC is a supplement, never a replacement: <=2 minutes, stored
  under `evidence/<finding-id>/`, and the report must still repro from
  the written steps alone.
- End with the observable result: what the triager sees that proves the bug.

## Impact statement formula

`Attacker` (who, and the access they need) → `action` (what they can do
that they should not) → `victim` (who pays) → `loss` (quantified: records
exposed, funds at risk, privilege gained). Assert only what your evidence
demonstrates. "Could potentially" is a banned phrase.

## Per-platform calibration

| Platform | Severity model | Title convention | Required extras | Watch out for |
|---|---|---|---|---|
| HackerOne | Program's own severity table; weakness dropdown must match report class | `[Class] on <host> allows <impact>` | Weakness (CWE) field, impact text box | Severity inflation is the #1 credibility killer with H1 triage |
| Bugcrowd | VRT — cite the VRT node and resulting P-level | Same as H1 | VRT category, target picker, CVSS if asked | Wrong VRT node = bounce before technical review |
| Intigriti | Program severity table, CVSS fallback | `[asset] - [vuln] - /endpoint` | Endpoint + weakness fields, researcher notes | Programs here run lean triage; sloppy repro = instant N/A. Validate the PoC on a fresh account / clean instance before drafting |
| YesWeHack | CVSS score + vector required in the form | Same as H1, French accepted on FR programs | CVSS base + vector string, CWE | Form blocks submission without a valid vector |
| Immunefi | Impact tiers priced in USD of funds at risk | `[Contract/function] <class> leads to <fund impact>` | Fork-test PoC at pinned block, decoded tx trace, funds-at-risk math, chain + block stated | "Theoretical" impact tiers are rejected; price from on-chain state, show the math |

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

## Quality gate — 9 questions

A draft may only be written after all nine pass. Any fail routes the
finding back to validation, not to prose workarounds.

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
- Immunefi severity = USD at risk. Price from on-chain state at a stated
  block, show the arithmetic, distinguish direct theft from griefing /
  unclaimed-yield classes — they map to different tiers.
- One finding per report. Chained bugs file as one finding only when every
  link is needed for the impact; otherwise split.
- Match program language (English default; French on FR YesWeHack scopes).

## Output contract

After writing the draft, append exactly one line to
`reports/<program>/SUBMIT-CHECKLIST.md`:

```
- [ ] <finding-id> — <class> on <surface> — severity <tier> — evidence ok — dedupe clean — pending human submit
```

The skill's job ends at that checklist line. Submission is the human's.
