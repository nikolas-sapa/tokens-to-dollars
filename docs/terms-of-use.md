# Terms of use

tokens-to-dollars is a toolkit for **authorized** security research only.
By using it you agree to the following.

## Authorized testing only

- Only run the tools and skills against assets explicitly in scope of a
  published bug bounty, vulnerability disclosure program, penetration-test
  engagement, or a written authorization you hold. `skills/scope-parser`
  exists to encode that scope — do not bypass it.
- Automated testing against third-party assets without authorization is
  prohibited and may violate computer-misuse law (CFAA, UK CMA, EU
  equivalents) in your jurisdiction.
- The human operator is solely responsible for confirming authorization,
  reading each program's rules of engagement, and making every submission
  decision. The software does not submit reports.

## No warranty

Provided "AS IS" under Apache-2.0 without warranty of any kind. The authors
are not liable for damages, account bans, or legal consequences arising
from use — including use that violates these terms or any platform's rules.

## Platform rules apply

Bug bounty platforms' terms (HackerOne Code of Conduct / hackbots policy,
Bugcrowd researcher agreement, Intigriti/YesWeHack/Immunefi rules) govern
your participation. Where this tool's behavior conflicts with a program
manifest or platform policy, the policy wins — that is a design
requirement, not a limitation.

## Misuse

Do not use this project to probe, exploit, or disrupt systems you do not
own or are not authorized to test; to exfiltrate data; to access accounts
that are not yours (including IDOR validation against real users); or to
remove/loosen the authorization gates, evidence gates, or human-submission
requirements built into the tooling.

If you believe the project is being misused, report it per `SECURITY.md`.
