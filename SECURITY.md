# Security Policy

## Reporting a vulnerability in this repo

If you find a security issue in the tooling itself (scripts, skills,
adapters), please do not open a public issue. Report privately via GitHub's
private vulnerability reporting ("Security" tab → "Report a vulnerability").

We practice what we ship: reports with a working repro get read first.

## Scope

In scope: `tools/` scripts, `skills/` instruction files (yes, skills can have
vulnerabilities — see `skills/injection-defense`), CI workflows.

Out of scope: third-party corpora ingested by the tools (report upstream),
bugs in bounty targets themselves (report to the program, obviously).

## A note on skills as an attack surface

Instruction files are executable content for agents. Treat any modification
to `skills/` the way you'd treat a code change — review diffs, especially in
rules, gates, and scope handling. A relaxed gate in a skill file is a
security regression with the blast radius of every hunt run against it.
