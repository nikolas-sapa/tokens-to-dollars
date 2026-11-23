# Contributing

This repo is an open skill-pack + thin CLI for turning agent token spend
into validated bug bounty reports. Contributions that sharpen the economics
or the validation gates are welcome. Read `docs/responsible-use.md` first —
it describes the rules the repo enforces, and PRs are judged against it.

## What we accept

- **New playbooks** — additions to `skills/hunt/references/playbooks.md`
  format: expanded method, gates touched, evidence rules, and **provenance**
  (who published the technique, where, and how it was corroborated). No
  provenance, no merge — see any PB-n entry for the bar.
- **New platform templates** — `skills/reporter` calibrations for platforms
  we don't cover yet: report skeletons, severity/payout tables, and the
  platform's always-rejected list, cited to public triager guidance.
- **Ingest source additions** — new public, keyless feeds for
  `tools/ingest-scope` (program scope data) or `tools/ingest-knowledge`
  (payout-labeled disclosed reports). Must be fetchable without auth and
  licensed for internal mirroring.
- **Eval results** — runs against `evals/bountybench` or `evals/fprate`
  with the harness doc's methodology: model, token spend, findings, FP
  count. Receipts beat opinions.
- Bug fixes, docs fixes, wrapper adapters for additional well-maintained
  tools (`tools/wrap`), and test coverage anywhere.

## What we don't accept

- **Techniques with no authorized-use framing.** If the writeup doesn't say
  when it's legal to run, it doesn't ship here.
- **Auto-submission tooling.** A human always hits submit — that is a
  platform ToS constraint and a headline feature, not a gap.
- **Gate-removal PRs.** Commits that weaken the manifest gate, scope checks,
  rate caps, dedupe requirements, or validation floors will be closed. If a
  gate is genuinely wrong for a program, the fix lives in that program's
  `roe-manifest.md`, not in the gate.

## Dev setup

- Python 3.9+. **Stdlib only** for everything under `tools/` — no pip
  installs, no third-party imports. If a script needs a dependency, that
  dependency is a wrapped binary under `tools/wrap`, not a Python package.
- No build step. Skills are markdown; tools run with `python3 <script>`.

## Smoke-test expectation

Before opening a PR, run:

```bash
python3 tools/bootstrap.py
python3 tools/ledger/ledger.py --ledger memory/ledger.md
python3 tools/wrap/wrap.py subfinder -d example.com -- --manifest <a test manifest>
```

The last command exits 127 on a machine without subfinder — that is the
expected path (missing binary is reported cleanly). CI
(`.github/workflows/smoke.yml`) runs the same checks.

## PR checklist

- [ ] No private context: no program names, targets, findings, keys, or
  paths from your own engagements. Public examples only.
- [ ] No emojis in files or commit messages.
- [ ] Cross-references between repo files are relative paths
  (`skills/scope-parser/SKILL.md`), never absolute URLs or machine paths.
- [ ] `tools/` changes are Python 3.9+ stdlib-only and fail soft per-source.
- [ ] Markdown additions match the house style: compact, tables over prose,
  headers sentence-cased the same way as neighbors.
- [ ] New techniques carry provenance and an authorized-testing framing line.
- [ ] Skills diffs get reviewed like code — see SECURITY.md on skills as an
  attack surface.

## Reporting security issues

Security problems in this tooling itself: disclose privately first —
see `SECURITY.md`. Bugs in bounty targets belong to the program, not to us.
