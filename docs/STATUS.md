# Project status

Last updated: 2026-09-16, after the v1.0.0 release.

## Where it stands

The tool is complete and released: 29 checks, scoring with coverage, JSON and HTML reports,
profiles and exceptions, Ansible remediation, offline auditing and a single-file build.
Repository, tag `v1.0.0` and the release with `blindagem.pyz` are published.

Verified locally and in CI:

| Gate | State |
|---|---|
| `ruff check` / `ruff format --check` | passing |
| `mypy src` | passing |
| `pytest -m "not docker"` | 153 passing, 93% coverage |
| `pytest -m docker` (weak / hardened containers) | passing in CI |
| `ansible-lint` on the generated playbook | passing, profile `production` |
| `ansible-playbook --syntax-check` | passing |
| `blindagem.pyz` build and run | passing |
| `tests/e2e/run.sh` | see below |

## Open item: the end-to-end run

The playbook itself applies cleanly in CI (13 tasks ok, 9 changed, 0 failed). What kept
failing was the assertion after it, and both causes turned out to be worth fixing:

1. **A false pass in `updates.pending`** — with an empty apt cache, `apt list --upgradable`
   prints nothing and the check called that "up to date". Fixed: it now returns an error
   saying the package list is missing.
2. **The score cannot rise while a critical finding is manual** — the weak container has an
   extra UID 0 account, which the playbook deliberately refuses to delete, and a failing
   critical check caps the score at 49 on both sides. The assertion was reworked into the two
   steps a real administrator takes: apply the playbook (assert fewer failures, no
   regressions), then do the manual step the report listed (assert the score moves).

Both fixes are committed and pushed. **The CI run that proves the end-to-end job now passes
had not finished when this was written** — check the latest run before trusting the table
above for that row:

```bash
gh run list --branch main --limit 1
gh run view --job <id> --log   # if it is red
```

## To do before showing this to anyone

- [ ] Confirm the end-to-end job is green (above).
- [ ] Record `docs/screenshots/demo.gif` and uncomment the image line in `README.md`
      (instructions in `docs/screenshots/README.md`).
- [ ] Fill the "Before and after" table in both READMEs with the real numbers that
      `bash tests/e2e/run.sh` prints. Do not invent them.
- [ ] Write the "What I learned" section: three to five things that actually surprised you.
      Good candidates from this build: why the first value wins in `sshd_config`, why an
      empty apt cache is a dangerous "pass", and why remediation has to be a separate artifact.
- [ ] Pin the repository on the GitHub profile.

## Things worth being able to explain in an interview

Pick three or four and be able to talk through them without notes — the project opens the
conversation, but this is what convinces:

- Why `PermitRootLogin no` matters: one guessed password instead of a key, and every action
  logged as "root" with no way to tell who did it.
- What a SUID binary is and why an unexpected one is a backdoor.
- What ASLR does and why a fixed memory layout turns a crash into a reliable exploit.
- Why the audit is read-only and remediation is a separate, reviewable playbook.
- Why `skip` and `error` are excluded from the score instead of counting as passes.
