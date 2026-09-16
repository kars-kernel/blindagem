# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/1.1.0/) and the project
uses [semantic versioning](https://semver.org/).

## [1.0.0] — 2026-09-16

First complete release: audit, report, remediate.

### Added

- **Audit engine.** A `Host` layer with a configurable root, a plugin registry, and a runner
  that converts an exception inside a check into an `error` result instead of aborting the
  audit. `needs_root` checks return `error` with a clear message when run unprivileged.
- **29 checks** in eight categories: SSH, accounts, permissions, network, kernel, updates,
  services and mount options. Each one carries its own rationale and remediation text, with
  the CIS recommendation number as a reference only.
- **Scoring** weighted by severity, where `skip` and `error` are excluded and reported as
  coverage instead of counting as passes, and any failing `critical` check caps the score at 49.
- **Reports**: a JSON document (`schema_version` 1.0, documented in `docs/report-format.md`)
  and a self-contained HTML report with no external requests.
- **`--compare old.json`** showing what was fixed, what regressed and how the score moved.
- **`--fail-under N`** exiting non-zero, so the tool works as a pipeline gate.
- **Profiles and accepted exceptions** in `blindagem.yaml`. An accepted finding keeps its real
  status in the report along with its justification, and scores as a pass.
- **`blindagem fix`** generating an Ansible playbook from the failures only, each task tagged
  with its check id and its category, with guards that refuse to lock the administrator out
  and `sshd -t` validation on every SSH change.
- **Offline auditing** with `--root /mnt/image`, and a single-file `blindagem.pyz` build.
- **Tests**: 148 unit tests against a fake rootfs, integration tests against deliberately weak
  and hardened containers, and an end-to-end job that applies the generated playbook and
  asserts the score improved.

### Security

- The audit is read-only; a test asserts the audited tree is unchanged byte for byte.
- Reports name accounts and files, never password hashes, keys or file contents; a test
  asserts no hash reaches either output format.
