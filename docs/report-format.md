# JSON report format (`schema_version` 1.0)

`blindagem audit --json` (or `--output report.json`) writes this. It is the input for
`--compare` and the format to parse in a pipeline.

```jsonc
{
  "schema_version": "1.0",
  "tool": "blindagem",
  "tool_version": "1.0.0",
  "generated_at": "2026-09-16T12:00:00+00:00",   // UTC, ISO 8601
  "profile": "server",                            // server | workstation | container
  "host": {
    "hostname": "web-01",
    "distro": "Debian GNU/Linux 12 (bookworm)",
    "kernel": "6.1.0-23-amd64",
    "family": "debian",                           // debian | rhel | suse | arch | unknown
    "is_root": true,                              // false means reduced coverage
    "root": "/"                                   // or the path given to --root
  },
  "score": 72,
  "band": "good",                                 // excellent | good | attention | critical
  "counts": { "pass": 18, "fail": 6, "warn": 2, "skip": 2, "error": 1 },
  "coverage": { "evaluated": 26, "total": 29, "ratio": 0.897 },
  "categories": { "ssh": { "pass": 4, "fail": 2, "warn": 0, "skip": 0, "error": 0, "total": 6 } },
  "duration_ms": 412.5,
  "results": [
    {
      "check_id": "ssh.root_login",
      "status": "fail",
      "message": "SSH allows direct root login",
      "evidence": ["permitrootlogin yes (from sshd_config)"],
      "duration_ms": 1.2,
      "accepted": false,
      "accepted_reason": null,
      "title": "Root cannot log in over SSH",
      "category": "ssh",
      "severity": "high",                         // low | medium | high | critical
      "rationale": "...",
      "remediation": "...",
      "reference": "CIS Linux Benchmark 5.2 (SSH server configuration)"
    }
  ]
}
```

## Stability

`schema_version` is bumped when a field is removed or changes meaning. New fields can appear
in a minor release, so parsers should ignore what they do not recognise.

## Notes for consumers

- `score` alone is not the whole picture. Read `coverage.ratio` with it: checks that could
  not run are excluded from the score, not counted as passes.
- `accepted: true` means the finding was declared an accepted risk in `blindagem.yaml`. It
  keeps its real `status` and scores as a pass. It never disappears.
- `evidence` is free text meant for a human and must not contain secrets. Do not parse it.
- Exit codes: `0` success, `1` the score is below `--fail-under`, `2` a usage or config error.
