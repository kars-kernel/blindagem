"""Profiles and accepted exceptions (blindagem.yaml)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

#: Where the CLI looks for a config file when none is given.
DEFAULT_PATHS = ("blindagem.yaml", "blindagem.yml", "/etc/blindagem.yaml")

PROFILES = ("server", "workstation", "container")

#: SUID binaries that ship with a normal distribution and are not, by themselves,
#: a finding. Users extend this in blindagem.yaml.
DEFAULT_SUID_ALLOWLIST = [
    "/usr/bin/su",
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/gpasswd",
    "/usr/bin/newgrp",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/pkexec",
    "/usr/bin/fusermount",
    "/usr/bin/fusermount3",
    "/usr/bin/ntfs-3g",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
    "/usr/libexec/openssh/ssh-keysign",
    "/usr/sbin/unix_chkpwd",
    "/usr/sbin/pam_timestamp_check",
    "/usr/bin/at",
    "/usr/bin/crontab",
]


@dataclass
class Config:
    """Runtime configuration: which profile, what was accepted, what was tuned."""

    profile: str = "server"
    #: check id -> justification, shown in the report as an accepted risk
    exceptions: dict[str, str] = field(default_factory=dict)
    #: check ids that are not run at all
    disabled: list[str] = field(default_factory=list)
    suid_allowlist: list[str] = field(default_factory=lambda: list(DEFAULT_SUID_ALLOWLIST))
    settings: dict[str, Any] = field(default_factory=dict)
    source: str | None = None

    # ------------------------------------------------------------------ query

    def exception_for(self, check_id: str) -> str | None:
        return self.exceptions.get(check_id)

    def is_disabled(self, check_id: str) -> bool:
        return check_id in self.disabled

    def setting(self, key: str, default: Any = None) -> Any:
        return self.settings.get(key, default)

    # ------------------------------------------------------------------ load

    @classmethod
    def load(cls, path: str | Path | None = None, profile: str | None = None) -> Config:
        """Read a config file, falling back to the defaults when there is none."""
        data: dict[str, Any] = {}
        used: str | None = None
        candidates = [path] if path else list(DEFAULT_PATHS)
        for candidate in candidates:
            if candidate and Path(candidate).is_file():
                loaded = yaml.safe_load(Path(candidate).read_text()) or {}
                if not isinstance(loaded, dict):
                    raise ValueError(f"{candidate}: expected a mapping at the top level")
                data = loaded
                used = str(candidate)
                break
        else:
            if path:
                raise FileNotFoundError(f"config file not found: {path}")

        exceptions: dict[str, str] = {}
        raw_exceptions = data.get("exceptions") or {}
        if isinstance(raw_exceptions, dict):
            exceptions = {str(k): str(v) for k, v in raw_exceptions.items()}
        elif isinstance(raw_exceptions, list):
            # also accept: - id: ssh.root_login / reason: ...
            for item in raw_exceptions:
                if isinstance(item, dict) and "id" in item:
                    exceptions[str(item["id"])] = str(item.get("reason", "accepted"))

        cfg = cls(
            profile=profile or str(data.get("profile", "server")),
            exceptions=exceptions,
            disabled=[str(x) for x in (data.get("disabled") or [])],
            suid_allowlist=[str(x) for x in (data.get("suid_allowlist") or DEFAULT_SUID_ALLOWLIST)],
            settings=dict(data.get("settings") or {}),
            source=used,
        )
        if cfg.profile not in PROFILES:
            raise ValueError(
                f"unknown profile '{cfg.profile}' (expected one of {', '.join(PROFILES)})"
            )
        return cfg
