"""File permissions: who can read the password database, who can plant a SUID binary."""

from __future__ import annotations

import os
import stat as stat_module

from ..config import DEFAULT_SUID_ALLOWLIST
from ..host import Host
from ..models import CheckMeta, CheckResult, Severity, Status
from ..registry import check
from ._common import mode_report, perm_check

CATEGORY = "permissions"

#: Directories never worth walking when hunting for SUID binaries.
_SKIP_DIRS = {"/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker", "/mnt", "/media"}


@check(
    CheckMeta(
        id="perms.shadow",
        title="/etc/shadow is not readable by regular users",
        category=CATEGORY,
        severity=Severity.HIGH,
        rationale=(
            "/etc/shadow holds the password hashes. Any user who can read it can copy the file "
            "and crack the hashes offline, at their own pace, with no failed-login alarms."
        ),
        remediation="chown root:shadow /etc/shadow && chmod 640 /etc/shadow (0000 on RHEL).",
        reference="CIS Linux Benchmark 6.1 (system file permissions)",
    )
)
def shadow(host: Host) -> CheckResult:
    if not host.exists("/etc/shadow"):
        return CheckResult("perms.shadow", Status.SKIP, "/etc/shadow does not exist")
    st = host.stat("/etc/shadow")
    if st is None:
        return CheckResult("perms.shadow", Status.ERROR, "/etc/shadow could not be inspected")
    mode = stat_module.S_IMODE(st.st_mode)
    problems = []
    if mode & 0o007:
        problems.append(f"other users have access (mode {mode_report(mode)})")
    if mode & 0o020:
        problems.append(f"the group can write to it (mode {mode_report(mode)})")
    if host.trusts_ownership and st.st_uid != 0:
        problems.append(f"owned by uid {st.st_uid}, expected root")
    if problems:
        return CheckResult("perms.shadow", Status.FAIL, "/etc/shadow is too permissive", problems)
    return CheckResult("perms.shadow", Status.PASS, f"/etc/shadow has mode {mode_report(mode)}")


@check(
    CheckMeta(
        id="perms.passwd",
        title="/etc/passwd is not writable by regular users",
        category=CATEGORY,
        severity=Severity.HIGH,
        rationale=(
            "Everyone needs to read /etc/passwd, but anyone who can write to it can add an "
            "account with UID 0 and become root without touching a single password."
        ),
        remediation="chown root:root /etc/passwd && chmod 644 /etc/passwd",
        reference="CIS Linux Benchmark 6.1 (system file permissions)",
    )
)
def passwd(host: Host) -> CheckResult:
    return perm_check(host, "perms.passwd", "/etc/passwd", max_mode=0o644)


@check(
    CheckMeta(
        id="perms.crontab",
        title="/etc/crontab is restricted to root",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        rationale=(
            "Cron runs its jobs as root. Write access to the crontab is write access to a root "
            "shell that starts on a schedule; read access reveals what the machine does and when."
        ),
        remediation="chown root:root /etc/crontab && chmod 600 /etc/crontab",
        reference="CIS Linux Benchmark 5.1 (cron and at)",
    )
)
def crontab(host: Host) -> CheckResult:
    return perm_check(host, "perms.crontab", "/etc/crontab", max_mode=0o600)


@check(
    CheckMeta(
        id="perms.suid_unexpected",
        title="No unexpected SUID binaries",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        rationale=(
            "A SUID binary runs with the owner's privileges — usually root — no matter who "
            "starts it. One that is not part of the distribution is either a leftover from a "
            "sloppy install or a deliberately planted way back to root."
        ),
        remediation=(
            "Review each file. If it does not need the bit, remove it with 'chmod u-s <file>'. "
            "Do this by hand: some applications genuinely need SUID."
        ),
        reference="CIS Linux Benchmark 6.1 (system file permissions)",
    )
)
def suid_unexpected(host: Host) -> CheckResult:
    found = _find_suid(host)
    if found is None:
        return CheckResult(
            "perms.suid_unexpected",
            Status.ERROR,
            "the filesystem could not be searched for SUID files",
        )
    allowlist = set(DEFAULT_SUID_ALLOWLIST)
    extras = sorted(
        p
        for p in found
        # /usr/bin/foo and /bin/foo are the same file on merged-/usr systems
        if p not in allowlist and p.replace("/bin/", "/usr/bin/", 1) not in allowlist
    )
    if extras:
        shown = extras[:15]
        if len(extras) > len(shown):
            shown.append(f"... and {len(extras) - len(shown)} more")
        return CheckResult(
            "perms.suid_unexpected",
            Status.WARN,
            f"{len(extras)} SUID binaries are not on the expected list",
            shown,
        )
    return CheckResult(
        "perms.suid_unexpected",
        Status.PASS,
        f"all {len(found)} SUID binaries are the expected ones",
    )


def _find_suid(host: Host) -> list[str] | None:
    """SUID files, via find(1) on a live system or os.walk on an offline root."""
    if host.root_is_live:
        result = host.run(
            ["find", "/", "-xdev", "-type", "f", "-perm", "-4000", "-print"], timeout=120
        )
        if result is None:
            return None
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    found: list[str] = []
    root = host.root
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda _: None):
        rel = "/" + os.path.relpath(dirpath, root).lstrip(".").lstrip("/")
        dirnames[:] = [d for d in dirnames if os.path.join(rel, d).rstrip("/") not in _SKIP_DIRS]
        for name in filenames:
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if stat_module.S_ISREG(st.st_mode) and st.st_mode & stat_module.S_ISUID:
                found.append("/" + os.path.relpath(full, root))
    return found


@check(
    CheckMeta(
        id="perms.world_writable_dirs",
        title="World-writable directories have the sticky bit",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        rationale=(
            "In a directory anyone can write to, without the sticky bit any user can delete or "
            "replace another user's files — including swapping a script a root cron job runs."
        ),
        remediation="chmod +t on each directory, or drop the write permission for others.",
        reference="CIS Linux Benchmark 6.1 (system file permissions)",
    )
)
def world_writable_dirs(host: Host) -> CheckResult:
    check_id = "perms.world_writable_dirs"
    if host.root_is_live:
        result = host.run(
            ["find", "/", "-xdev", "-type", "d", "-perm", "-0002", "!", "-perm", "-1000", "-print"],
            timeout=120,
        )
        if result is None:
            return CheckResult(check_id, Status.ERROR, "the filesystem could not be searched")
        bad = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    else:
        bad = []
        for dirpath, dirnames, _ in os.walk(host.root, onerror=lambda _: None):
            rel = "/" + os.path.relpath(dirpath, host.root).lstrip(".").lstrip("/")
            dirnames[:] = [
                d for d in dirnames if os.path.join(rel, d).rstrip("/") not in _SKIP_DIRS
            ]
            try:
                mode = stat_module.S_IMODE(os.lstat(dirpath).st_mode)
            except OSError:
                continue
            if mode & 0o002 and not mode & stat_module.S_ISVTX:
                bad.append("/" + os.path.relpath(dirpath, host.root))
    if bad:
        shown = sorted(bad)[:15]
        return CheckResult(
            check_id,
            Status.FAIL,
            f"{len(bad)} world-writable directories without the sticky bit",
            shown,
        )
    return CheckResult(check_id, Status.PASS, "every world-writable directory has the sticky bit")
