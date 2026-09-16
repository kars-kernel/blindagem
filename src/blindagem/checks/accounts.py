"""Accounts and password policy. Reports names only — never password fields."""

from __future__ import annotations

from ..host import Host
from ..models import CheckMeta, CheckResult, Severity, Status
from ..registry import check
from ._common import parse_kv

CATEGORY = "accounts"


@check(
    CheckMeta(
        id="accounts.extra_uid0",
        title="Only root has UID 0",
        category=CATEGORY,
        severity=Severity.CRITICAL,
        rationale=(
            "The kernel grants full administrator power by user ID, not by name. A second "
            "account with UID 0 is root under another name — a classic backdoor that survives "
            "a root password change and is easy to miss in a user list."
        ),
        remediation=(
            "Confirm what the account is for, then give it a normal UID with 'usermod -u' or "
            "remove it with 'userdel'. Do this by hand: deleting an account is not reversible."
        ),
        reference="CIS Linux Benchmark 6.2 (user and group settings)",
    )
)
def extra_uid0(host: Host) -> CheckResult:
    text = host.read_text("/etc/passwd")
    if text is None:
        return CheckResult("accounts.extra_uid0", Status.ERROR, "/etc/passwd is not readable")
    extra = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) > 2 and fields[2] == "0" and fields[0] != "root":
            extra.append(f"{fields[0]} (UID 0, shell {fields[6] if len(fields) > 6 else '?'})")
    if extra:
        return CheckResult(
            "accounts.extra_uid0", Status.FAIL, "Accounts other than root have UID 0", extra
        )
    return CheckResult("accounts.extra_uid0", Status.PASS, "Only root has UID 0")


@check(
    CheckMeta(
        id="accounts.empty_password",
        title="No account can log in without a password",
        category=CATEGORY,
        severity=Severity.CRITICAL,
        rationale=(
            "An empty password field means the account authenticates with nothing at all. "
            "Combined with any service that accepts local logins, that is an open door."
        ),
        remediation="Set a password with 'passwd <user>' or lock the account with 'passwd -l <user>'.",
        reference="CIS Linux Benchmark 6.2 (user and group settings)",
        needs_root=True,
    )
)
def empty_password(host: Host) -> CheckResult:
    text = host.read_text("/etc/shadow")
    if text is None:
        return CheckResult(
            "accounts.empty_password", Status.ERROR, "/etc/shadow is not readable (run with sudo)"
        )
    empty = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split(":")
        # Report the name only. The hash itself never leaves this function.
        if len(fields) > 1 and fields[1] == "":
            empty.append(f"{fields[0]} has no password set")
    if empty:
        return CheckResult(
            "accounts.empty_password", Status.FAIL, "Accounts with an empty password", empty
        )
    return CheckResult(
        "accounts.empty_password", Status.PASS, "Every account has a password or is locked"
    )


@check(
    CheckMeta(
        id="accounts.pass_max_days",
        title="Passwords expire at least once a year",
        category=CATEGORY,
        severity=Severity.LOW,
        rationale=(
            "A password that never expires stays valid years after the laptop it was typed on "
            "was sold, or after the person who knew it left the company."
        ),
        remediation="Set PASS_MAX_DAYS to 365 or less in /etc/login.defs (applies to new accounts).",
        reference="CIS Linux Benchmark 5.4 (user accounts and environment)",
    )
)
def pass_max_days(host: Host) -> CheckResult:
    if not host.exists("/etc/login.defs"):
        return CheckResult("accounts.pass_max_days", Status.SKIP, "/etc/login.defs does not exist")
    lines = host.read_lines("/etc/login.defs")
    if not lines:
        return CheckResult(
            "accounts.pass_max_days", Status.ERROR, "/etc/login.defs is not readable"
        )
    values = parse_kv([line.replace("\t", " ") for line in lines])
    raw = values.get("PASS_MAX_DAYS")
    if raw is None:
        return CheckResult("accounts.pass_max_days", Status.FAIL, "PASS_MAX_DAYS is not configured")
    try:
        days = int(raw.split()[0])
    except (ValueError, IndexError):
        return CheckResult(
            "accounts.pass_max_days", Status.ERROR, f"PASS_MAX_DAYS is not a number: {raw}"
        )
    if days > 365:
        return CheckResult(
            "accounts.pass_max_days",
            Status.FAIL,
            "Passwords effectively never expire",
            [f"PASS_MAX_DAYS {days}, expected 365 or fewer"],
        )
    return CheckResult("accounts.pass_max_days", Status.PASS, f"PASS_MAX_DAYS is {days}")


@check(
    CheckMeta(
        id="accounts.pw_quality",
        title="Password policy requires at least 12 characters",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        rationale=(
            "Short passwords fall to offline cracking in minutes once a hash leaks. Length is "
            "the single setting that helps most, far more than forcing symbols."
        ),
        remediation="Set 'minlen = 12' in /etc/security/pwquality.conf.",
        reference="CIS Linux Benchmark 5.3 (PAM configuration)",
    )
)
def pw_quality(host: Host) -> CheckResult:
    path = "/etc/security/pwquality.conf"
    files = [path] + [
        str(p.relative_to(host.root)) for p in host.glob("/etc/security/pwquality.conf.d/*.conf")
    ]
    minlen: int | None = None
    if not host.exists(path) and len(files) == 1:
        return CheckResult(
            "accounts.pw_quality",
            Status.FAIL,
            "No password quality policy configured (pwquality is not set up)",
        )
    for candidate in files:
        for raw in host.read_lines("/" + candidate.lstrip("/")):
            line = raw.split("#", 1)[0].strip()
            if not line or "=" not in line:
                continue
            key, _, value = line.partition("=")
            if key.strip() == "minlen":
                try:
                    minlen = int(value.strip())
                except ValueError:
                    return CheckResult(
                        "accounts.pw_quality",
                        Status.ERROR,
                        f"minlen is not a number: {value.strip()}",
                    )
    if minlen is None:
        return CheckResult(
            "accounts.pw_quality", Status.FAIL, "minlen is not set, so short passwords are accepted"
        )
    if minlen < 12:
        return CheckResult(
            "accounts.pw_quality",
            Status.FAIL,
            "Minimum password length is too short",
            [f"minlen {minlen}, expected 12 or more"],
        )
    return CheckResult("accounts.pw_quality", Status.PASS, f"minlen is {minlen}")
