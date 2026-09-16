"""SSH daemon configuration — the front door of most servers."""

from __future__ import annotations

from pathlib import Path

from ..host import Host
from ..models import CheckMeta, CheckResult, Severity, Status
from ..registry import check
from ._common import perm_check, strip_comment

CATEGORY = "ssh"


def _parse_file(
    path: Path, host: Host, seen: set[Path], values: dict[str, str], sources: dict[str, str]
) -> None:
    """Collect keyword values from one sshd_config, following Include directives.

    OpenSSH keeps the **first** value it sees for a keyword, and the Include line
    usually sits at the top of the main file — which is why a drop-in in
    sshd_config.d wins over the same keyword below it.
    """
    if path in seen:
        return
    seen.add(path)
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return

    for raw in lines:
        line = strip_comment(raw)
        if not line:
            continue
        keyword, _, value = line.partition(" ") if " " in line else line.partition("=")
        keyword = keyword.strip().lower()
        value = value.strip()
        if keyword == "include":
            for pattern in value.split():
                target = pattern if pattern.startswith("/") else f"/etc/ssh/{pattern}"
                for included in host.glob(target):
                    _parse_file(included, host, seen, values, sources)
            continue
        if keyword == "match":
            # Everything after a Match block is conditional; the plain defaults we
            # care about are the ones above it.
            break
        if keyword and keyword not in values:
            values[keyword] = value
            sources[keyword] = str(path)


def effective_config(host: Host) -> tuple[dict[str, str], str]:
    """Effective sshd settings and where they came from.

    Prefers ``sshd -T`` (resolves Include and Match exactly as the daemon does,
    but needs root); falls back to parsing the files.
    """
    if host.is_root():
        for binary in ("/usr/sbin/sshd", "/sbin/sshd", "sshd"):
            result = host.run([binary, "-T"])
            if result and result.returncode == 0 and result.stdout.strip():
                effective: dict[str, str] = {}
                for line in result.stdout.splitlines():
                    key, _, value = line.partition(" ")
                    key = key.strip().lower()
                    if key and key not in effective:
                        effective[key] = value.strip()
                return effective, "sshd -T"

    values: dict[str, str] = {}
    sources: dict[str, str] = {}
    main = host.path("/etc/ssh/sshd_config")
    _parse_file(main, host, set(), values, sources)
    return values, "sshd_config"


def _installed(host: Host) -> bool:
    return host.exists("/etc/ssh/sshd_config") or bool(host.glob("/etc/ssh/sshd_config.d/*.conf"))


def _setting_check(
    host: Host,
    check_id: str,
    keyword: str,
    *,
    bad_values: tuple[str, ...] = (),
    warn_values: tuple[str, ...] = (),
    fail_message: str = "",
    warn_message: str = "",
    default: str | None = None,
) -> CheckResult:
    if not _installed(host):
        return CheckResult(check_id, Status.SKIP, "no SSH server configuration found")
    values, source = effective_config(host)
    raw = values.get(keyword, default)
    if raw is None:
        return CheckResult(check_id, Status.PASS, f"{keyword} is not set (OpenSSH default is safe)")
    value = raw.strip().lower()
    if value in bad_values:
        return CheckResult(
            check_id, Status.FAIL, fail_message, [f"{keyword} {raw} (from {source})"]
        )
    if value in warn_values:
        return CheckResult(
            check_id, Status.WARN, warn_message, [f"{keyword} {raw} (from {source})"]
        )
    return CheckResult(check_id, Status.PASS, f"{keyword} is {raw}")


@check(
    CheckMeta(
        id="ssh.root_login",
        title="Root cannot log in over SSH",
        category=CATEGORY,
        severity=Severity.HIGH,
        rationale=(
            "With root login enabled, an attacker only has to guess one password to own the "
            "machine, and every action lands in the logs as 'root' with no way to tell who did it. "
            "Admins should log in as themselves and escalate with sudo."
        ),
        remediation=(
            "Set 'PermitRootLogin no' in /etc/ssh/sshd_config.d/10-blindagem.conf, "
            "then reload sshd."
        ),
        reference="CIS Linux Benchmark 5.2 (SSH server configuration)",
    )
)
def root_login(host: Host) -> CheckResult:
    return _setting_check(
        host,
        "ssh.root_login",
        "permitrootlogin",
        bad_values=("yes",),
        warn_values=("prohibit-password", "without-password", "forced-commands-only"),
        fail_message="SSH allows direct root login",
        warn_message="SSH allows root login with a key (no password)",
        default="prohibit-password",
    )


@check(
    CheckMeta(
        id="ssh.password_auth",
        title="SSH requires keys instead of passwords",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        rationale=(
            "Password logins can be brute-forced from anywhere on the internet, and bots try "
            "thousands of them a day. A private key cannot be guessed."
        ),
        remediation="Set 'PasswordAuthentication no' after confirming your key works.",
        reference="CIS Linux Benchmark 5.2 (SSH server configuration)",
    )
)
def password_auth(host: Host) -> CheckResult:
    return _setting_check(
        host,
        "ssh.password_auth",
        "passwordauthentication",
        bad_values=("yes",),
        fail_message="SSH accepts password authentication",
        default="yes",
    )


@check(
    CheckMeta(
        id="ssh.empty_passwords",
        title="SSH rejects accounts with empty passwords",
        category=CATEGORY,
        severity=Severity.CRITICAL,
        rationale=(
            "If an account has no password and the daemon accepts that, anyone who knows the "
            "user name is already inside. There is no scenario where this is acceptable "
            "on a server."
        ),
        remediation="Set 'PermitEmptyPasswords no' and give every account a password or lock it.",
        reference="CIS Linux Benchmark 5.2 (SSH server configuration)",
    )
)
def empty_passwords(host: Host) -> CheckResult:
    return _setting_check(
        host,
        "ssh.empty_passwords",
        "permitemptypasswords",
        bad_values=("yes",),
        fail_message="SSH allows logins with empty passwords",
        default="no",
    )


@check(
    CheckMeta(
        id="ssh.max_auth_tries",
        title="SSH limits authentication attempts per connection",
        category=CATEGORY,
        severity=Severity.LOW,
        rationale=(
            "Each connection allowing many tries multiplies how fast a brute-force attack can go "
            "and buries the useful lines in the auth log."
        ),
        remediation="Set 'MaxAuthTries 4' in the sshd configuration.",
        reference="CIS Linux Benchmark 5.2 (SSH server configuration)",
    )
)
def max_auth_tries(host: Host) -> CheckResult:
    if not _installed(host):
        return CheckResult("ssh.max_auth_tries", Status.SKIP, "no SSH server configuration found")
    values, source = effective_config(host)
    raw = values.get("maxauthtries", "6")
    try:
        tries = int(raw.split()[0])
    except (ValueError, IndexError):
        return CheckResult(
            "ssh.max_auth_tries", Status.ERROR, f"MaxAuthTries is not a number: {raw}"
        )
    if tries > 4:
        return CheckResult(
            "ssh.max_auth_tries",
            Status.FAIL,
            "SSH allows too many authentication attempts per connection",
            [f"MaxAuthTries {tries} (from {source}), expected 4 or fewer"],
        )
    return CheckResult("ssh.max_auth_tries", Status.PASS, f"MaxAuthTries is {tries}")


@check(
    CheckMeta(
        id="ssh.x11_forwarding",
        title="SSH X11 forwarding is disabled",
        category=CATEGORY,
        severity=Severity.LOW,
        rationale=(
            "X11 forwarding opens a channel back into the client's graphical session. A server "
            "that was taken over can use it to read keystrokes on the admin's desktop, and a "
            "headless server has no reason to offer it."
        ),
        remediation="Set 'X11Forwarding no' in the sshd configuration.",
        reference="CIS Linux Benchmark 5.2 (SSH server configuration)",
    )
)
def x11_forwarding(host: Host) -> CheckResult:
    return _setting_check(
        host,
        "ssh.x11_forwarding",
        "x11forwarding",
        bad_values=("yes",),
        fail_message="SSH X11 forwarding is enabled",
        default="no",
    )


@check(
    CheckMeta(
        id="ssh.config_perms",
        title="sshd_config is only writable by root",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        rationale=(
            "If any other user can edit the SSH configuration, they can quietly re-enable root "
            "login or password authentication and hand themselves a permanent way in."
        ),
        remediation="chown root:root /etc/ssh/sshd_config && chmod 600 /etc/ssh/sshd_config",
        reference="CIS Linux Benchmark 5.2 (SSH server configuration)",
    )
)
def config_perms(host: Host) -> CheckResult:
    return perm_check(host, "ssh.config_perms", "/etc/ssh/sshd_config", max_mode=0o600)
