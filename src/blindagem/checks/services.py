"""Services that should not be running, and the ones that should."""

from __future__ import annotations

from ..host import Host
from ..models import CheckMeta, CheckResult, Severity, Status
from ..registry import check

CATEGORY = "services"

LEGACY_UNITS = ("telnet.socket", "rsh.socket", "rlogin.socket", "vsftpd", "tftp.socket", "xinetd")


def _systemd_available(host: Host) -> bool:
    return host.root_is_live and host.which("systemctl") and host.has_systemd()


def _is_active(host: Host, unit: str) -> str | None:
    result = host.run(["systemctl", "is-active", unit])
    return result.stdout.strip() if result else None


@check(
    CheckMeta(
        id="services.legacy",
        title="No legacy remote-access services are running",
        category=CATEGORY,
        severity=Severity.HIGH,
        rationale=(
            "telnet, rsh and tftp predate encryption and authenticate over the wire in clear "
            "text. If one is running, it is almost always a leftover nobody remembers installing."
        ),
        remediation="systemctl disable --now <unit>, and remove the package if it is not needed.",
        reference="CIS Linux Benchmark 2.1 (server services)",
        skip_profiles=("container",),
    )
)
def legacy(host: Host) -> CheckResult:
    check_id = "services.legacy"
    if not _systemd_available(host):
        return CheckResult(check_id, Status.SKIP, "systemd is not available on this system")
    active = []
    for unit in LEGACY_UNITS:
        state = _is_active(host, unit)
        if state == "active":
            active.append(f"{unit} is active")
    if active:
        return CheckResult(
            check_id, Status.FAIL, "Legacy remote-access services are running", active
        )
    return CheckResult(check_id, Status.PASS, "no legacy remote-access service is running")


@check(
    CheckMeta(
        id="services.auditd",
        title="The audit daemon is running",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        rationale=(
            "auditd records who ran what and which files were touched. Without it, after an "
            "incident there is no way to reconstruct what happened — and no evidence either."
        ),
        remediation="Install auditd and enable it: systemctl enable --now auditd.",
        reference="CIS Linux Benchmark 4.1 (system accounting)",
        skip_profiles=("container", "workstation"),
    )
)
def auditd(host: Host) -> CheckResult:
    check_id = "services.auditd"
    if not _systemd_available(host):
        return CheckResult(check_id, Status.SKIP, "systemd is not available on this system")
    state = _is_active(host, "auditd")
    if state is None:
        return CheckResult(check_id, Status.ERROR, "systemctl could not be run")
    if state == "active":
        return CheckResult(check_id, Status.PASS, "auditd is active")
    return CheckResult(
        check_id, Status.FAIL, "auditd is not running", [f"systemctl reports '{state}'"]
    )


@check(
    CheckMeta(
        id="services.fail2ban",
        title="Brute-force protection when passwords are accepted",
        category=CATEGORY,
        severity=Severity.LOW,
        rationale=(
            "If SSH accepts passwords, something has to stop the endless guessing. fail2ban "
            "reads the auth log and blocks an address after a few failures. With key-only "
            "logins it is nice to have; with passwords it is the difference between noise and a breach."
        ),
        remediation="Install fail2ban and enable the sshd jail, or disable password authentication.",
        reference="CIS Linux Benchmark 5.2 (SSH server configuration)",
        skip_profiles=("container",),
    )
)
def fail2ban(host: Host) -> CheckResult:
    from .ssh import _installed, effective_config  # local import avoids a cycle at import time

    check_id = "services.fail2ban"
    if not _systemd_available(host):
        return CheckResult(check_id, Status.SKIP, "systemd is not available on this system")
    state = _is_active(host, "fail2ban")
    if state == "active":
        return CheckResult(check_id, Status.PASS, "fail2ban is active")

    passwords_allowed = False
    if _installed(host):
        values, _ = effective_config(host)
        passwords_allowed = values.get("passwordauthentication", "yes").strip().lower() == "yes"
    if passwords_allowed:
        return CheckResult(
            check_id,
            Status.WARN,
            "SSH accepts passwords and no brute-force protection is running",
            ["fail2ban is not active", "PasswordAuthentication is yes"],
        )
    return CheckResult(
        check_id, Status.PASS, "fail2ban is not running, but SSH does not accept passwords"
    )
