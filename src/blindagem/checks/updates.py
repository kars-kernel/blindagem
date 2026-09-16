"""Pending security updates and whether they get applied on their own."""

from __future__ import annotations

from ..host import Host
from ..models import CheckMeta, CheckResult, Severity, Status
from ..registry import check

CATEGORY = "updates"


@check(
    CheckMeta(
        id="updates.pending",
        title="No pending package updates",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        rationale=(
            "Most successful attacks use a vulnerability that already had a patch. Every day a "
            "package stays behind is a day the exploit is public and the fix is not installed."
        ),
        remediation="Debian/Ubuntu: apt update && apt upgrade. RHEL/Fedora: dnf upgrade.",
        reference="CIS Linux Benchmark 1.2 (package management)",
    )
)
def pending(host: Host) -> CheckResult:
    check_id = "updates.pending"
    if host.family == "debian":
        result = host.run(["apt", "list", "--upgradable"], timeout=60)
        if result is None:
            return CheckResult(check_id, Status.ERROR, "apt could not be run")
        packages = [
            line.split("/")[0]
            for line in result.stdout.splitlines()
            if "/" in line and not line.startswith("Listing")
        ]
    elif host.family == "rhel":
        result = host.run(["dnf", "--quiet", "check-update"], timeout=120)
        if result is None:
            return CheckResult(check_id, Status.ERROR, "dnf could not be run")
        if result.returncode not in (0, 100):
            return CheckResult(
                check_id, Status.ERROR, f"dnf check-update failed (exit {result.returncode})"
            )
        packages = [
            line.split()[0]
            for line in result.stdout.splitlines()
            if line.strip() and not line.startswith(("Last metadata", "Obsoleting"))
        ]
    else:
        return CheckResult(
            check_id, Status.SKIP, f"no supported package manager for '{host.family}'"
        )

    if packages:
        shown = sorted(packages)[:10]
        if len(packages) > len(shown):
            shown.append(f"... and {len(packages) - len(shown)} more")
        return CheckResult(
            check_id,
            Status.FAIL,
            f"{len(packages)} packages have updates available "
            "(reflects the last package-list refresh)",
            shown,
        )
    return CheckResult(check_id, Status.PASS, "every package is up to date")


@check(
    CheckMeta(
        id="updates.automatic",
        title="Security updates are installed automatically",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        rationale=(
            "Manual patching slips the moment someone is on holiday. Automatic security updates "
            "close the window between a patch being published and it being installed."
        ),
        remediation=(
            "Debian/Ubuntu: install unattended-upgrades and enable it in "
            "/etc/apt/apt.conf.d/20auto-upgrades. RHEL/Fedora: enable dnf-automatic.timer."
        ),
        reference="CIS Linux Benchmark 1.2 (package management)",
    )
)
def automatic(host: Host) -> CheckResult:
    check_id = "updates.automatic"
    if host.family == "debian":
        result = host.run(["dpkg-query", "-W", "-f=${Status}", "unattended-upgrades"])
        installed = bool(
            result and result.returncode == 0 and "install ok installed" in result.stdout
        )
        if not installed and not host.exists("/usr/bin/unattended-upgrade"):
            return CheckResult(check_id, Status.FAIL, "unattended-upgrades is not installed")
        text = host.read_text("/etc/apt/apt.conf.d/20auto-upgrades") or ""
        enabled = any(
            '"1"' in line and "Unattended-Upgrade" in line
            for line in text.splitlines()
            if not line.strip().startswith("//")
        )
        if not enabled:
            return CheckResult(
                check_id,
                Status.FAIL,
                "unattended-upgrades is installed but not enabled",
                ["APT::Periodic::Unattended-Upgrade is not set to 1"],
            )
        return CheckResult(check_id, Status.PASS, "unattended-upgrades is installed and enabled")

    if host.family == "rhel":
        result = host.run(["systemctl", "is-active", "dnf-automatic.timer"])
        if result is None:
            return CheckResult(check_id, Status.ERROR, "systemctl could not be run")
        if result.stdout.strip() == "active":
            return CheckResult(check_id, Status.PASS, "dnf-automatic.timer is active")
        return CheckResult(check_id, Status.FAIL, "dnf-automatic.timer is not active")

    return CheckResult(check_id, Status.SKIP, f"no supported package manager for '{host.family}'")
