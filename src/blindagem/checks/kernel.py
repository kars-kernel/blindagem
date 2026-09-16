"""Kernel parameters that make exploitation harder."""

from __future__ import annotations

from ..host import Host
from ..models import CheckMeta, CheckResult, Severity
from ..registry import check
from ._common import sysctl_check

CATEGORY = "kernel"


@check(
    CheckMeta(
        id="kernel.aslr",
        title="Address space layout randomisation is fully enabled",
        category=CATEGORY,
        severity=Severity.HIGH,
        rationale=(
            "ASLR shuffles where a program's code and data land in memory on every start. "
            "Without it, the addresses an exploit needs are the same on every run, which turns "
            "a crash bug into a reliable remote shell."
        ),
        remediation="Set kernel.randomize_va_space = 2 in /etc/sysctl.d/60-blindagem.conf.",
        reference="CIS Linux Benchmark 1.5 (additional process hardening)",
        skip_profiles=("container",),
    )
)
def aslr(host: Host) -> CheckResult:
    return sysctl_check(
        host,
        "kernel.aslr",
        "kernel.randomize_va_space",
        "2",
        fail_message="Memory layout randomisation is not fully enabled",
    )


@check(
    CheckMeta(
        id="kernel.suid_dumpable",
        title="SUID programs do not write core dumps",
        category=CATEGORY,
        severity=Severity.LOW,
        rationale=(
            "A core dump from a privileged program is a copy of its memory, which can hold "
            "passwords or keys, written to disk where a normal user may reach it."
        ),
        remediation="Set fs.suid_dumpable = 0 in /etc/sysctl.d/60-blindagem.conf.",
        reference="CIS Linux Benchmark 1.5 (additional process hardening)",
        skip_profiles=("container",),
    )
)
def suid_dumpable(host: Host) -> CheckResult:
    return sysctl_check(
        host,
        "kernel.suid_dumpable",
        "fs.suid_dumpable",
        "0",
        fail_message="SUID programs are allowed to write core dumps",
    )


@check(
    CheckMeta(
        id="kernel.dmesg_restrict",
        title="Kernel log is restricted to root",
        category=CATEGORY,
        severity=Severity.LOW,
        rationale=(
            "The kernel ring buffer leaks memory addresses and hardware details that help an "
            "attacker who already has a normal shell aim a local privilege-escalation exploit."
        ),
        remediation="Set kernel.dmesg_restrict = 1 in /etc/sysctl.d/60-blindagem.conf.",
        reference="CIS Linux Benchmark 1.5 (additional process hardening)",
        skip_profiles=("container",),
    )
)
def dmesg_restrict(host: Host) -> CheckResult:
    return sysctl_check(
        host,
        "kernel.dmesg_restrict",
        "kernel.dmesg_restrict",
        "1",
        fail_message="Any user can read the kernel log",
    )
