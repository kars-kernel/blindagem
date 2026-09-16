"""Small helpers shared by the check modules."""

from __future__ import annotations

import stat as stat_module

from ..host import Host
from ..models import CheckResult, Status


def strip_comment(line: str) -> str:
    """Drop everything after '#' and surrounding whitespace."""
    return line.split("#", 1)[0].strip()


def parse_kv(lines: list[str], sep: str | None = None) -> dict[str, str]:
    """Parse 'KEY value' or 'KEY = value' config lines into a dict (last one wins)."""
    out: dict[str, str] = {}
    for raw in lines:
        line = strip_comment(raw)
        if not line:
            continue
        key, _, value = line.partition(sep) if sep else line.partition(" ")
        key = key.strip()
        if not key:
            continue
        out[key] = value.strip()
    return out


def mode_report(mode: int) -> str:
    return f"{mode:04o}"


def perm_check(
    host: Host,
    check_id: str,
    path: str,
    *,
    max_mode: int,
    owner_uid: int | None = 0,
    allowed_group_owners: tuple[int, ...] | None = None,
    missing_status: Status = Status.SKIP,
) -> CheckResult:
    """Shared body for 'this file must not be too open' checks."""
    if not host.exists(path):
        return CheckResult(check_id, missing_status, f"{path} does not exist")
    st = host.stat(path)
    if st is None:
        return CheckResult(check_id, Status.ERROR, f"{path} is not readable (run with sudo)")

    mode = stat_module.S_IMODE(st.st_mode)
    problems: list[str] = []
    if mode & ~max_mode:
        problems.append(f"mode is {mode_report(mode)}, expected at most {mode_report(max_mode)}")
    if host.trusts_ownership:
        if owner_uid is not None and st.st_uid != owner_uid:
            problems.append(f"owned by uid {st.st_uid}, expected {owner_uid}")
        if allowed_group_owners is not None and st.st_gid not in allowed_group_owners:
            problems.append(f"group is gid {st.st_gid}, expected one of {allowed_group_owners}")

    if problems:
        return CheckResult(check_id, Status.FAIL, f"{path} is too permissive", problems)
    return CheckResult(check_id, Status.PASS, f"{path} has mode {mode_report(mode)}")


def sysctl_check(
    host: Host,
    check_id: str,
    name: str,
    expected: str,
    *,
    fail_message: str,
    status_on_mismatch: Status = Status.FAIL,
) -> CheckResult:
    """Compare a kernel parameter in force with its expected value.

    Offline (``--root``) there is no /proc, so the configured value from
    /etc/sysctl.conf and /etc/sysctl.d is used and the message says "configured"
    rather than "in force".
    """
    value = host.sysctl(name)
    if value is not None:
        current = value.split()[0] if value.split() else value
        if current == expected:
            return CheckResult(check_id, Status.PASS, f"{name} = {current}")
        return CheckResult(
            check_id,
            status_on_mismatch,
            fail_message,
            [f"{name} = {current} (expected {expected})"],
        )

    configured = sysctl_configured(host, name)
    if configured is None:
        return CheckResult(
            check_id, Status.ERROR, f"{name} could not be read (no /proc and no sysctl config)"
        )
    if configured == expected:
        return CheckResult(check_id, Status.PASS, f"{name} is configured as {configured}")
    return CheckResult(
        check_id,
        status_on_mismatch,
        fail_message + " (configured value, not verified in force)",
        [f"{name} = {configured} configured (expected {expected})"],
    )


def sysctl_configured(host: Host, name: str) -> str | None:
    """Last value set for ``name`` across sysctl.conf and the sysctl.d drop-ins."""
    files = [host.path("/etc/sysctl.conf")]
    for directory in ("/etc/sysctl.d", "/run/sysctl.d", "/usr/lib/sysctl.d"):
        files.extend(p for p in host.glob(f"{directory}/*.conf"))
    value: str | None = None
    for path in files:
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for raw in lines:
            line = strip_comment(raw)
            if not line or "=" not in line:
                continue
            key, _, val = line.partition("=")
            if key.strip() == name:
                value = val.strip()
    return value
