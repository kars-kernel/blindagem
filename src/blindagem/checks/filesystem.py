"""Mount options — what a writable directory is allowed to contain."""

from __future__ import annotations

from ..host import Host
from ..models import CheckMeta, CheckResult, Severity, Status
from ..registry import check

CATEGORY = "filesystem"

REQUIRED_TMP_OPTIONS = ("nodev", "nosuid", "noexec")


@check(
    CheckMeta(
        id="fs.tmp_options",
        title="/tmp is mounted with nodev, nosuid and noexec",
        category=CATEGORY,
        severity=Severity.LOW,
        rationale=(
            "/tmp is writable by everyone, which makes it the usual landing spot for a "
            "downloaded exploit. With noexec the file cannot be run, with nosuid a SUID bit on "
            "it is ignored, and with nodev device files there are inert."
        ),
        remediation=(
            "Give /tmp its own mount (tmpfs or a partition) with nodev,nosuid,noexec in "
            "/etc/fstab. Changing this needs a reboot or a remount, so it is a manual step."
        ),
        reference="CIS Linux Benchmark 1.1 (filesystem configuration)",
        skip_profiles=("container",),
    )
)
def tmp_options(host: Host) -> CheckResult:
    check_id = "fs.tmp_options"
    entries = _mount_entries(host)
    if entries is None:
        return CheckResult(check_id, Status.ERROR, "mount information could not be read")

    options = entries.get("/tmp")
    if options is None:
        return CheckResult(
            check_id,
            Status.WARN,
            "/tmp is not a separate mount, so it inherits the options of /",
            ["a separate /tmp is what makes nodev, nosuid and noexec possible"],
        )
    missing = [opt for opt in REQUIRED_TMP_OPTIONS if opt not in options]
    if missing:
        return CheckResult(
            check_id,
            Status.FAIL,
            "/tmp is missing hardening mount options",
            [f"missing: {', '.join(missing)}", f"current: {', '.join(sorted(options))}"],
        )
    return CheckResult(check_id, Status.PASS, "/tmp is mounted with nodev, nosuid and noexec")


def _mount_entries(host: Host) -> dict[str, set[str]] | None:
    """Mount point -> options, from /proc/mounts live or /etc/fstab offline."""
    lines = host.read_lines("/proc/mounts")
    source_is_proc = bool(lines)
    if not lines:
        lines = host.read_lines("/etc/fstab")
    if not lines:
        return None
    entries: dict[str, set[str]] = {}
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        fields = line.split()
        if len(fields) < 4:
            continue
        mount_point, options = fields[1], fields[3]
        if not source_is_proc and mount_point in entries:
            continue
        entries[mount_point] = {opt.split("=")[0] for opt in options.split(",")}
    return entries
