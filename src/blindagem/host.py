"""The only door between the checks and the audited system.

Every check asks the ``Host`` for files and command output instead of touching
the filesystem itself. That buys two things: tests point ``root`` at a fake
rootfs under ``tests/fixtures/``, and the CLI gains ``--root /mnt/image`` to
audit an offline disk image.
"""

from __future__ import annotations

import os
import platform
import shutil
import socket
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .models import HostInfo

#: Environment forced on every command so parsers never see translated output.
C_ENV = {"LC_ALL": "C", "LANG": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class Host:
    def __init__(self, root: str = "/", runner=None, root_is_live: bool | None = None):
        self.root = Path(root)
        self._runner = runner or self._run
        # Commands describe the *running* system, so they are only meaningful when
        # auditing "/" — unless a test says otherwise.
        self.root_is_live = self.root == Path("/") if root_is_live is None else root_is_live
        self._os_release: dict[str, str] | None = None

    # ------------------------------------------------------------------ files

    def path(self, p: str) -> Path:
        return self.root / p.lstrip("/")

    def exists(self, p: str) -> bool:
        return self.path(p).exists()

    def read_text(self, p: str) -> str | None:
        """File contents, or ``None`` if it is missing or unreadable.

        Use :meth:`exists` to tell the two apart: a missing file is often ``skip``
        or ``pass``, an unreadable one is ``error``.
        """
        try:
            return self.path(p).read_text(errors="replace")
        except (FileNotFoundError, NotADirectoryError, IsADirectoryError, PermissionError, OSError):
            return None

    def read_lines(self, p: str) -> list[str]:
        text = self.read_text(p)
        return text.splitlines() if text else []

    def glob(self, pattern: str) -> list[Path]:
        """Glob inside the audited root; the pattern is absolute-ish ('/etc/x/*.conf')."""
        return sorted(self.root.glob(pattern.lstrip("/")))

    def stat(self, p: str) -> os.stat_result | None:
        try:
            return self.path(p).lstat()
        except (FileNotFoundError, NotADirectoryError, PermissionError, OSError):
            return None

    def mode(self, p: str) -> int | None:
        st = self.stat(p)
        return stat.S_IMODE(st.st_mode) if st else None

    def sysctl(self, name: str) -> str | None:
        """Value in force, read straight from /proc/sys (no sysctl binary needed)."""
        return (self.read_text("/proc/sys/" + name.replace(".", "/")) or "").strip() or None

    # --------------------------------------------------------------- identity

    def is_root(self) -> bool:
        return self.root_is_live and os.geteuid() == 0

    @property
    def trusts_ownership(self) -> bool:
        """Whether file ownership in this tree means anything.

        A live system and a properly mounted image keep the original uids, so the
        root directory is owned by root. A rootfs unpacked or checked out by a
        normal user has every file owned by that user, and reporting "owned by
        uid 1000" for all of them would be noise, not a finding.
        """
        st = self.stat("/")
        return st is not None and st.st_uid == 0

    def which(self, name: str) -> bool:
        if self.root_is_live:
            return shutil.which(name) is not None
        return any(self.exists(f"{d}/{name}") for d in ("/usr/sbin", "/usr/bin", "/sbin", "/bin"))

    @property
    def os_release(self) -> dict[str, str]:
        if self._os_release is None:
            data: dict[str, str] = {}
            for line in self.read_lines("/etc/os-release"):
                key, _, value = line.partition("=")
                if _:
                    data[key.strip()] = value.strip().strip('"').strip("'")
            self._os_release = data
        return self._os_release

    @property
    def family(self) -> str:
        """'debian', 'rhel', 'suse', 'arch' or 'unknown' — picks the right commands."""
        ids = [self.os_release.get("ID", "")] + self.os_release.get("ID_LIKE", "").split()
        for name in ids:
            if name in ("debian", "ubuntu"):
                return "debian"
            if name in ("rhel", "fedora", "centos"):
                return "rhel"
            if name in ("suse", "opensuse", "sles"):
                return "suse"
            if name in ("arch", "archlinux"):
                return "arch"
        return "unknown"

    def is_container(self) -> bool:
        """Best-effort container detection, used to suggest the 'container' profile."""
        if self.exists("/.dockerenv") or self.exists("/run/.containerenv"):
            return True
        cgroup = self.read_text("/proc/1/cgroup") or ""
        return any(marker in cgroup for marker in ("docker", "lxc", "containerd", "kubepods"))

    def has_systemd(self) -> bool:
        return self.exists("/run/systemd/system")

    def info(self) -> HostInfo:
        return HostInfo(
            hostname=socket.gethostname() if self.root_is_live else "(offline image)",
            distro=self.os_release.get("PRETTY_NAME", "unknown"),
            kernel=platform.release() if self.root_is_live else "",
            family=self.family,
            is_root=self.is_root(),
            root=str(self.root),
        )

    # ------------------------------------------------------------- subprocess

    def run(self, args: list[str], timeout: int = 20) -> CommandResult | None:
        """Run a command; ``None`` when offline, missing or timed out.

        Always a list of arguments — never a shell string — so nothing read from
        the audited system can be interpreted as a command.
        """
        if not self.root_is_live:
            return None
        return self._runner(args, timeout)

    @staticmethod
    def _run(args: list[str], timeout: int) -> CommandResult | None:
        try:
            p = subprocess.run(
                args, capture_output=True, text=True, timeout=timeout, env=C_ENV, check=False
            )
        except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired, OSError):
            return None
        return CommandResult(p.returncode, p.stdout, p.stderr)
