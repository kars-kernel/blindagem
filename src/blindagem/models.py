"""Core data types shared by every part of the auditor."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    """Outcome of a single check.

    ``SKIP`` means the check does not apply to this system (firewalld on Debian),
    ``ERROR`` means it could not be evaluated (no root, unreadable file). Neither
    counts as passed or failed when scoring.
    """

    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"
    ERROR = "error"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


#: Weight of each severity when computing the score.
SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 3,
    Severity.HIGH: 6,
    Severity.CRITICAL: 10,
}


@dataclass
class CheckResult:
    """What a check found.

    ``evidence`` holds short, non-sensitive facts ("account `toor` has UID 0").
    Never put password hashes, keys or whole config files here.
    """

    check_id: str
    status: Status
    message: str
    evidence: list[str] = field(default_factory=list)
    duration_ms: float = 0.0
    accepted_reason: str | None = None

    @property
    def accepted(self) -> bool:
        return self.accepted_reason is not None


@dataclass
class CheckMeta:
    """Static description of a check: what it looks at and why it matters."""

    id: str
    title: str
    category: str
    severity: Severity
    rationale: str
    remediation: str
    reference: str = ""
    needs_root: bool = False
    #: Profiles this check does not apply to (e.g. "container" for systemd checks).
    skip_profiles: tuple[str, ...] = ()


@dataclass
class HostInfo:
    hostname: str = ""
    distro: str = ""
    kernel: str = ""
    family: str = "unknown"
    is_root: bool = False
    root: str = "/"


@dataclass
class Report:
    """A full audit: host facts, every result and the score."""

    schema_version: str = "1.0"
    generated_at: str = ""
    tool_version: str = ""
    profile: str = "server"
    host: HostInfo = field(default_factory=HostInfo)
    score: int = 0
    band: str = ""
    results: list[CheckResult] = field(default_factory=list)
    meta: dict[str, CheckMeta] = field(default_factory=dict)
    duration_ms: float = 0.0

    def by_status(self, status: Status) -> list[CheckResult]:
        return [r for r in self.results if r.status is status]

    @property
    def counts(self) -> dict[str, int]:
        return {s.value: len(self.by_status(s)) for s in Status}

    @property
    def evaluated(self) -> int:
        """Checks that produced a usable verdict."""
        return sum(1 for r in self.results if r.status in (Status.PASS, Status.FAIL, Status.WARN))

    @property
    def coverage(self) -> float:
        """Fraction of checks that could actually be evaluated (0.0–1.0)."""
        return self.evaluated / len(self.results) if self.results else 0.0
