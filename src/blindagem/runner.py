"""Runs the checks and turns whatever happens into an honest result."""

from __future__ import annotations

import time
from datetime import UTC, datetime

from . import __version__, registry
from .config import Config
from .host import Host
from .models import CheckMeta, CheckResult, Report, Status
from .scoring import band_for, score_report


def _error(meta: CheckMeta, message: str) -> CheckResult:
    return CheckResult(meta.id, Status.ERROR, message)


def run_check(meta: CheckMeta, fn, host: Host) -> CheckResult:
    """Run one check, never letting it raise.

    A bug in a single check must not take the whole audit down, so anything
    unexpected becomes ``ERROR`` with the exception text as the message.
    """
    started = time.perf_counter()
    try:
        if meta.needs_root and not host.is_root():
            result = _error(meta, "run with sudo to check this")
        else:
            result = fn(host)
            if not isinstance(result, CheckResult):  # pragma: no cover - defensive
                result = _error(
                    meta, f"check returned {type(result).__name__}, expected CheckResult"
                )
    except Exception as exc:  # deliberate catch-all: a broken check must not abort the run
        result = _error(meta, f"check raised {type(exc).__name__}: {exc}")
    result.duration_ms = (time.perf_counter() - started) * 1000
    return result


def run(
    host: Host,
    config: Config | None = None,
    only: list[str] | None = None,
    categories: list[str] | None = None,
) -> Report:
    """Run the selected checks against ``host`` and build the report."""
    config = config or Config()
    registry.load_all()
    started = time.perf_counter()

    results: list[CheckResult] = []
    meta_used: dict[str, CheckMeta] = {}

    for meta, fn in sorted(registry.REGISTRY.values(), key=lambda item: item[0].id):
        if only and meta.id not in only:
            continue
        if categories and meta.category not in categories:
            continue
        if config.is_disabled(meta.id):
            continue
        meta_used[meta.id] = meta

        if config.profile in meta.skip_profiles:
            results.append(
                CheckResult(
                    meta.id, Status.SKIP, f"not applicable to the '{config.profile}' profile"
                )
            )
            continue

        result = run_check(meta, fn, host)
        reason = config.exception_for(meta.id)
        if reason and result.status in (Status.FAIL, Status.WARN):
            # Accepted risks stay visible in the report, but score as a pass.
            result.accepted_reason = reason
        results.append(result)

    report = Report(
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        tool_version=__version__,
        profile=config.profile,
        host=host.info(),
        results=results,
        meta=meta_used,
        duration_ms=(time.perf_counter() - started) * 1000,
    )
    report.score = score_report(report)
    report.band = band_for(report.score)
    return report
