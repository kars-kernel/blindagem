"""Turning results into a 0-100 score, without flattering the system."""

from __future__ import annotations

from .models import SEVERITY_WEIGHT, Report, Severity, Status

#: score >= threshold -> label
BANDS: list[tuple[int, str]] = [
    (90, "excellent"),
    (70, "good"),
    (50, "attention"),
    (0, "critical"),
]

#: A single failing CRITICAL check caps the score here: one account without a
#: password undoes everything else, and an 80 would hide that.
CRITICAL_CAP = 49


def band_for(score: int) -> str:
    for threshold, label in BANDS:
        if score >= threshold:
            return label
    return "critical"  # pragma: no cover - unreachable, BANDS ends at 0


def score_report(report: Report) -> int:
    """Weighted score over the checks that could be evaluated.

    ``skip`` and ``error`` are left out entirely — they are reported as coverage
    instead, so a 95 obtained from three checks cannot pass for a clean system.
    Accepted exceptions count as passes.
    """
    possible = 0
    lost = 0.0
    has_critical_fail = False

    for result in report.results:
        meta = report.meta.get(result.check_id)
        if meta is None or result.status in (Status.SKIP, Status.ERROR):
            continue
        weight = SEVERITY_WEIGHT[meta.severity]
        possible += weight
        if result.accepted:
            continue
        if result.status is Status.FAIL:
            lost += weight
            if meta.severity is Severity.CRITICAL:
                has_critical_fail = True
        elif result.status is Status.WARN:
            lost += weight / 2

    if possible == 0:
        return 100
    score = round(100 * (1 - lost / possible))
    if has_critical_fail:
        score = min(score, CRITICAL_CAP)
    return max(0, min(100, score))


def category_scores(report: Report) -> dict[str, dict[str, int]]:
    """Per-category tallies for the report's summary bars."""
    out: dict[str, dict[str, int]] = {}
    for result in report.results:
        meta = report.meta.get(result.check_id)
        if meta is None:
            continue
        bucket = out.setdefault(meta.category, {s.value: 0 for s in Status} | {"total": 0})
        status = "pass" if result.accepted else result.status.value
        bucket[status] += 1
        bucket["total"] += 1
    return dict(sorted(out.items()))
