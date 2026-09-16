"""JSON output — the format --compare reads back and CI pipelines parse.

Documented in docs/report-format.md. Bump ``schema_version`` on breaking changes.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from ..models import Report, Status
from ..scoring import category_scores


def to_dict(report: Report) -> dict[str, Any]:
    return {
        "schema_version": report.schema_version,
        "tool": "blindagem",
        "tool_version": report.tool_version,
        "generated_at": report.generated_at,
        "profile": report.profile,
        "host": asdict(report.host),
        "score": report.score,
        "band": report.band,
        "counts": report.counts,
        "coverage": {
            "evaluated": report.evaluated,
            "total": len(report.results),
            "ratio": round(report.coverage, 3),
        },
        "categories": category_scores(report),
        "duration_ms": round(report.duration_ms, 1),
        "results": [
            {
                "check_id": result.check_id,
                "status": result.status.value,
                "message": result.message,
                "evidence": result.evidence,
                "duration_ms": round(result.duration_ms, 2),
                "accepted": result.accepted,
                "accepted_reason": result.accepted_reason,
                **(
                    {
                        "title": meta.title,
                        "category": meta.category,
                        "severity": meta.severity.value,
                        "rationale": meta.rationale,
                        "remediation": meta.remediation,
                        "reference": meta.reference,
                    }
                    if (meta := report.meta.get(result.check_id))
                    else {}
                ),
            }
            for result in report.results
        ],
    }


def dumps(report: Report, indent: int = 2) -> str:
    return json.dumps(to_dict(report), indent=indent, ensure_ascii=False)


def compare(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """What changed between two JSON reports."""
    old_results = {r["check_id"]: r for r in old.get("results", [])}
    new_results = {r["check_id"]: r for r in new.get("results", [])}
    bad = {Status.FAIL.value, Status.WARN.value}

    fixed, broken, changed = [], [], []
    for check_id, new_result in new_results.items():
        old_result = old_results.get(check_id)
        if old_result is None:
            continue
        before, after = old_result["status"], new_result["status"]
        if before == after:
            continue
        entry = {
            "check_id": check_id,
            "before": before,
            "after": after,
            "title": new_result.get("title", check_id),
        }
        if before in bad and after == Status.PASS.value:
            fixed.append(entry)
        elif before == Status.PASS.value and after in bad:
            broken.append(entry)
        else:
            changed.append(entry)

    return {
        "score_before": old.get("score"),
        "score_after": new.get("score"),
        "score_delta": (new.get("score") or 0) - (old.get("score") or 0),
        "fixed": fixed,
        "broken": broken,
        "changed": changed,
        "new_checks": sorted(set(new_results) - set(old_results)),
        "removed_checks": sorted(set(old_results) - set(new_results)),
    }
