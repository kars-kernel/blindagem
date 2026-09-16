"""Self-contained HTML report (inline CSS, no external requests)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import SEVERITY_WEIGHT, CheckMeta, CheckResult, Report, Severity, Status
from ..scoring import category_scores

TEMPLATE_DIR = Path(__file__).parent / "templates"

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

BAND_COLOR = {
    "excellent": "#3fb950",
    "good": "#d29922",
    "attention": "#db6d28",
    "critical": "#f85149",
}


@dataclass
class Row:
    """One check as the template sees it."""

    result: CheckResult
    meta: CheckMeta | None
    severity: str
    weight: int
    order: int


def _environment() -> Environment:
    # Autoescaping matters here: file names and account names come from the
    # audited system and must never be able to inject markup.
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml", "j2"], default_for_string=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render(report: Report) -> str:
    rows = []
    for result in report.results:
        meta = report.meta.get(result.check_id)
        rows.append(
            Row(
                result=result,
                meta=meta,
                severity=meta.severity.value if meta else "",
                weight=SEVERITY_WEIGHT[meta.severity] if meta else 0,
                order=SEVERITY_ORDER.get(meta.severity, 9) if meta else 9,
            )
        )

    def bucket(*statuses: Status, accepted: bool | None = None) -> list[Row]:
        items = [
            row
            for row in rows
            if row.result.status in statuses
            and (accepted is None or row.result.accepted is accepted)
        ]
        return sorted(items, key=lambda row: (row.order, row.result.check_id))

    template = _environment().get_template("report.html.j2")
    return template.render(
        report=report,
        failures=bucket(Status.FAIL, Status.WARN, accepted=False),
        accepted=bucket(Status.FAIL, Status.WARN, accepted=True),
        passes=bucket(Status.PASS),
        unknown=bucket(Status.SKIP, Status.ERROR),
        categories=category_scores(report),
        band_color=BAND_COLOR.get(report.band, "#8b949e"),
        coverage_pct=round(report.coverage * 100),
    )


def write(report: Report, path: str | Path) -> Path:
    destination = Path(path)
    destination.write_text(render(report), encoding="utf-8")
    return destination
