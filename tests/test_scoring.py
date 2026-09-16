"""The score must not flatter a system: coverage and the critical cap."""

from __future__ import annotations

from blindagem.models import CheckMeta, CheckResult, Report, Severity, Status
from blindagem.scoring import CRITICAL_CAP, band_for, category_scores, score_report


def build(*rows: tuple[str, Severity, Status], accepted: dict[str, str] | None = None) -> Report:
    report = Report()
    for check_id, severity, status in rows:
        report.meta[check_id] = CheckMeta(
            id=check_id,
            title=check_id,
            category=check_id.split(".")[0],
            severity=severity,
            rationale="x",
            remediation="y",
        )
        result = CheckResult(check_id, status, "")
        if accepted and check_id in accepted:
            result.accepted_reason = accepted[check_id]
        report.results.append(result)
    return report


def test_everything_passing_is_100():
    assert score_report(build(("a.x", Severity.HIGH, Status.PASS))) == 100


def test_no_applicable_checks_is_100():
    assert score_report(build(("a.x", Severity.HIGH, Status.SKIP))) == 100


def test_weights_follow_severity():
    # one low fail out of low+high: lost 1 of 7
    report = build(("a.low", Severity.LOW, Status.FAIL), ("a.high", Severity.HIGH, Status.PASS))
    assert score_report(report) == round(100 * (1 - 1 / 7))


def test_warn_costs_half_of_a_fail():
    warn = build(("a.high", Severity.HIGH, Status.WARN), ("b.high", Severity.HIGH, Status.PASS))
    fail = build(("a.high", Severity.HIGH, Status.FAIL), ("b.high", Severity.HIGH, Status.PASS))
    assert score_report(warn) == 75
    assert score_report(fail) == 50


def test_skip_and_error_are_left_out_entirely():
    report = build(
        ("a.high", Severity.HIGH, Status.PASS),
        ("b.critical", Severity.CRITICAL, Status.SKIP),
        ("c.critical", Severity.CRITICAL, Status.ERROR),
    )
    assert score_report(report) == 100
    assert report.evaluated == 1
    assert report.coverage == 1 / 3


def test_one_critical_failure_caps_the_score():
    report = build(
        ("a.critical", Severity.CRITICAL, Status.FAIL),
        *[(f"b.{i}", Severity.LOW, Status.PASS) for i in range(50)],
    )
    assert score_report(report) == CRITICAL_CAP


def test_an_accepted_exception_scores_as_a_pass():
    report = build(
        ("a.high", Severity.HIGH, Status.FAIL), accepted={"a.high": "this host is a router"}
    )
    assert score_report(report) == 100


def test_an_accepted_critical_does_not_trigger_the_cap():
    report = build(
        ("a.critical", Severity.CRITICAL, Status.FAIL), accepted={"a.critical": "reviewed"}
    )
    assert score_report(report) == 100


def test_bands():
    assert band_for(100) == "excellent"
    assert band_for(90) == "excellent"
    assert band_for(89) == "good"
    assert band_for(70) == "good"
    assert band_for(69) == "attention"
    assert band_for(50) == "attention"
    assert band_for(49) == "critical"
    assert band_for(0) == "critical"


def test_category_scores_count_accepted_as_pass():
    report = build(("ssh.a", Severity.HIGH, Status.FAIL), accepted={"ssh.a": "reviewed"})
    assert category_scores(report)["ssh"]["pass"] == 1
    assert category_scores(report)["ssh"]["fail"] == 0
