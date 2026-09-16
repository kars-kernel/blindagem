"""Registration rules and the runner's promise: a check never crashes the audit."""

from __future__ import annotations

import pytest

from blindagem import registry
from blindagem.config import Config
from blindagem.host import Host
from blindagem.models import CheckMeta, CheckResult, Severity, Status
from blindagem.runner import run, run_check


def test_every_check_is_registered_once():
    metas = registry.all_meta()
    ids = [m.id for m in metas]
    assert len(ids) == len(set(ids))
    assert len(ids) >= 25, "the catalog should cover at least 25 checks"


def test_every_check_explains_itself():
    for meta in registry.all_meta():
        assert meta.rationale.strip(), f"{meta.id} has no rationale"
        assert meta.remediation.strip(), f"{meta.id} has no remediation"
        assert meta.title.strip()
        assert meta.id.startswith(f"{_prefix(meta)}."), f"{meta.id} does not match its category"


def _prefix(meta: CheckMeta) -> str:
    aliases = {"permissions": "perms", "network": "net", "filesystem": "fs"}
    return aliases.get(meta.category, meta.category)


def test_duplicate_id_is_refused():
    meta = CheckMeta(
        id="ssh.root_login",
        title="dup",
        category="ssh",
        severity=Severity.LOW,
        rationale="x",
        remediation="y",
    )
    registry.load_all()
    with pytest.raises(ValueError, match="duplicate"):
        registry.check(meta)(lambda host: CheckResult("ssh.root_login", Status.PASS, "x"))


def test_a_raising_check_becomes_an_error(make_host):
    meta = CheckMeta(
        id="test.boom",
        title="boom",
        category="test",
        severity=Severity.LOW,
        rationale="x",
        remediation="y",
    )

    def boom(host: Host) -> CheckResult:
        raise RuntimeError("the parser exploded")

    result = run_check(meta, boom, make_host())
    assert result.status is Status.ERROR
    assert "the parser exploded" in result.message


def test_needs_root_without_root_is_an_error_and_does_not_run(make_host, monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    called = False

    def never(host):  # pragma: no cover - must not be reached
        nonlocal called
        called = True
        return CheckResult("test.root", Status.PASS, "x")

    meta = CheckMeta(
        id="test.root",
        title="needs root",
        category="test",
        severity=Severity.LOW,
        rationale="x",
        remediation="y",
        needs_root=True,
    )
    result = run_check(meta, never, make_host())
    assert result.status is Status.ERROR
    assert "sudo" in result.message
    assert called is False


def test_check_returning_junk_is_an_error(make_host):
    meta = CheckMeta(
        id="test.junk",
        title="junk",
        category="test",
        severity=Severity.LOW,
        rationale="x",
        remediation="y",
    )
    result = run_check(meta, lambda host: "not a result", make_host())
    assert result.status is Status.ERROR


def test_profile_skips_are_applied(make_host):
    report = run(make_host(), Config(profile="container"))
    aslr = next(r for r in report.results if r.check_id == "kernel.aslr")
    assert aslr.status is Status.SKIP
    assert "container" in aslr.message


def test_only_and_category_filters(make_host):
    report = run(make_host(), only=["ssh.root_login"])
    assert [r.check_id for r in report.results] == ["ssh.root_login"]
    report = run(make_host(), categories=["ssh"])
    assert {r.check_id.split(".")[0] for r in report.results} == {"ssh"}


def test_disabled_checks_are_not_run(make_host):
    report = run(make_host(), Config(disabled=["ssh.root_login"]))
    assert "ssh.root_login" not in {r.check_id for r in report.results}
