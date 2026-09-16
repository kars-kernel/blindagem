"""The command line: exit codes, output formats and the read-only promise."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from blindagem.cli import app

runner = CliRunner()


@pytest.fixture
def audit_args(rootfs):
    return ["audit", "--root", str(rootfs)]


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "blindagem" in result.stdout


def test_audit_prints_a_table(audit_args):
    result = runner.invoke(app, audit_args)
    assert result.exit_code == 0
    assert "/100" in result.stdout
    assert "coverage" in result.stdout


def test_audit_json_is_parseable(audit_args, tmp_path):
    out = tmp_path / "report.json"
    result = runner.invoke(app, [*audit_args, "--output", str(out)])
    assert result.exit_code == 0
    data = json.loads(out.read_text())
    assert data["score"] == data["score"]
    assert len(data["results"]) >= 25


def test_fail_under_gates_a_pipeline(audit_args):
    assert runner.invoke(app, [*audit_args, "--fail-under", "0"]).exit_code == 0
    assert runner.invoke(app, [*audit_args, "--fail-under", "101"]).exit_code == 1


def test_only_filter(audit_args):
    result = runner.invoke(app, [*audit_args, "--only", "ssh.root_login", "--show-passed"])
    assert "ssh.root_login" in result.stdout
    assert "kernel.aslr" not in result.stdout


def test_html_output(audit_args, tmp_path):
    out = tmp_path / "report.html"
    result = runner.invoke(app, [*audit_args, "--html", str(out)])
    assert result.exit_code == 0
    assert out.read_text().startswith("<!DOCTYPE html>")


def test_compare_against_an_older_report(audit_args, tmp_path):
    first = tmp_path / "before.json"
    runner.invoke(app, [*audit_args, "--output", str(first)])
    result = runner.invoke(app, [*audit_args, "--compare", str(first)])
    assert result.exit_code == 0
    assert "Compared with the previous report" in result.stdout


def test_list_checks_markdown_is_a_table():
    result = runner.invoke(app, ["list-checks", "--markdown"])
    assert result.exit_code == 0
    assert result.stdout.startswith("| id | title |")
    assert "`ssh.root_login`" in result.stdout


def test_explain_known_check():
    result = runner.invoke(app, ["explain", "ssh.root_login"])
    assert result.exit_code == 0
    assert "Why it matters" in result.stdout
    assert "How to fix it" in result.stdout


def test_explain_unknown_check():
    result = runner.invoke(app, ["explain", "ssh.no_such_thing"])
    assert result.exit_code == 2


def test_fix_writes_a_playbook(rootfs, tmp_path):
    out = tmp_path / "fix.yml"
    result = runner.invoke(app, ["fix", "--root", str(rootfs), "-o", str(out)])
    assert result.exit_code == 0
    assert "Blindagem remediation" in out.read_text()


def test_fix_can_work_from_a_saved_report(rootfs, tmp_path):
    report = tmp_path / "report.json"
    runner.invoke(app, ["audit", "--root", str(rootfs), "--output", str(report)])
    out = tmp_path / "fix.yml"
    result = runner.invoke(app, ["fix", "--from-json", str(report), "-o", str(out)])
    assert result.exit_code == 0
    assert "tags:" in out.read_text()


def test_bad_profile_is_rejected(audit_args):
    assert runner.invoke(app, [*audit_args, "--profile", "spaceship"]).exit_code == 2


def test_audit_does_not_modify_the_audited_tree(rootfs):
    before = {p: p.stat().st_mtime_ns for p in rootfs.rglob("*") if p.is_file()}
    runner.invoke(app, ["audit", "--root", str(rootfs)])
    after = {p: p.stat().st_mtime_ns for p in rootfs.rglob("*") if p.is_file()}
    assert before == after, "the audit must be read-only"
