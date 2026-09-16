"""Accounts and password policy."""

from __future__ import annotations

import os

import pytest

from blindagem.models import Status


def test_extra_uid0_fail(rootfs, check_result):
    with (rootfs / "etc/passwd").open("a") as handle:
        handle.write("toor:x:0:0::/root:/bin/sh\n")
    result = check_result("accounts.extra_uid0")
    assert result.status is Status.FAIL
    assert any("toor" in line for line in result.evidence)


def test_extra_uid0_pass(check_result):
    assert check_result("accounts.extra_uid0").status is Status.PASS


def test_extra_uid0_ignores_comments_and_blank_lines(rootfs, check_result):
    with (rootfs / "etc/passwd").open("a") as handle:
        handle.write("\n# toor:x:0:0::/root:/bin/sh\n")
    assert check_result("accounts.extra_uid0").status is Status.PASS


def test_extra_uid0_missing_passwd_is_an_error(rootfs, check_result):
    (rootfs / "etc/passwd").unlink()
    assert check_result("accounts.extra_uid0").status is Status.ERROR


@pytest.mark.skipif(os.geteuid() != 0, reason="needs_root turns this into an error otherwise")
def test_empty_password_pair_as_root(rootfs, check_result):
    (rootfs / "etc/shadow").write_text("root:*:19800:0:99999:7:::\nbob::19800:0:99999:7:::\n")
    result = check_result("accounts.empty_password")
    assert result.status is Status.FAIL
    assert any("bob" in line for line in result.evidence)


def test_empty_password_never_leaks_the_hash(rootfs, check_result, monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0)
    secret = "$6$salt$averysecrethashvalue"
    (rootfs / "etc/shadow").write_text(f"root:{secret}:19800:0:99999:7:::\nbob::1:0:9:7:::\n")
    result = check_result("accounts.empty_password")
    assert result.status is Status.FAIL
    assert secret not in repr(result)


def test_empty_password_pass(check_result, monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0)
    assert check_result("accounts.empty_password").status is Status.PASS


def test_empty_password_without_root_is_an_error(check_result, monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    result = check_result("accounts.empty_password")
    assert result.status is Status.ERROR
    assert "sudo" in result.message


def test_pass_max_days_pair(rootfs, check_result):
    assert check_result("accounts.pass_max_days").status is Status.FAIL  # fixture has 99999
    (rootfs / "etc/login.defs").write_text("PASS_MAX_DAYS\t365\nPASS_MIN_DAYS\t0\n")
    assert check_result("accounts.pass_max_days").status is Status.PASS


def test_pass_max_days_missing_setting_fails(rootfs, check_result):
    (rootfs / "etc/login.defs").write_text("PASS_MIN_DAYS\t0\n")
    assert check_result("accounts.pass_max_days").status is Status.FAIL


def test_pw_quality_pair(rootfs, check_result):
    assert check_result("accounts.pw_quality").status is Status.FAIL  # fixture has minlen 8
    (rootfs / "etc/security/pwquality.conf").write_text("minlen = 14\n")
    assert check_result("accounts.pw_quality").status is Status.PASS


def test_pw_quality_missing_file_fails(rootfs, check_result):
    (rootfs / "etc/security/pwquality.conf").unlink()
    assert check_result("accounts.pw_quality").status is Status.FAIL
