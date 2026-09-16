"""File permission checks."""

from __future__ import annotations

from blindagem.models import Status


def test_shadow_perms_fail(rootfs, check_result):
    (rootfs / "etc/shadow").chmod(0o644)
    assert check_result("perms.shadow").status is Status.FAIL


def test_shadow_perms_pass(rootfs, check_result):
    (rootfs / "etc/shadow").chmod(0o640)
    assert check_result("perms.shadow").status is Status.PASS


def test_shadow_rhel_style_zero_mode_passes(rootfs, check_result):
    (rootfs / "etc/shadow").chmod(0o000)
    assert check_result("perms.shadow").status is Status.PASS


def test_shadow_group_write_fails(rootfs, check_result):
    (rootfs / "etc/shadow").chmod(0o660)
    assert check_result("perms.shadow").status is Status.FAIL


def test_shadow_missing_is_skipped(rootfs, check_result):
    (rootfs / "etc/shadow").unlink()
    assert check_result("perms.shadow").status is Status.SKIP


def test_passwd_perms_pair(rootfs, check_result):
    (rootfs / "etc/passwd").chmod(0o666)
    assert check_result("perms.passwd").status is Status.FAIL
    (rootfs / "etc/passwd").chmod(0o644)
    assert check_result("perms.passwd").status is Status.PASS


def test_crontab_perms_pair(rootfs, check_result):
    (rootfs / "etc/crontab").chmod(0o644)
    assert check_result("perms.crontab").status is Status.FAIL
    (rootfs / "etc/crontab").chmod(0o600)
    assert check_result("perms.crontab").status is Status.PASS


def test_suid_offline_walk_finds_an_unexpected_binary(rootfs, make_host, check_result):
    payload = rootfs / "opt"
    payload.mkdir()
    binary = payload / "backdoor"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o4755)
    result = check_result("perms.suid_unexpected", make_host(live=False))
    assert result.status is Status.WARN
    assert any("backdoor" in line for line in result.evidence)


def test_suid_allowlisted_binary_passes(rootfs, make_host, check_result):
    sudo = rootfs / "usr/bin"
    sudo.mkdir(parents=True)
    (sudo / "sudo").write_text("x")
    (sudo / "sudo").chmod(0o4755)
    assert check_result("perms.suid_unexpected", make_host(live=False)).status is Status.PASS


def test_suid_uses_find_on_a_live_system(make_host, check_result):
    from blindagem.host import CommandResult

    host = make_host(
        {
            ("find", "/", "-xdev", "-type", "f", "-perm", "-4000", "-print"): CommandResult(
                0, "/usr/bin/sudo\n/opt/evil\n", ""
            )
        }
    )
    result = check_result("perms.suid_unexpected", host)
    assert result.status is Status.WARN
    assert result.evidence == ["/opt/evil"]


def test_suid_without_find_is_an_error(make_host, check_result):
    assert check_result("perms.suid_unexpected", make_host()).status is Status.ERROR


def test_world_writable_dir_pair(rootfs, make_host, check_result):
    shared = rootfs / "srv/shared"
    shared.mkdir(parents=True)
    shared.chmod(0o777)
    host = make_host(live=False)
    result = check_result("perms.world_writable_dirs", host)
    assert result.status is Status.FAIL
    assert any("srv/shared" in line for line in result.evidence)

    shared.chmod(0o1777)  # sticky bit
    assert check_result("perms.world_writable_dirs", make_host(live=False)).status is Status.PASS


def test_world_writable_check_respects_sticky_tmp(rootfs, make_host, check_result):
    (rootfs / "tmp").chmod(0o1777)
    assert check_result("perms.world_writable_dirs", make_host(live=False)).status is Status.PASS
