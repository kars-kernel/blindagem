"""SSH checks, including the OpenSSH rule that the first value wins."""

from __future__ import annotations

from blindagem.checks.ssh import effective_config
from blindagem.models import Status


def write_sshd(rootfs, text: str) -> None:
    (rootfs / "etc/ssh/sshd_config").write_text(text)


def write_dropin(rootfs, name: str, text: str) -> None:
    (rootfs / "etc/ssh/sshd_config.d" / name).write_text(text)


def test_root_login_fail(rootfs, check_result):
    write_sshd(rootfs, "PermitRootLogin yes\n")
    assert check_result("ssh.root_login").status is Status.FAIL


def test_root_login_pass(rootfs, check_result):
    write_sshd(rootfs, "PermitRootLogin no\n")
    assert check_result("ssh.root_login").status is Status.PASS


def test_root_login_with_key_only_is_a_warning(rootfs, check_result):
    write_sshd(rootfs, "PermitRootLogin prohibit-password\n")
    assert check_result("ssh.root_login").status is Status.WARN


def test_dropin_beats_the_main_file(rootfs, check_result):
    # Include sits at the top and OpenSSH keeps the first value it sees.
    write_sshd(rootfs, "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n")
    write_dropin(rootfs, "10-hardening.conf", "PermitRootLogin no\n")
    assert check_result("ssh.root_login").status is Status.PASS


def test_main_file_wins_when_it_comes_before_the_include(rootfs, check_result):
    write_sshd(rootfs, "PermitRootLogin yes\nInclude /etc/ssh/sshd_config.d/*.conf\n")
    write_dropin(rootfs, "10-hardening.conf", "PermitRootLogin no\n")
    assert check_result("ssh.root_login").status is Status.FAIL


def test_keywords_are_case_insensitive(rootfs, check_result):
    write_sshd(rootfs, "permitROOTlogin YES\n")
    assert check_result("ssh.root_login").status is Status.FAIL


def test_trailing_comment_is_ignored(rootfs, check_result):
    write_sshd(rootfs, "PermitRootLogin no   # locked down after the incident\n")
    assert check_result("ssh.root_login").status is Status.PASS


def test_settings_after_a_match_block_are_ignored(rootfs, check_result):
    write_sshd(rootfs, "PermitRootLogin no\nMatch User deploy\n    PermitRootLogin yes\n")
    assert check_result("ssh.root_login").status is Status.PASS


def test_missing_config_is_skipped_not_an_exception(rootfs, check_result):
    (rootfs / "etc/ssh/sshd_config").unlink()
    result = check_result("ssh.root_login")
    assert result.status is Status.SKIP


def test_password_auth_pair(rootfs, check_result):
    write_sshd(rootfs, "PasswordAuthentication yes\n")
    assert check_result("ssh.password_auth").status is Status.FAIL
    write_sshd(rootfs, "PasswordAuthentication no\n")
    assert check_result("ssh.password_auth").status is Status.PASS


def test_password_auth_defaults_to_enabled(rootfs, check_result):
    write_sshd(rootfs, "# nothing configured\n")
    assert check_result("ssh.password_auth").status is Status.FAIL


def test_empty_passwords_pair(rootfs, check_result):
    write_sshd(rootfs, "PermitEmptyPasswords yes\n")
    assert check_result("ssh.empty_passwords").status is Status.FAIL
    write_sshd(rootfs, "PermitEmptyPasswords no\n")
    assert check_result("ssh.empty_passwords").status is Status.PASS


def test_max_auth_tries_pair(rootfs, check_result):
    write_sshd(rootfs, "MaxAuthTries 6\n")
    assert check_result("ssh.max_auth_tries").status is Status.FAIL
    write_sshd(rootfs, "MaxAuthTries 4\n")
    assert check_result("ssh.max_auth_tries").status is Status.PASS


def test_max_auth_tries_with_junk_is_an_error(rootfs, check_result):
    write_sshd(rootfs, "MaxAuthTries lots\n")
    assert check_result("ssh.max_auth_tries").status is Status.ERROR


def test_x11_forwarding_pair(rootfs, check_result):
    write_sshd(rootfs, "X11Forwarding yes\n")
    assert check_result("ssh.x11_forwarding").status is Status.FAIL
    write_sshd(rootfs, "X11Forwarding no\n")
    assert check_result("ssh.x11_forwarding").status is Status.PASS


def test_config_perms_pair(rootfs, check_result):
    (rootfs / "etc/ssh/sshd_config").chmod(0o644)
    assert check_result("ssh.config_perms").status is Status.FAIL
    (rootfs / "etc/ssh/sshd_config").chmod(0o600)
    assert check_result("ssh.config_perms").status is Status.PASS


def test_sshd_dash_t_is_preferred_when_root(rootfs, make_host, monkeypatch):
    from blindagem.host import CommandResult

    monkeypatch.setattr("os.geteuid", lambda: 0)
    write_sshd(rootfs, "PermitRootLogin yes\n")
    host = make_host({("/usr/sbin/sshd", "-T"): CommandResult(0, "permitrootlogin no\n", "")})
    values, source = effective_config(host)
    assert source == "sshd -T"
    assert values["permitrootlogin"] == "no"


def test_falls_back_to_files_when_sshd_t_fails(rootfs, make_host, monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0)
    write_sshd(rootfs, "PermitRootLogin yes\n")
    _values, source = effective_config(make_host())  # no command scripted -> None
    assert source == "sshd_config"


def test_include_loop_does_not_hang(rootfs, check_result):
    write_sshd(rootfs, "Include /etc/ssh/sshd_config\nPermitRootLogin no\n")
    assert check_result("ssh.root_login").status is Status.PASS
