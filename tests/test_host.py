"""The Host layer: paths stay inside the audited root, failures return None."""

from __future__ import annotations

import os

from blindagem.host import CommandResult, Host


def test_path_stays_inside_root(rootfs):
    host = Host(str(rootfs))
    assert host.path("/etc/passwd") == rootfs / "etc/passwd"
    assert host.read_text("/etc/passwd").startswith("root:x:0:0")


def test_missing_file_returns_none(make_host):
    assert make_host().read_text("/etc/does-not-exist") is None


def test_unreadable_file_returns_none(rootfs):
    secret = rootfs / "etc/secret"
    secret.write_text("x")
    secret.chmod(0o000)
    host = Host(str(rootfs))
    if os.geteuid() == 0:  # root reads it anyway; the distinction only matters unprivileged
        assert host.read_text("/etc/secret") == "x"
    else:
        assert host.read_text("/etc/secret") is None
        assert host.exists("/etc/secret")  # exists() still tells them apart


def test_family_from_os_release(make_host):
    assert make_host().family == "debian"


def test_family_unknown_without_os_release(tmp_path):
    assert Host(str(tmp_path)).family == "unknown"


def test_sysctl_reads_proc(make_host):
    assert make_host().sysctl("kernel.randomize_va_space") == "2"


def test_run_returns_none_when_offline(make_host):
    host = make_host({("echo", "hi"): CommandResult(0, "hi", "")}, live=False)
    assert host.run(["echo", "hi"]) is None


def test_run_uses_injected_runner(make_host):
    host = make_host({("echo", "hi"): CommandResult(0, "hi", "")})
    assert host.run(["echo", "hi"]).stdout == "hi"


def test_unscripted_command_behaves_as_missing(make_host):
    assert make_host().run(["ufw", "status"]) is None


def test_real_runner_survives_a_missing_binary():
    assert Host("/")._run(["definitely-not-a-real-binary-xyz"], 5) is None


def test_ownership_is_not_trusted_in_a_user_owned_tree(make_host):
    # The fixture is owned by whoever ran the tests, so uids carry no meaning
    # there — unless the tests themselves run as root.
    assert make_host().trusts_ownership is (os.geteuid() == 0)


def test_ownership_is_trusted_on_a_real_root():
    assert Host("/").trusts_ownership is True


def test_info_reports_the_audited_root(make_host):
    info = make_host(live=False).info()
    assert info.hostname == "(offline image)"
    assert info.distro.startswith("Debian")
