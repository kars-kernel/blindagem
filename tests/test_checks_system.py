"""Kernel, network, updates, services and filesystem checks."""

from __future__ import annotations

from blindagem.models import Status

from .conftest import ok, output

# ------------------------------------------------------------------- kernel


def test_aslr_pair(rootfs, check_result):
    assert check_result("kernel.aslr").status is Status.PASS  # fixture has 2
    (rootfs / "proc/sys/kernel/randomize_va_space").write_text("0\n")
    assert check_result("kernel.aslr").status is Status.FAIL


def test_dmesg_restrict_pair(rootfs, check_result):
    assert check_result("kernel.dmesg_restrict").status is Status.FAIL  # fixture has 0
    (rootfs / "proc/sys/kernel/dmesg_restrict").write_text("1\n")
    assert check_result("kernel.dmesg_restrict").status is Status.PASS


def test_suid_dumpable_pair(rootfs, check_result):
    assert check_result("kernel.suid_dumpable").status is Status.PASS
    (rootfs / "proc/sys/fs/suid_dumpable").write_text("2\n")
    assert check_result("kernel.suid_dumpable").status is Status.FAIL


def test_sysctl_falls_back_to_config_files_when_proc_is_absent(rootfs, check_result):
    (rootfs / "proc/sys/kernel/randomize_va_space").unlink()
    (rootfs / "etc/sysctl.conf").write_text("kernel.randomize_va_space = 2\n")
    result = check_result("kernel.aslr")
    assert result.status is Status.PASS
    assert "configured" in result.message


def test_sysctl_drop_in_wins_over_sysctl_conf(rootfs, check_result):
    (rootfs / "proc/sys/kernel/randomize_va_space").unlink()
    (rootfs / "etc/sysctl.conf").write_text("kernel.randomize_va_space = 2\n")
    (rootfs / "etc/sysctl.d").mkdir(exist_ok=True)
    (rootfs / "etc/sysctl.d/99-local.conf").write_text("kernel.randomize_va_space = 0\n")
    result = check_result("kernel.aslr")
    assert result.status is Status.FAIL
    assert "not verified in force" in result.message


def test_sysctl_with_no_source_at_all_is_an_error(rootfs, check_result):
    (rootfs / "proc/sys/kernel/randomize_va_space").unlink()
    assert check_result("kernel.aslr").status is Status.ERROR


# ------------------------------------------------------------------ network


def test_firewall_active_with_ufw(make_host, check_result):
    host = make_host({("ufw", "status"): ok(output("ufw-active.txt"))})
    assert check_result("net.firewall_active", host).status is Status.PASS


def test_firewall_inactive_ufw_fails(make_host, check_result):
    host = make_host({("ufw", "status"): ok(output("ufw-inactive.txt"))})
    result = check_result("net.firewall_active", host)
    assert result.status is Status.FAIL
    assert any("inactive" in line for line in result.evidence)


def test_firewall_firewalld_running(make_host, check_result):
    host = make_host({("firewall-cmd", "--state"): ok("running\n")})
    assert check_result("net.firewall_active", host).status is Status.PASS


def test_firewall_nftables_ruleset(make_host, check_result):
    host = make_host({("nft", "list", "ruleset"): ok(output("nft-rules.txt"))})
    assert check_result("net.firewall_active", host).status is Status.PASS


def test_firewall_empty_nftables_is_not_enough(make_host, check_result):
    host = make_host({("nft", "list", "ruleset"): ok(output("nft-empty.txt"))})
    assert check_result("net.firewall_active", host).status is Status.FAIL


def test_firewall_with_no_tool_available_is_an_error(make_host, check_result):
    assert check_result("net.firewall_active", make_host()).status is Status.ERROR


def test_legacy_listeners_pair(make_host, check_result):
    host = make_host({("ss", "-H", "-tuln"): ok(output("ss-legacy.txt"))})
    result = check_result("net.legacy_listeners", host)
    assert result.status is Status.FAIL
    assert len(result.evidence) == 3  # telnet, ftp, tftp

    host = make_host({("ss", "-H", "-tuln"): ok(output("ss-clean.txt"))})
    assert check_result("net.legacy_listeners", host).status is Status.PASS


def test_legacy_listeners_without_ss_is_an_error(make_host, check_result):
    assert check_result("net.legacy_listeners", make_host()).status is Status.ERROR


def test_ip_forward_pair(rootfs, check_result):
    assert check_result("net.ip_forward").status is Status.PASS
    (rootfs / "proc/sys/net/ipv4/ip_forward").write_text("1\n")
    assert check_result("net.ip_forward").status is Status.FAIL


def test_syncookies_pair(rootfs, check_result):
    assert check_result("net.syncookies").status is Status.PASS
    (rootfs / "proc/sys/net/ipv4/tcp_syncookies").write_text("0\n")
    assert check_result("net.syncookies").status is Status.FAIL


def test_accept_redirects_pair(rootfs, check_result):
    assert check_result("net.accept_redirects").status is Status.PASS
    (rootfs / "proc/sys/net/ipv4/conf/all/accept_redirects").write_text("1\n")
    assert check_result("net.accept_redirects").status is Status.FAIL


# ------------------------------------------------------------------ updates


def test_updates_pending_pair(rootfs, make_host, check_result):
    apt_lists = rootfs / "var/lib/apt/lists"
    apt_lists.mkdir(parents=True)
    (apt_lists / "deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages").write_text("")

    host = make_host({("apt", "list", "--upgradable"): ok(output("apt-upgradable.txt"))})
    result = check_result("updates.pending", host)
    assert result.status is Status.FAIL
    assert "libssl3" in result.evidence

    host = make_host({("apt", "list", "--upgradable"): ok(output("apt-clean.txt"))})
    assert check_result("updates.pending", host).status is Status.PASS


def test_updates_pending_on_rhel(rootfs, make_host, check_result):
    (rootfs / "etc/os-release").write_text('ID="fedora"\nVERSION_ID="40"\n')
    host = make_host({("dnf", "--quiet", "check-update"): ok(output("dnf-check-update.txt"), 100)})
    result = check_result("updates.pending", host)
    assert result.status is Status.FAIL
    assert "kernel.x86_64" in result.evidence


def test_updates_pending_on_an_unknown_distro_is_skipped(rootfs, make_host, check_result):
    (rootfs / "etc/os-release").write_text('ID="plan9"\n')
    assert check_result("updates.pending", make_host()).status is Status.SKIP


def test_updates_automatic_pair(rootfs, make_host, check_result):
    scripted = {
        ("dpkg-query", "-W", "-f=${Status}", "unattended-upgrades"): ok("install ok installed")
    }
    (rootfs / "etc/apt/apt.conf.d").mkdir(parents=True)
    (rootfs / "etc/apt/apt.conf.d/20auto-upgrades").write_text(
        'APT::Periodic::Unattended-Upgrade "0";\n'
    )
    assert check_result("updates.automatic", make_host(scripted)).status is Status.FAIL

    (rootfs / "etc/apt/apt.conf.d/20auto-upgrades").write_text(
        'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'
    )
    assert check_result("updates.automatic", make_host(scripted)).status is Status.PASS


def test_updates_automatic_not_installed_fails(make_host, check_result):
    assert check_result("updates.automatic", make_host()).status is Status.FAIL


# ----------------------------------------------------------------- services


def test_services_are_skipped_without_systemd(make_host, check_result):
    for check_id in ("services.legacy", "services.auditd", "services.fail2ban"):
        assert check_result(check_id, make_host()).status is Status.SKIP


def _systemd_host(rootfs, make_host, commands):
    (rootfs / "run/systemd/system").mkdir(parents=True, exist_ok=True)
    (rootfs / "usr/bin").mkdir(parents=True, exist_ok=True)
    (rootfs / "usr/bin/systemctl").write_text("#!/bin/sh\n")
    host = make_host(commands)
    host.which = lambda name: True  # the real which() looks at PATH, not the fixture
    return host


def test_legacy_services_pair(rootfs, make_host, check_result):
    host = _systemd_host(
        rootfs, make_host, {("systemctl", "is-active", "telnet.socket"): ok("active\n")}
    )
    result = check_result("services.legacy", host)
    assert result.status is Status.FAIL
    assert any("telnet" in line for line in result.evidence)

    host = _systemd_host(
        rootfs, make_host, {("systemctl", "is-active", "telnet.socket"): ok("inactive\n", 3)}
    )
    assert check_result("services.legacy", host).status is Status.PASS


def test_auditd_pair(rootfs, make_host, check_result):
    host = _systemd_host(rootfs, make_host, {("systemctl", "is-active", "auditd"): ok("active\n")})
    assert check_result("services.auditd", host).status is Status.PASS

    host = _systemd_host(
        rootfs, make_host, {("systemctl", "is-active", "auditd"): ok("inactive\n", 3)}
    )
    assert check_result("services.auditd", host).status is Status.FAIL


def test_fail2ban_warns_only_when_passwords_are_accepted(rootfs, make_host, check_result):
    (rootfs / "etc/ssh/sshd_config").write_text("PasswordAuthentication yes\n")
    host = _systemd_host(
        rootfs, make_host, {("systemctl", "is-active", "fail2ban"): ok("inactive\n", 3)}
    )
    assert check_result("services.fail2ban", host).status is Status.WARN

    (rootfs / "etc/ssh/sshd_config").write_text("PasswordAuthentication no\n")
    host = _systemd_host(
        rootfs, make_host, {("systemctl", "is-active", "fail2ban"): ok("inactive\n", 3)}
    )
    assert check_result("services.fail2ban", host).status is Status.PASS


# --------------------------------------------------------------- filesystem


def test_tmp_options_from_proc_mounts(rootfs, check_result):
    (rootfs / "proc/mounts").write_text(
        "/dev/sda1 / ext4 rw,relatime 0 0\ntmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\n"
    )
    assert check_result("fs.tmp_options").status is Status.PASS

    (rootfs / "proc/mounts").write_text(
        "/dev/sda1 / ext4 rw,relatime 0 0\ntmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n"
    )
    result = check_result("fs.tmp_options")
    assert result.status is Status.FAIL
    assert any("noexec" in line for line in result.evidence)


def test_tmp_not_a_separate_mount_is_a_warning(rootfs, check_result):
    (rootfs / "proc/mounts").write_text("/dev/sda1 / ext4 rw,relatime 0 0\n")
    assert check_result("fs.tmp_options").status is Status.WARN


def test_tmp_options_fall_back_to_fstab(rootfs, check_result):
    # No /proc/mounts in the fixture, so /etc/fstab is what is left.
    assert check_result("fs.tmp_options").status is Status.FAIL  # fstab lacks noexec


def test_tmp_options_without_any_mount_source_is_an_error(rootfs, check_result):
    (rootfs / "etc/fstab").unlink()
    assert check_result("fs.tmp_options").status is Status.ERROR


def test_updates_pending_without_a_package_list_is_not_a_pass(rootfs, make_host, check_result):
    """An empty apt cache must not read as 'up to date'.

    apt lists nothing upgradable when it has no package list, which is exactly
    what a machine months behind on patches also looks like.
    """
    host = make_host({("apt", "list", "--upgradable"): ok(output("apt-clean.txt"))})
    result = check_result("updates.pending", host)
    assert result.status is Status.ERROR
    assert "apt update" in " ".join(result.evidence)


def test_updates_pending_passes_when_the_list_exists(rootfs, make_host, check_result):
    lists = rootfs / "var/lib/apt/lists"
    lists.mkdir(parents=True)
    (lists / "deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages").write_text("")
    host = make_host({("apt", "list", "--upgradable"): ok(output("apt-clean.txt"))})
    assert check_result("updates.pending", host).status is Status.PASS
