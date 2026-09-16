"""The generated playbook: only what failed, and never a lock-out."""

from __future__ import annotations

import yaml

from blindagem.config import Config
from blindagem.remediation import ansible
from blindagem.runner import run


def test_playbook_is_valid_yaml_with_one_play(rootfs, make_host):
    playbook, _automated, _manual = ansible.build(run(make_host()))
    parsed = yaml.safe_load(playbook)
    assert len(parsed) == 1
    assert parsed[0]["hosts"] == "all"
    assert parsed[0]["become"] is True


def test_playbook_only_contains_failing_checks(rootfs, make_host):
    (rootfs / "etc/ssh/sshd_config").write_text("PermitRootLogin yes\nX11Forwarding no\n")
    report = run(make_host(), only=["ssh.root_login", "ssh.x11_forwarding"])
    playbook, automated, _manual = ansible.build(report)
    assert automated == ["ssh.root_login"]
    assert "PermitRootLogin no" in playbook
    assert "X11Forwarding" not in playbook


def test_every_task_carries_its_check_id_and_category_tags(rootfs, make_host):
    report = run(make_host())
    playbook, _automated, _manual = ansible.build(report)
    tasks = yaml.safe_load(playbook)[0]["tasks"]
    tagged = [t for t in tasks if "always" not in t.get("tags", [])]
    assert tagged, "expected at least one remediation task"
    for task in tagged:
        assert len(task["tags"]) >= 2, f"{task['name']} needs both an id and a category tag"


def test_ssh_tasks_validate_the_config_before_writing(rootfs, make_host):
    (rootfs / "etc/ssh/sshd_config").write_text("PermitRootLogin yes\n")
    playbook, _a, _m = ansible.build(run(make_host(), only=["ssh.root_login"]))
    assert "validate: /usr/sbin/sshd -t -f %s" in playbook


def test_lockout_guard_comes_before_the_risky_task(rootfs, make_host):
    (rootfs / "etc/ssh/sshd_config").write_text("PasswordAuthentication yes\n")
    playbook, _a, _m = ansible.build(run(make_host(), only=["ssh.password_auth"]))
    assert playbook.index("Refuse to lock the administrator out") < playbook.index(
        "Require SSH keys instead of passwords"
    )


def test_no_lockout_guard_when_nothing_risky_is_fixed(rootfs, make_host):
    (rootfs / "proc/sys/kernel/randomize_va_space").write_text("0\n")
    playbook, _a, _m = ansible.build(run(make_host(), only=["kernel.aslr"]))
    assert "Refuse to lock the administrator out" not in playbook


def test_risky_manual_fixes_are_listed_but_not_generated(rootfs, make_host):
    with (rootfs / "etc/passwd").open("a") as handle:
        handle.write("toor:x:0:0::/root:/bin/sh\n")
    report = run(make_host(), only=["accounts.extra_uid0"])
    playbook, automated, manual = ansible.build(report)
    assert automated == []
    assert manual == ["accounts.extra_uid0"]
    assert "accounts.extra_uid0" in playbook  # as a comment for the administrator
    assert "userdel" not in playbook.split("tasks:")[1]


def test_upgrading_packages_never_runs_by_accident(rootfs, make_host):
    tasks = yaml.safe_load((ansible.TASKS_DIR / "updates.pending.yml").read_text())
    assert "never" in tasks[0]["tags"]


def test_service_tasks_can_be_skipped_where_there_is_no_systemd(rootfs, make_host):
    playbook, _a, _m = ansible.build(run(make_host()))
    handler = yaml.safe_load(playbook)[0]["handlers"][0]
    assert "skip_service_restart" in handler["when"]


def test_a_clean_system_produces_a_playbook_that_does_nothing(rootfs, make_host):
    report = run(make_host(), Config(profile="container"), only=["ssh.root_login"])
    (rootfs / "etc/ssh/sshd_config").write_text("PermitRootLogin no\n")
    report = run(make_host(), only=["ssh.root_login"])
    playbook, automated, manual = ansible.build(report)
    assert (automated, manual) == ([], [])
    assert yaml.safe_load(playbook)[0]["tasks"][0]["ansible.builtin.debug"]


def test_every_task_file_matches_a_real_check():
    from blindagem import registry

    known = {meta.id for meta in registry.all_meta()}
    assert ansible.available_tasks() <= known


def test_write_also_emits_requirements(rootfs, make_host, tmp_path):
    path, _a, _m = ansible.write(run(make_host()), tmp_path / "fix.yml")
    requirements = yaml.safe_load((path.parent / "requirements.yml").read_text())
    names = {c["name"] for c in requirements["collections"]}
    assert "ansible.posix" in names
