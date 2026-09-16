"""Profiles and accepted exceptions."""

from __future__ import annotations

import pytest

from blindagem.config import Config
from blindagem.models import Status
from blindagem.runner import run


def test_defaults_without_a_file():
    cfg = Config.load(None)
    assert cfg.profile == "server"
    assert cfg.exceptions == {}
    assert "/usr/bin/sudo" in cfg.suid_allowlist


def test_load_mapping_style_exceptions(tmp_path):
    path = tmp_path / "blindagem.yaml"
    path.write_text(
        "profile: workstation\n"
        "exceptions:\n"
        "  net.ip_forward: this host routes traffic for the lab network\n"
        "disabled:\n"
        "  - updates.pending\n"
    )
    cfg = Config.load(path)
    assert cfg.profile == "workstation"
    assert cfg.exception_for("net.ip_forward").startswith("this host routes")
    assert cfg.is_disabled("updates.pending")


def test_load_list_style_exceptions(tmp_path):
    path = tmp_path / "blindagem.yaml"
    path.write_text(
        "exceptions:\n  - id: ssh.password_auth\n    reason: jump host for contractors\n"
    )
    assert Config.load(path).exception_for("ssh.password_auth") == "jump host for contractors"


def test_unknown_profile_is_refused(tmp_path):
    path = tmp_path / "blindagem.yaml"
    path.write_text("profile: spaceship\n")
    with pytest.raises(ValueError, match="unknown profile"):
        Config.load(path)


def test_missing_named_file_is_refused(tmp_path):
    with pytest.raises(FileNotFoundError):
        Config.load(tmp_path / "nope.yaml")


def test_cli_profile_overrides_the_file(tmp_path):
    path = tmp_path / "blindagem.yaml"
    path.write_text("profile: workstation\n")
    assert Config.load(path, profile="container").profile == "container"


def test_accepted_failure_stays_visible_in_the_report(rootfs, make_host):
    cfg = Config(exceptions={"accounts.pw_quality": "corporate SSO enforces length"})
    report = run(make_host(), cfg, only=["accounts.pw_quality"])
    result = report.results[0]
    assert result.status is Status.FAIL  # the finding does not disappear
    assert result.accepted is True
    assert report.score == 100  # but it does not cost anything


def test_container_detection(rootfs, make_host):
    host = make_host()
    assert host.is_container() is False
    (rootfs / ".dockerenv").write_text("")
    assert host.is_container() is True
