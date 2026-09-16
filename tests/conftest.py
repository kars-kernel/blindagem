"""Shared fixtures: a throwaway copy of the fake rootfs and a scripted Host."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from blindagem import registry
from blindagem.host import CommandResult, Host
from blindagem.models import CheckResult
from blindagem.runner import run_check

FIXTURE = Path(__file__).parent / "fixtures" / "rootfs"
OUTPUTS = Path(__file__).parent / "fixtures" / "outputs"


@pytest.fixture
def rootfs(tmp_path: Path) -> Path:
    """A fresh copy of the fake rootfs, safe to chmod and edit."""
    root = tmp_path / "root"
    shutil.copytree(FIXTURE, root)
    # Git does not store permissions, so the fixture sets the ones tests rely on.
    (root / "etc/shadow").chmod(0o640)
    (root / "etc/passwd").chmod(0o644)
    (root / "etc/crontab").chmod(0o600)
    (root / "etc/ssh/sshd_config").chmod(0o600)
    return root


@pytest.fixture
def make_host(rootfs):
    """Build a Host over the fake rootfs with a scripted command runner."""

    def _make(
        commands: dict[tuple[str, ...], CommandResult] | None = None, live: bool = True
    ) -> Host:
        commands = commands or {}

        def fake_runner(args, timeout):
            return commands.get(tuple(args))  # an unscripted command behaves as missing

        return Host(str(rootfs), runner=fake_runner, root_is_live=live)

    return _make


@pytest.fixture
def check_result(make_host):
    """Run one check by id and return its result."""

    def _run(check_id: str, host: Host | None = None) -> CheckResult:
        found = registry.get(check_id)
        assert found is not None, f"unknown check {check_id}"
        meta, fn = found
        return run_check(meta, fn, host if host is not None else make_host())

    return _run


def output(name: str) -> str:
    """Read a captured command output from tests/fixtures/outputs."""
    return (OUTPUTS / name).read_text()


def ok(stdout: str = "", returncode: int = 0, stderr: str = "") -> CommandResult:
    return CommandResult(returncode, stdout, stderr)
