"""Integration tests against deliberately weak and hardened containers.

These images exist only for testing and are never exposed to a network. Run
them with: pytest -m docker (they need Docker and the two built images).
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.docker

WEAK = "blindagem-weak"
HARDENED = "blindagem-hardened"


def _audit(image: str) -> dict:
    """Run the auditor inside a throwaway container and return its JSON report."""
    if shutil.which("docker") is None:
        pytest.skip("docker is not installed")
    result = subprocess.run(
        ["docker", "run", "--rm", image, "blindagem", "audit", "--json", "--profile", "container"],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip(f"image {image} is not available: {result.stderr.strip()[:200]}")
    return json.loads(result.stdout)


@pytest.fixture(scope="module")
def weak() -> dict:
    return _audit(WEAK)


@pytest.fixture(scope="module")
def hardened() -> dict:
    return _audit(HARDENED)


def status_of(report: dict, check_id: str) -> str:
    return next(r["status"] for r in report["results"] if r["check_id"] == check_id)


@pytest.mark.parametrize("check_id", ["ssh.root_login", "perms.shadow", "accounts.extra_uid0"])
def test_the_weak_container_is_caught(weak: dict, check_id: str):
    assert status_of(weak, check_id) == "fail"


@pytest.mark.parametrize("check_id", ["ssh.root_login", "perms.shadow", "accounts.extra_uid0"])
def test_the_hardened_container_is_clean(hardened: dict, check_id: str):
    assert status_of(hardened, check_id) == "pass"


def test_hardening_raises_the_score(weak: dict, hardened: dict):
    assert hardened["score"] > weak["score"]


def test_the_container_profile_skips_what_cannot_apply(weak: dict):
    # No systemd and a read-only /proc/sys: reporting these as failures would be noise.
    assert status_of(weak, "kernel.aslr") == "skip"
    assert status_of(weak, "net.firewall_active") == "skip"


def test_audit_reports_useful_coverage(weak: dict):
    assert weak["coverage"]["evaluated"] >= 10
