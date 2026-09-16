"""JSON and HTML output, plus the comparison between two runs."""

from __future__ import annotations

import json

from blindagem.config import Config
from blindagem.report import html_out, json_out
from blindagem.runner import run


def test_json_has_the_documented_shape(make_host):
    data = json.loads(json_out.dumps(run(make_host())))
    assert data["schema_version"] == "1.0"
    assert set(data) >= {"score", "band", "counts", "coverage", "categories", "results", "host"}
    first = data["results"][0]
    assert set(first) >= {"check_id", "status", "message", "severity", "rationale", "remediation"}


def test_json_reports_coverage_not_just_the_score(make_host):
    data = json.loads(json_out.dumps(run(make_host())))
    assert data["coverage"]["total"] == len(data["results"])
    assert 0 <= data["coverage"]["ratio"] <= 1


def test_compare_detects_fixed_and_broken(rootfs, make_host):
    (rootfs / "etc/ssh/sshd_config").write_text("PermitRootLogin no\n")
    old = json_out.to_dict(run(make_host(), only=["ssh.root_login", "accounts.pw_quality"]))
    by_id = {r["check_id"]: r for r in old["results"]}
    assert by_id["ssh.root_login"]["status"] == "pass"
    assert by_id["accounts.pw_quality"]["status"] == "fail"

    new = json.loads(json.dumps(old))
    new["score"] = 90
    for row in new["results"]:  # swap both verdicts
        row["status"] = "fail" if row["check_id"] == "ssh.root_login" else "pass"

    diff = json_out.compare(old, new)
    assert diff["score_delta"] == 90 - old["score"]
    assert [e["check_id"] for e in diff["fixed"]] == ["accounts.pw_quality"]
    assert [e["check_id"] for e in diff["broken"]] == ["ssh.root_login"]


def test_compare_counts_warn_to_fail_as_a_change_not_a_break(make_host):
    old = json_out.to_dict(run(make_host(), only=["ssh.root_login"]))  # fixture warns
    assert old["results"][0]["status"] == "warn"
    new = json.loads(json.dumps(old))
    new["results"][0]["status"] = "fail"
    diff = json_out.compare(old, new)
    assert diff["broken"] == []
    assert diff["changed"][0]["before"], "a warn -> fail move is still reported"


def test_compare_notices_new_checks(make_host):
    old = json_out.to_dict(run(make_host(), only=["ssh.root_login"]))
    new = json_out.to_dict(run(make_host(), only=["ssh.root_login", "ssh.x11_forwarding"]))
    assert json_out.compare(old, new)["new_checks"] == ["ssh.x11_forwarding"]


def test_html_is_self_contained(make_host, tmp_path):
    path = html_out.write(run(make_host()), tmp_path / "report.html")
    text = path.read_text()
    assert text.startswith("<!DOCTYPE html>")
    assert "<style>" in text
    # No external requests: the report has to open from a laptop with no network.
    assert "http://" not in text and "https://" not in text
    assert "src=" not in text


def test_html_escapes_values_from_the_audited_system(rootfs, make_host, tmp_path):
    with (rootfs / "etc/passwd").open("a") as handle:
        handle.write("<script>alert(1)</script>:x:0:0::/root:/bin/sh\n")
    report = run(make_host(), only=["accounts.extra_uid0"])
    text = html_out.render(report)
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text


def test_html_shows_accepted_risks_instead_of_hiding_them(make_host, tmp_path):
    cfg = Config(exceptions={"accounts.pw_quality": "SSO enforces length"})
    report = run(make_host(), cfg, only=["accounts.pw_quality"])
    text = html_out.render(report)
    assert "Accepted risks" in text
    assert "SSO enforces length" in text


def test_report_never_contains_a_password_hash(rootfs, make_host, monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0)
    secret = "$6$abc$SECRETHASHVALUE"
    (rootfs / "etc/shadow").write_text(f"root:{secret}:19800:0:99999:7:::\nbob::1:0:9:7:::\n")
    report = run(make_host())
    assert secret not in json_out.dumps(report)
    assert secret not in html_out.render(report)
