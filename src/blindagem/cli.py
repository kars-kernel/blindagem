"""Command line interface: audit, list-checks, explain, fix."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__, registry, runner
from .config import Config
from .host import Host
from .models import Report, Severity, Status
from .remediation import ansible
from .report import html_out, json_out

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Read-only hardening auditor for Linux servers. The audit never changes anything.",
)
console = Console()
err_console = Console(stderr=True)

STATUS_STYLE = {
    Status.PASS: "green",
    Status.FAIL: "bold red",
    Status.WARN: "yellow",
    Status.SKIP: "dim",
    Status.ERROR: "magenta",
}
SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "dim",
}
BAND_STYLE = {
    "excellent": "bold green",
    "good": "yellow",
    "attention": "bold yellow",
    "critical": "bold red",
}


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"blindagem {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """blindagem — audit, explain, fix."""


def _load_config(config_path: str | None, profile: str | None, host: Host) -> Config:
    try:
        cfg = Config.load(config_path, profile)
    except (ValueError, FileNotFoundError) as exc:
        err_console.print(f"[red]configuration error:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    if profile is None and cfg.profile == "server" and host.is_container():
        err_console.print(
            "[yellow]note:[/yellow] this looks like a container — "
            "consider --profile container to skip checks that cannot apply here."
        )
    return cfg


def _run_audit(
    root: str,
    config_path: str | None,
    profile: str | None,
    only: str | None,
    category: str | None,
) -> tuple[Report, Config]:
    host = Host(root)
    cfg = _load_config(config_path, profile, host)
    report = runner.run(
        host,
        cfg,
        only=[c.strip() for c in only.split(",")] if only else None,
        categories=[c.strip() for c in category.split(",")] if category else None,
    )
    return report, cfg


@app.command()
def audit(
    root: str = typer.Option("/", "--root", help="Audit this root instead of / (offline image)."),
    profile: str | None = typer.Option(None, "--profile", help="server, workstation or container."),
    config: str | None = typer.Option(None, "--config", "-c", help="Path to blindagem.yaml."),
    only: str | None = typer.Option(None, "--only", help="Comma-separated check ids."),
    category: str | None = typer.Option(None, "--category", help="Comma-separated categories."),
    as_json: bool = typer.Option(False, "--json", help="Print the JSON report instead of a table."),
    html: str | None = typer.Option(
        None, "--html", help="Also write a self-contained HTML report."
    ),
    output: str | None = typer.Option(
        None, "--output", "-o", help="Write the JSON report to a file."
    ),
    fail_under: int | None = typer.Option(
        None, "--fail-under", help="Exit with code 1 when the score is below this (for CI)."
    ),
    compare: str | None = typer.Option(
        None, "--compare", help="Compare against an older JSON report."
    ),
    show_passed: bool = typer.Option(
        False, "--show-passed", help="Include passing checks in the table."
    ),
) -> None:
    """Audit the system and report what is weak. Reads only; changes nothing."""
    report, _cfg = _run_audit(root, config, profile, only, category)

    if output:
        Path(output).write_text(json_out.dumps(report), encoding="utf-8")
    if html:
        html_out.write(report, html)

    if as_json:
        console.print_json(json_out.dumps(report))
    else:
        _print_report(report, show_passed=show_passed)
        if html:
            console.print(f"HTML report written to [bold]{html}[/bold]")
        if output:
            console.print(f"JSON report written to [bold]{output}[/bold]")

    if compare:
        _print_comparison(json.loads(Path(compare).read_text()), json_out.to_dict(report))

    if fail_under is not None and report.score < fail_under:
        err_console.print(f"[red]score {report.score} is below the required {fail_under}[/red]")
        raise typer.Exit(code=1)


def _print_report(report: Report, show_passed: bool = False) -> None:
    band_style = BAND_STYLE.get(report.band, "white")
    header = Text.assemble(
        (f"{report.score}/100", band_style),
        ("  "),
        (report.band.upper(), band_style),
    )
    facts = (
        f"{report.host.hostname} · {report.host.distro}\n"
        f"profile: {report.profile} · root: {report.host.root} · "
        f"{'running as root' if report.host.is_root else 'running unprivileged'}\n"
        f"coverage: {report.evaluated}/{len(report.results)} checks evaluated"
    )
    console.print(Panel(Text.assemble(header, "\n\n", facts), title="🛡️  blindagem", expand=False))

    table = Table(show_lines=False, header_style="bold")
    table.add_column("check", no_wrap=True)
    table.add_column("sev", no_wrap=True)
    table.add_column("status", no_wrap=True)
    table.add_column("result")

    for result in report.results:
        if not show_passed and result.status is Status.PASS:
            continue
        meta = report.meta.get(result.check_id)
        status_text = Text(result.status.value, style=STATUS_STYLE[result.status])
        if result.accepted:
            status_text = Text("accepted", style="dim")
        message = result.message
        if result.accepted:
            message += f"  [accepted: {result.accepted_reason}]"
        elif result.evidence:
            message += "\n  " + "\n  ".join(result.evidence[:4])
        table.add_row(
            result.check_id,
            Text(
                meta.severity.value if meta else "",
                style=SEVERITY_STYLE.get(meta.severity, "") if meta else "",
            ),
            status_text,
            message,
        )

    if table.row_count:
        console.print(table)
    else:
        console.print("[green]Every applicable check passed.[/green]")

    counts = report.counts
    console.print(
        f"\n[green]{counts['pass']} pass[/green] · [red]{counts['fail']} fail[/red] · "
        f"[yellow]{counts['warn']} warn[/yellow] · [dim]{counts['skip']} skip[/dim] · "
        f"[magenta]{counts['error']} error[/magenta]"
    )
    if counts["error"]:
        console.print(
            "[dim]Some checks could not run — try again with sudo for full coverage.[/dim]"
        )
    console.print(
        "[dim]Nothing on this system was modified. Run 'blindagem fix -o fix.yml' for a playbook.[/dim]"
    )


def _print_comparison(old: dict, new: dict) -> None:
    diff = json_out.compare(old, new)
    delta = diff["score_delta"]
    arrow = "▲" if delta > 0 else ("▼" if delta < 0 else "=")
    style = "green" if delta > 0 else ("red" if delta < 0 else "dim")
    console.print(
        f"\n[bold]Compared with the previous report:[/bold] "
        f"[{style}]{diff['score_before']} → {diff['score_after']} ({arrow}{abs(delta)})[/{style}]"
    )
    for entry in diff["fixed"]:
        console.print(f"  [green]fixed[/green]   {entry['check_id']}")
    for entry in diff["broken"]:
        console.print(f"  [red]broke[/red]   {entry['check_id']}")
    for entry in diff["changed"]:
        console.print(
            f"  [dim]changed[/dim] {entry['check_id']}: {entry['before']} → {entry['after']}"
        )
    if diff["new_checks"]:
        console.print(f"  [dim]new checks: {', '.join(diff['new_checks'])}[/dim]")


@app.command("list-checks")
def list_checks(
    category: str | None = typer.Option(None, "--category", help="Only this category."),
    markdown: bool = typer.Option(False, "--markdown", help="Print a Markdown table for the docs."),
) -> None:
    """List every available check."""
    metas = [m for m in registry.all_meta() if not category or m.category == category]
    if markdown:
        print("| id | title | category | severity | needs root | reference |")
        print("|---|---|---|---|---|---|")
        for meta in metas:
            print(
                f"| `{meta.id}` | {meta.title} | {meta.category} | {meta.severity.value} | "
                f"{'yes' if meta.needs_root else 'no'} | {meta.reference} |"
            )
        print(f"\n{len(metas)} checks. Generated by `blindagem list-checks --markdown`.")
        return

    table = Table(header_style="bold")
    table.add_column("id", no_wrap=True)
    table.add_column("severity", no_wrap=True)
    table.add_column("title")
    for meta in metas:
        table.add_row(
            meta.id, Text(meta.severity.value, style=SEVERITY_STYLE[meta.severity]), meta.title
        )
    console.print(table)
    console.print(f"[dim]{len(metas)} checks · run 'blindagem explain <id>' for the details[/dim]")


@app.command()
def explain(check_id: str = typer.Argument(..., help="Check id, e.g. ssh.root_login")) -> None:
    """Explain what a check looks at, why it matters and how to fix it."""
    found = registry.get(check_id)
    if found is None:
        err_console.print(f"[red]unknown check '{check_id}'[/red] — try 'blindagem list-checks'")
        raise typer.Exit(code=2)
    meta, _ = found
    body = Text()
    body.append(f"{meta.title}\n\n", style="bold")
    body.append("Severity: ", style="dim")
    body.append(f"{meta.severity.value}\n", style=SEVERITY_STYLE[meta.severity])
    body.append(f"Category: {meta.category}\n", style="dim")
    if meta.reference:
        body.append(f"Reference: {meta.reference}\n", style="dim")
    if meta.needs_root:
        body.append("Needs root to run.\n", style="dim")
    body.append("\nWhy it matters\n", style="bold")
    body.append(f"{meta.rationale}\n")
    body.append("\nHow to fix it\n", style="bold")
    body.append(f"{meta.remediation}\n")
    has_task = meta.id in ansible.available_tasks()
    body.append(
        "\nAutomated fix available in 'blindagem fix'.\n"
        if has_task
        else "\nNo automated fix: this one needs a human decision.\n",
        style="dim",
    )
    console.print(Panel(body, title=meta.id, expand=False))


@app.command()
def fix(
    root: str = typer.Option("/", "--root", help="Audit this root instead of /."),
    profile: str | None = typer.Option(None, "--profile", help="server, workstation or container."),
    config: str | None = typer.Option(None, "--config", "-c", help="Path to blindagem.yaml."),
    only: str | None = typer.Option(None, "--only", help="Comma-separated check ids."),
    category: str | None = typer.Option(None, "--category", help="Comma-separated categories."),
    output: str = typer.Option("fix.yml", "--output", "-o", help="Where to write the playbook."),
    from_json: str | None = typer.Option(
        None, "--from-json", help="Build the playbook from an existing JSON report."
    ),
) -> None:
    """Generate an Ansible playbook for what failed. Applies nothing by itself."""
    if from_json:
        report = _report_from_json(json.loads(Path(from_json).read_text()))
    else:
        report, _cfg = _run_audit(root, config, profile, only, category)

    path, automated, manual = ansible.write(report, output)
    console.print(f"Playbook written to [bold]{path}[/bold] ({len(automated)} tasks)")
    for check_id in automated:
        console.print(f"  [green]•[/green] {check_id}")
    if manual:
        console.print("\n[yellow]Left for you to do by hand:[/yellow]")
        for check_id in manual:
            console.print(f"  [yellow]•[/yellow] {check_id} — {report.meta[check_id].remediation}")
    console.print(
        "\n[dim]Review it first:[/dim]\n"
        f"  ansible-playbook -i <host>, {path} --check --diff\n"
        f"  ansible-playbook -i <host>, {path} --tags ssh,kernel"
    )


def _report_from_json(data: dict) -> Report:
    """Rebuild enough of a Report from JSON to generate a playbook from it."""
    from .models import CheckMeta, CheckResult, HostInfo

    report = Report(
        generated_at=data.get("generated_at", ""),
        tool_version=data.get("tool_version", __version__),
        profile=data.get("profile", "server"),
        host=HostInfo(
            **{k: v for k, v in (data.get("host") or {}).items() if k in HostInfo.__annotations__}
        ),
        score=data.get("score", 0),
        band=data.get("band", ""),
    )
    for row in data.get("results", []):
        report.results.append(
            CheckResult(
                check_id=row["check_id"],
                status=Status(row["status"]),
                message=row.get("message", ""),
                evidence=row.get("evidence", []),
                accepted_reason=row.get("accepted_reason"),
            )
        )
        if "severity" in row:
            report.meta[row["check_id"]] = CheckMeta(
                id=row["check_id"],
                title=row.get("title", row["check_id"]),
                category=row.get("category", ""),
                severity=Severity(row["severity"]),
                rationale=row.get("rationale", ""),
                remediation=row.get("remediation", ""),
                reference=row.get("reference", ""),
            )
    return report


@app.command()
def categories() -> None:
    """List the check categories."""
    for name in registry.categories():
        count = sum(1 for m in registry.all_meta() if m.category == name)
        console.print(f"{name:<12} {count} checks")


if __name__ == "__main__":  # pragma: no cover
    app()
