"""Command-line interface: scan, inspect, pin and rules."""

from __future__ import annotations

import sys
from enum import StrEnum
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from skill_vet import __version__, lockfile, report
from skill_vet.engine import Options, scan
from skill_vet.loader import Limits, discover
from skill_vet.models import Kind, Severity, printable
from skill_vet.rules import RULES
from skill_vet.rules import code as code_rules
from skill_vet.rules import text as text_rules

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Scan agent skills for hidden instructions, dangerous scripts, broad permissions and unapproved changes.",
)
console = Console(highlight=False)
err = Console(stderr=True, highlight=False)


class Format(StrEnum):
    table = "table"
    json = "json"
    sarif = "sarif"
    markdown = "markdown"


class FailOn(StrEnum):
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"
    none = "none"


def _version(value: bool) -> None:
    if value:
        console.print(f"skill-vet {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(False, "--version", callback=_version, is_eager=True, help="Show the version."),
) -> None:
    pass


def _limits(max_mb: int) -> Limits:
    if max_mb < 1:
        raise typer.BadParameter("--max-file-size must be at least 1")
    return Limits(max_file_bytes=max_mb * 1024 * 1024)


@app.command("scan")
def scan_cmd(
    paths: list[Path] = typer.Argument(
        ..., exists=True, help="Skill folders, folders of skills, or .zip/.skill files."
    ),
    fmt: Format = typer.Option(Format.table, "--format", "-f", help="Output format."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write the report to a file instead of stdout."),
    fail_on: FailOn = typer.Option(FailOn.high, help="Exit with status 1 when a finding is at or above this severity."),
    lock: Path | None = typer.Option(None, "--lock", help="Compare skills with this lockfile (see `skill-vet pin`)."),
    ignore: list[str] = typer.Option(
        [], "--ignore", help="Ignore a rule, optionally for matching skills or files: SV203 or SV203:cleanup/*."
    ),
    exclude: list[str] = typer.Option([], "--exclude", help="Skip skills whose path matches this glob."),
    max_mb: int = typer.Option(5, "--max-file-size", help="Do not read files larger than this many MB."),
    summary: Path | None = typer.Option(
        None, "--summary", help="Append a Markdown summary here (e.g. $GITHUB_STEP_SUMMARY)."
    ),
) -> None:
    """Scan skills and report findings."""
    options = Options(ignore=ignore, exclude=exclude, limits=_limits(max_mb))
    pins = None
    if lock is not None and lock.exists():
        try:
            pins = lockfile.read(lock)
        except (ValueError, OSError) as exc:
            err.print(f"[red]error:[/] {escape(str(exc))}")
            raise typer.Exit(2) from exc
    elif lock is not None:
        err.print(f"[yellow]warning:[/] lockfile {escape(str(lock))} not found; run `skill-vet pin` to create it")

    result = scan(paths, options, pins)

    if fmt is Format.table and output is None:
        report.render_table(result, console)
    else:
        rendered = {
            Format.table: lambda: report.to_markdown(result),
            Format.json: lambda: report.to_json(result),
            Format.sarif: lambda: report.to_sarif(result),
            Format.markdown: lambda: report.to_markdown(result),
        }[fmt]()
        if output is not None:
            output.write_text(rendered, encoding="utf-8")
            err.print(
                f"wrote {escape(str(output))}: {len(result.findings)} finding(s) in {escape(report.scope(result))}"
            )
        else:
            sys.stdout.write(rendered if rendered.endswith("\n") else rendered + "\n")
        for error in result.errors:
            err.print(f"[yellow]warning:[/] {escape(error)}")
    if summary is not None:
        with summary.open("a", encoding="utf-8") as f:
            f.write(report.to_markdown(result))

    if not result.skills and result.errors:
        raise typer.Exit(2)
    if fail_on is not FailOn.none:
        threshold = Severity(fail_on.value).rank
        if any(f.severity.rank >= threshold for f in result.findings):
            raise typer.Exit(1)


@app.command("inspect")
def inspect_cmd(
    path: Path = typer.Argument(..., exists=True, help="A skill folder, SKILL.md or skill archive."),
    max_mb: int = typer.Option(5, "--max-file-size", help="Do not read files larger than this many MB."),
) -> None:
    """Show what a skill contains: its manifest, files, capabilities and any hidden text."""
    found = discover([path], limits=_limits(max_mb))
    for error in found.errors:
        err.print(f"[yellow]warning:[/] {escape(error)}")
    if not found.skills:
        raise typer.Exit(2)
    for skill in found.skills:
        console.rule(f"[bold]{escape(skill.label)}[/] [dim]{escape(skill.root)}[/]")
        if skill.manifest_error:
            console.print(f"[red]manifest:[/] {escape(skill.manifest_error)}")
        for key, value in skill.frontmatter.items():
            shown = (
                value
                if isinstance(value, str | int | float | bool)
                else ", ".join(map(str, value))
                if isinstance(value, list)
                else "{...}"
            )
            console.print(f"[bold]{escape(str(key))}:[/] {escape(printable(str(shown))[:600] or '')}")
        table = Table(header_style="bold")
        table.add_column("File", overflow="fold")
        table.add_column("Kind")
        table.add_column("Size", justify="right")
        table.add_column("Does", overflow="fold")
        for f in skill.files:
            caps = sorted(code_rules.capabilities(f.text)) if f.text else []
            extra = f" -> {f.link}" if f.link else (f" ({f.note})" if f.note else "")
            kind = f.kind.value + (" +x" if f.executable else "")
            table.add_row(escape(printable(f.path + extra) or ""), kind, str(f.size), ", ".join(caps))
        console.print(table)
        for f in skill.files:
            if not f.text or f.kind not in (Kind.MANIFEST, Kind.MARKDOWN, Kind.TEXT, Kind.SCRIPT, Kind.CONFIG):
                continue
            hidden = text_rules.hidden_unicode(f.text)
            if f.kind in (Kind.MANIFEST, Kind.MARKDOWN, Kind.TEXT):
                for label, pattern in text_rules.HIDDEN_MARKDOWN:
                    for m in pattern.finditer(f.text):
                        body = (m.group(m.lastindex or 0) or "").strip()
                        if body:
                            line = f.text.count("\n", 0, m.start()) + 1
                            console.print(f"[yellow]hidden[/] {escape(f.path)}:{line} [dim]{label}[/]")
                            console.print("  " + escape(printable(body[:800]) or ""), soft_wrap=True)
            for hit in hidden:
                line = f.text.count("\n", 0, hit.start) + 1
                console.print(f"[yellow]invisible characters[/] {escape(f.path)}:{line}")
                console.print("  " + escape(hit.evidence), soft_wrap=True)


@app.command("pin")
def pin_cmd(
    paths: list[Path] = typer.Argument(..., exists=True, help="Skills to approve."),
    lock: Path = typer.Option(Path("skill-vet.lock"), "--lock", help="Lockfile to write."),
    exclude: list[str] = typer.Option([], "--exclude", help="Skip skills whose path matches this glob."),
    max_mb: int = typer.Option(5, "--max-file-size", help="Do not read files larger than this many MB."),
) -> None:
    """Record a hash of every file of every skill, so later scans report changes."""
    found = discover(paths, exclude, _limits(max_mb))
    for error in found.errors:
        err.print(f"[yellow]warning:[/] {escape(error)}")
    lockfile.write(lock, found.skills)
    console.print(f"pinned {len(found.skills)} skill(s) to {escape(str(lock))}")


@app.command("rules")
def rules_cmd() -> None:
    """List the rules."""
    table = Table(header_style="bold")
    table.add_column("Rule")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("OWASP")
    for rule in RULES.values():
        table.add_row(rule.id, str(rule.severity), rule.title, rule.owasp)
    console.print(table)


def main() -> None:
    # Never crash on a console that cannot show a character from a skill.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    # Click expands wildcards in arguments on Windows, which would turn --exclude/--ignore globs into file paths.
    app(windows_expand_args=False)
