"""Render results as a terminal table, JSON, SARIF 2.1.0 or Markdown."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from skill_vet import __version__
from skill_vet.engine import Result, summarise, verdict
from skill_vet.models import Finding, Severity, Skill
from skill_vet.rules import RULES

SARIF_LEVEL = {Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}
SECURITY_SEVERITY = {Severity.HIGH: "8.0", Severity.MEDIUM: "5.0", Severity.LOW: "3.0", Severity.INFO: "1.0"}
STYLE = {Severity.HIGH: "bold red", Severity.MEDIUM: "yellow", Severity.LOW: "cyan", Severity.INFO: "dim"}
VERDICT_STYLE = dict(zip(("block", "review", "pass"), ("bold red", "yellow", "green"), strict=True))
HELP_URI = "https://github.com/OsamaWehbi/skill-vet/blob/main/docs/rules.md"


def by_skill(result: Result) -> list[tuple[str, str, list[Finding]]]:
    """(root, name, findings) for every scanned skill, plus pinned skills that are missing."""
    rows: dict[str, tuple[str, list[Finding]]] = {s.root: (s.label, []) for s in result.skills}
    for f in result.findings:
        rows.setdefault(f.skill, (f.skill.rsplit("/", 1)[-1], []))[1].append(f)
    return [(root, name, fs) for root, (name, fs) in sorted(rows.items())]


def scope(result: Result) -> str:
    files = sum(len(s.files) for s in result.skills)
    return f"{len(result.skills)} skill(s), {files} file(s)"


def render_table(result: Result, console: Console) -> None:
    console.print(f"[bold]skill-vet {__version__}[/] scanned {escape(scope(result))}")
    for error in result.errors:
        console.print(f"[yellow]warning:[/] {escape(error)}")
    if result.skills or result.findings:
        overview = Table(header_style="bold", title="Skills", title_justify="left")
        overview.add_column("Verdict")
        overview.add_column("Skill", overflow="fold")
        overview.add_column("Path", overflow="fold")
        overview.add_column("High", justify="right")
        overview.add_column("Medium", justify="right")
        overview.add_column("Low/info", justify="right")
        for root, name, fs in by_skill(result):
            v = verdict(fs)
            counts = summarise(fs)
            overview.add_row(
                f"[{VERDICT_STYLE[v]}]{v}[/]",
                escape(name),
                escape(root),
                str(counts["high"]),
                str(counts["medium"]),
                str(counts["low"] + counts["info"]),
            )
        console.print(overview)
    if not result.findings:
        console.print("[green]No findings.[/]")
        return
    table = Table(header_style="bold", title="Findings", title_justify="left")
    table.add_column("Severity")
    table.add_column("Rule")
    table.add_column("Location", overflow="fold")
    table.add_column("Finding", overflow="fold")
    for f in result.findings:
        detail = escape(f.title)
        if f.evidence:
            detail += f"\n[dim]{escape(f.evidence)}[/]"
        table.add_row(f"[{STYLE[f.severity]}]{f.severity}[/]", f.rule_id, escape(f.location), detail)
    console.print(table)
    console.print("  ".join(f"{k}: {v}" for k, v in summarise(result.findings).items()))


def _skill_json(skill: Skill, findings: list[Finding]) -> dict[str, Any]:
    return {
        "root": skill.root,
        "name": skill.name,
        "description": skill.description,
        "verdict": verdict(findings),
        "files": [{"path": f.path, "kind": f.kind.value, "size": f.size, "digest": f.digest} for f in skill.files],
        "manifest_error": skill.manifest_error,
    }


def to_json(result: Result) -> str:
    grouped = {root: fs for root, _, fs in by_skill(result)}
    doc = {
        "tool": "skill-vet",
        "version": __version__,
        "skills": [_skill_json(s, grouped.get(s.root, [])) for s in result.skills],
        "errors": result.errors,
        "summary": summarise(result.findings),
        "findings": [f.model_dump(mode="json") for f in result.findings],
    }
    return json.dumps(doc, indent=2)


def _fingerprint(f: Finding) -> str:
    evidence = hashlib.sha256(f.evidence.encode("utf-8")).hexdigest()[:16]
    return f"{f.rule_id}:{f.skill}:{f.path}:{evidence}"


def _uri(f: Finding) -> str:
    root = f.skill.split("!/", 1)[0] if "!/" in f.skill else f.skill
    if "!/" in f.skill or root.lower().endswith((".zip", ".skill")):
        return root  # inside an archive: point at the archive itself
    return f"{root}/{f.path}" if f.path else f"{root}/SKILL.md"


def to_sarif(result: Result) -> str:
    """SARIF 2.1.0 for GitHub code scanning."""
    used = sorted({f.rule_id for f in result.findings})
    index = {rid: i for i, rid in enumerate(used)}
    rules: list[dict[str, Any]] = []
    for rid in used:
        rule = RULES[rid]
        rules.append(
            {
                "id": rid,
                "name": "".join(w.capitalize() for w in rule.title.replace("-", " ").split()),
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.description},
                "help": {"text": rule.remediation, "markdown": f"{rule.remediation}\n\nOWASP: {rule.owasp}"},
                "helpUri": f"{HELP_URI}#{rid.lower()}",
                "defaultConfiguration": {"level": SARIF_LEVEL[rule.severity]},
                "properties": {
                    "tags": ["security", "agent-skills", rule.owasp],
                    "security-severity": SECURITY_SEVERITY[rule.severity],
                },
            }
        )
    results = []
    for f in result.findings:
        message = f"{f.title}: {f.location}. {f.evidence}".strip()
        results.append(
            {
                "ruleId": f.rule_id,
                "ruleIndex": index[f.rule_id],
                "level": SARIF_LEVEL[f.severity],
                "message": {"text": message},
                "partialFingerprints": {"skillVetFinding/v1": _fingerprint(f)},
                "properties": {"security-severity": SECURITY_SEVERITY[f.severity]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _uri(f)},
                            "region": {"startLine": f.line or 1},
                        }
                    }
                ],
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "skill-vet",
                        "version": __version__,
                        "informationUri": "https://github.com/OsamaWehbi/skill-vet",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("`", "'").replace("\n", " ")


def to_markdown(result: Result) -> str:
    lines = [f"### skill-vet: {scope(result)}", ""]
    groups = by_skill(result)
    if groups:
        lines += ["| Verdict | Skill | Path | High | Medium | Low/info |", "| --- | --- | --- | ---: | ---: | ---: |"]
        for root, name, fs in groups:
            c = summarise(fs)
            lines.append(
                f"| {verdict(fs)} | {_md(name)} | `{_md(root)}` | {c['high']} | {c['medium']} | {c['low'] + c['info']} |"
            )
        lines.append("")
    if not result.findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"
    lines += ["| Severity | Rule | Location | Finding |", "| --- | --- | --- | --- |"]
    for f in result.findings:
        detail = _md(f.title) + (f"<br>`{_md(f.evidence)}`" if f.evidence else "")
        lines.append(f"| {f.severity} | {f.rule_id} | `{_md(f.location)}` | {detail} |")
    return "\n".join(lines) + "\n"
