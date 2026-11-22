"""Run every rule over the skills found under the given paths."""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from skill_vet import lockfile
from skill_vet.loader import Limits, discover
from skill_vet.models import Finding, Kind, Severity, Skill, SkillFile
from skill_vet.rules import RULES
from skill_vet.rules import code as code_rules
from skill_vet.rules import text as text_rules
from skill_vet.rules.text import Hit

TEXT_KINDS = {Kind.MANIFEST, Kind.MARKDOWN, Kind.SCRIPT, Kind.CONFIG, Kind.TEXT}
PROSE_KINDS = {Kind.MANIFEST, Kind.MARKDOWN, Kind.TEXT}
NAME_RE = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
SHELL_TOOLS = {
    "bash",
    "shell",
    "sh",
    "zsh",
    "powershell",
    "pwsh",
    "cmd",
    "terminal",
    "exec",
    "run_shell_command",
    "run_terminal_cmd",
    "execute_command",
    "computer",
}
WILDCARD_SCOPES = {"", "*", ":*", "**", "*:*"}
ARCHIVE_SUFFIXES = (".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".skill")


@dataclass
class Options:
    ignore: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    limits: Limits = field(default_factory=Limits)


@dataclass
class Result:
    skills: list[Skill]
    findings: list[Finding]
    errors: list[str] = field(default_factory=list)


def finding(
    rule_id: str,
    skill: Skill | str,
    path: str = "",
    line: int | None = None,
    evidence: str = "",
    severity: Severity | None = None,
) -> Finding:
    rule = RULES[rule_id]
    return Finding(
        rule_id=rule_id,
        title=rule.title,
        severity=severity or rule.severity,
        skill=skill if isinstance(skill, str) else skill.root,
        path=path,
        line=line,
        evidence=evidence,
        owasp=rule.owasp,
        remediation=rule.remediation,
    )


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _key_line(text: str, key: str) -> int | None:
    m = re.search(rf"^{re.escape(key)}\s*:", text, re.M)
    return line_of(text, m.start()) if m else None


def folder_name(root: str) -> str:
    inner = root.rsplit("!/", 1)[-1] if "!/" in root else root
    name = PurePosixPath(inner).name
    if "!/" not in root:
        for suffix in (".zip", ".skill"):
            if name.lower().endswith(suffix):
                name = name[: -len(suffix)]
    return name


def tool_grants(value: Any) -> list[str]:
    if isinstance(value, str):
        return re.findall(r"[^,\s()]+(?:\([^)]*\))?", value)
    if isinstance(value, list):
        return [t for item in value if isinstance(item, str) for t in tool_grants(item)]
    return []


def broad_grants(value: Any) -> list[str]:
    broad = []
    for grant in tool_grants(value):
        m = re.fullmatch(r"([^()]+)(?:\((.*)\))?", grant.strip())
        if not m:
            continue
        name, scope = m.group(1).strip(), m.group(2)
        if name in ("*", "all", "All") or (
            name.lower() in SHELL_TOOLS and (scope is None or scope.strip() in WILDCARD_SCOPES)
        ):
            broad.append(grant)
    return broad


def check_manifest(skill: Skill) -> list[Finding]:
    out: list[Finding] = []
    manifest = skill.manifest
    text = manifest.text if manifest and manifest.text else ""
    path = manifest.path if manifest else "SKILL.md"
    if skill.manifest_error:
        out.append(finding("SV001", skill, path, 1, skill.manifest_error))
    elif not skill.name or not skill.description:
        missing = " and ".join(k for k in ("name", "description") if not getattr(skill, k))
        out.append(finding("SV001", skill, path, 1, f"front matter has no {missing}"))
    if skill.name:
        problems = []
        if not NAME_RE.fullmatch(skill.name) or len(skill.name) > 64:
            problems.append("not lowercase letters, digits and hyphens (at most 64)")
        folder = folder_name(skill.root)
        if folder and folder not in (".", "") and folder != skill.name:
            problems.append(f"folder is {folder!r}")
        if problems:
            evidence = f"name {text_rules.clean(skill.name)!r}: " + "; ".join(problems)
            out.append(finding("SV002", skill, path, _key_line(text, "name"), evidence))
    for hit in text_rules.hijack(skill.description):
        out.append(finding("SV105", skill, path, _key_line(text, "description"), hit.evidence))
    fm = skill.frontmatter
    grants = fm.get("allowed-tools", fm.get("allowed_tools"))
    broad = broad_grants(grants)
    if broad:
        out.append(
            finding(
                "SV301",
                skill,
                path,
                _key_line(text, "allowed-tools") or _key_line(text, "allowed_tools"),
                "allowed-tools: " + ", ".join(broad),
            )
        )
    if "hooks" in fm:
        hooks = fm["hooks"]
        detail = ", ".join(map(str, hooks)) if isinstance(hooks, dict | list) else str(hooks)
        out.append(
            finding("SV303", skill, path, _key_line(text, "hooks"), f"[defines hooks] {text_rules.clean(detail)[:160]}")
        )
    return out


def text_hits(f: SkillFile) -> list[Hit]:
    text = f.text or ""
    hits = (
        text_rules.overrides(text)
        + text_rules.hidden_unicode(text)
        + text_rules.encoded(text)
        + text_rules.secrets(text)
        + text_rules.safety(text)
        + code_rules.commands(text)
    )
    if f.kind in PROSE_KINDS:
        hits += text_rules.exfil_urls(text) + text_rules.hidden_markdown(text, code_rules.is_dangerous)
    return hits


def check_files(skill: Skill) -> list[Finding]:
    out: list[Finding] = []
    for f in skill.files:
        if f.kind is Kind.LINK:
            if f.escapes:
                evidence = f"{f.path} -> {f.link}" if f.link else f"{f.path}: {f.note}"
                out.append(finding("SV405", skill, f.path, None, text_rules.clean(evidence)))
            continue
        if f.kind is Kind.SKIPPED:
            out.append(finding("SV406", skill, f.path, None, f.note))
            continue
        if f.kind is Kind.EXECUTABLE:
            out.append(finding("SV208", skill, f.path, None, f"[executable] {f.size} bytes, {f.digest[:19]}..."))
            continue
        if f.kind is Kind.BINARY:
            if f.path.lower().endswith(ARCHIVE_SUFFIXES):
                out.append(finding("SV208", skill, f.path, None, f"[nested archive] {f.size} bytes, not unpacked"))
            continue
        if f.kind in TEXT_KINDS and f.text:
            seen: set[tuple[str, str]] = set()
            for hit in text_hits(f):
                key = (hit.rule_id, hit.label)
                if key in seen:
                    continue
                seen.add(key)
                out.append(finding(hit.rule_id, skill, f.path, line_of(f.text, hit.start), hit.evidence, hit.severity))
    for note in skill.notes:
        out.append(finding("SV406", skill, "", None, note))
    return out


def check_names(skills: list[Skill]) -> list[Finding]:
    by_name: dict[str, list[Skill]] = {}
    for s in skills:
        if s.name:
            by_name.setdefault(s.name, []).append(s)
    out = []
    for name, group in by_name.items():
        if len(group) < 2:
            continue
        for s in group:
            others = ", ".join(o.root for o in group if o is not s)
            manifest = s.manifest.path if s.manifest else "SKILL.md"
            out.append(finding("SV404", s, manifest, None, f"name {name!r} is also used by {others}"))
    return out


def _covered(root: str, bases: list[str]) -> bool:
    return any(
        b in ("", ".") or root == b or root.startswith(b.rstrip("/") + "/") or root.startswith(b + "!/") for b in bases
    )


def check_pins(skills: list[Skill], pins: dict[str, dict[str, Any]], bases: list[str]) -> list[Finding]:
    out = []
    current = {s.root: s for s in skills}
    for root, skill in current.items():
        if root not in pins:
            out.append(finding("SV402", skill, "", None, f"{len(skill.files)} file(s), not in the lockfile"))
            continue
        changes = lockfile.diff(pins[root]["files"], lockfile.snapshot(skill)["files"])
        if any(changes.values()):
            parts = []
            for kind, paths in changes.items():
                if paths:
                    listed = ", ".join(paths[:8]) + (f" and {len(paths) - 8} more" if len(paths) > 8 else "")
                    parts.append(f"{kind}: {listed}")
            out.append(finding("SV401", skill, "", None, "; ".join(parts)))
    for root, entry in pins.items():
        if root not in current and _covered(root, bases):
            name = entry.get("name") if isinstance(entry, dict) else ""
            out.append(finding("SV403", root, "", None, f"pinned skill {name or root!r} was not found"))
    return out


def ignored(f: Finding, rules: Iterable[str]) -> bool:
    for spec in rules:
        rule, _, pattern = spec.partition(":")
        if rule.strip().upper() != f.rule_id:
            continue
        if not pattern:
            return True
        targets = (f.skill, f"{f.skill}/{f.path}" if f.path else f.skill, folder_name(f.skill))
        if any(fnmatch.fnmatch(t, pattern) for t in targets):
            return True
    return False


def summarise(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def verdict(findings: list[Finding]) -> str:
    worst = max((f.severity.rank for f in findings), default=-1)
    return "block" if worst >= Severity.HIGH.rank else "review" if worst >= Severity.MEDIUM.rank else "pass"


def scan(
    paths: Iterable[Path], options: Options | None = None, pins: dict[str, dict[str, Any]] | None = None
) -> Result:
    options = options or Options()
    paths = list(paths)
    found = discover(paths, options.exclude, options.limits)
    findings: list[Finding] = []
    for skill in found.skills:
        findings += check_manifest(skill) + check_files(skill)
    findings += check_names(found.skills)
    if pins is not None:
        findings += check_pins(found.skills, pins, [p.as_posix() for p in paths])
    findings = [f for f in findings if not ignored(f, options.ignore)]
    findings.sort(key=Finding.sort_key)
    return Result(found.skills, findings, found.errors)
