"""Core data types: skills, the files inside them, and findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from pydantic import BaseModel


class Severity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


class Kind(StrEnum):
    MANIFEST = "manifest"
    MARKDOWN = "markdown"
    SCRIPT = "script"
    CONFIG = "config"
    TEXT = "text"
    BINARY = "binary"
    EXECUTABLE = "executable"
    LINK = "link"
    SKIPPED = "skipped"


def printable(text: str | None) -> str | None:
    """Escape control and invisible characters so hostile text cannot drive the terminal or hide in reports."""
    if text is None:
        return None
    return "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in text)


@dataclass
class SkillFile:
    """One file of a skill. `path` is relative to the skill folder and uses forward slashes.

    `text` is None for binaries and for files that were not read. `link` holds the target of a symbolic
    link, which is never followed. `escapes` is set when a link or an archive entry points outside the skill.
    """

    path: str
    kind: Kind
    size: int = 0
    digest: str = ""
    text: str | None = None
    executable: bool = False
    link: str | None = None
    escapes: bool = False
    note: str = ""


@dataclass
class Skill:
    root: str
    name: str = ""
    description: str = ""
    frontmatter: dict[str, Any] = field(default_factory=dict)
    manifest_error: str | None = None
    files: list[SkillFile] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def manifest(self) -> SkillFile | None:
        return next((f for f in self.files if f.kind is Kind.MANIFEST), None)

    @property
    def label(self) -> str:
        return self.name or self.root.rsplit("/", 1)[-1]


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    skill: str
    path: str
    line: int | None = None
    evidence: str = ""
    owasp: str = ""
    remediation: str = ""

    @property
    def location(self) -> str:
        where = f"{self.skill}/{self.path}" if self.path else self.skill
        return f"{where}:{self.line}" if self.line else where

    def sort_key(self) -> tuple[int, str, str, int, str]:
        return (-self.severity.rank, self.skill, self.path, self.line or 0, self.rule_id)
