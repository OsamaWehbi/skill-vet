"""Skill lockfile: a SHA-256 for every file of every approved skill, so later scans report what changed."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from skill_vet.models import Kind, Skill, SkillFile

LOCK_VERSION = 1


def file_digest(f: SkillFile) -> str:
    if f.kind is Kind.LINK:
        return f"link:{f.link or ''}"
    return f.digest or "unread"


def snapshot(skill: Skill) -> dict[str, Any]:
    files = {f.path: file_digest(f) for f in sorted(skill.files, key=lambda f: f.path)}
    tree = hashlib.sha256("".join(f"{p}\0{d}\n" for p, d in files.items()).encode("utf-8")).hexdigest()
    return {"name": skill.name, "digest": "sha256:" + tree, "files": files}


def write(lock_path: Path, skills: list[Skill]) -> None:
    doc = {
        "version": LOCK_VERSION,
        "tool": "skill-vet",
        "skills": {s.root: snapshot(s) for s in sorted(skills, key=lambda s: s.root)},
    }
    lock_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")


def read(lock_path: Path) -> dict[str, dict[str, Any]]:
    try:
        data = json.loads(lock_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{lock_path}: not valid JSON ({exc.msg})") from exc
    if not isinstance(data, dict) or data.get("version") != LOCK_VERSION:
        version = data.get("version") if isinstance(data, dict) else None
        raise ValueError(f"{lock_path}: unsupported lockfile version {version!r}")
    skills = data.get("skills")
    if not isinstance(skills, dict):
        raise ValueError(f"{lock_path}: 'skills' must be a mapping")
    for root, entry in skills.items():
        files = entry.get("files") if isinstance(entry, dict) else None
        if not isinstance(files, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in files.items()):
            raise ValueError(f"{lock_path}: skill {root!r} must have a 'files' mapping of paths to hashes")
    return skills


def diff(pinned: dict[str, str], current: dict[str, str]) -> dict[str, list[str]]:
    return {
        "changed": sorted(p for p in pinned.keys() & current.keys() if pinned[p] != current[p]),
        "added": sorted(current.keys() - pinned.keys()),
        "removed": sorted(pinned.keys() - current.keys()),
    }
