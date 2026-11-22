from __future__ import annotations

from pathlib import Path

import pytest

from skill_vet.engine import Options, Result, scan

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples" / "skills"


def manifest(
    name: str = "demo",
    description: str = "Does one thing. Use when the user asks for it.",
    extra: str = "",
    body: str = "# Demo\n\nFollow the steps.\n",
) -> str:
    return f"---\nname: {name}\ndescription: {description}\n{extra}---\n\n{body}"


@pytest.fixture
def make_skill(tmp_path: Path):
    """Create a skill folder: make_skill(files={"scripts/x.sh": "..."}, body="...")."""

    def _make(name: str = "demo", files: dict[str, str | bytes] | None = None, **kwargs: str) -> Path:
        root = tmp_path / name
        root.mkdir(parents=True, exist_ok=True)
        (root / "SKILL.md").write_text(manifest(name, **kwargs), encoding="utf-8", newline="\n")
        for rel, content in (files or {}).items():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                target.write_bytes(content)
            else:
                target.write_text(content, encoding="utf-8", newline="\n")
        return root

    return _make


def run(*paths: Path, **options) -> Result:
    return scan(list(paths), Options(**options))


def rules(result: Result) -> set[str]:
    return {f.rule_id for f in result.findings}
