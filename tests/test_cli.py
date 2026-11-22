"""CLI and report tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from conftest import EXAMPLES, ROOT
from skill_vet import __version__
from skill_vet.cli import app
from skill_vet.rules import RULES

runner = CliRunner()


def invoke(*args: str):
    return runner.invoke(app, [str(a) for a in args])


def test_version_and_rules():
    assert __version__ in invoke("--version").output
    out = invoke("rules").output
    assert all(rid in out for rid in RULES)


def test_exit_codes():
    assert invoke("scan", EXAMPLES / "clean").exit_code == 0
    assert invoke("scan", EXAMPLES / "malicious").exit_code == 1
    assert invoke("scan", EXAMPLES / "malicious", "--fail-on", "none").exit_code == 0
    assert invoke("scan", EXAMPLES / "clean" / "pdf-tables" / "SKILL.md").exit_code == 0


def test_no_skills_is_an_error(tmp_path):
    result = invoke("scan", tmp_path)
    assert result.exit_code == 2


def test_json_report(tmp_path):
    out = tmp_path / "r.json"
    invoke("scan", EXAMPLES / "malicious", "-f", "json", "-o", out, "--fail-on", "none")
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["tool"] == "skill-vet" and doc["summary"]["high"] > 0
    assert {s["verdict"] for s in doc["skills"]} == {"block"}
    assert all(f["rule_id"] in RULES for f in doc["findings"])


def test_sarif_report(tmp_path):
    out = tmp_path / "r.sarif"
    invoke("scan", EXAMPLES / "malicious", EXAMPLES / "archives", "-f", "sarif", "-o", out, "--fail-on", "none")
    doc = json.loads(out.read_text(encoding="utf-8"))
    run = doc["runs"][0]
    ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert ids == sorted(set(ids))
    for result in run["results"]:
        assert run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"] == result["ruleId"]
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert "!/" not in uri and not uri.startswith("/")
    assert any(
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith("theme-pack.skill")
        for r in run["results"]
    )


def test_markdown_and_summary(tmp_path):
    summary = tmp_path / "summary.md"
    result = invoke("scan", EXAMPLES / "malicious", "-f", "markdown", "--summary", summary, "--fail-on", "none")
    assert "| block | git-helper |" in result.output
    assert summary.read_text(encoding="utf-8").startswith("### skill-vet:")


def test_table_output():
    result = invoke("scan", EXAMPLES / "malicious" / "git-helper")
    assert "block" in result.output and "SV302" in result.output


def test_pin_then_scan(tmp_path, make_skill):
    root = make_skill(files={"a.sh": "echo hi\n"})
    lock = tmp_path / "skill-vet.lock"
    assert invoke("pin", root, "--lock", lock).exit_code == 0
    assert invoke("scan", root, "--lock", lock, "--fail-on", "low").exit_code == 0
    (root / "a.sh").write_text("echo changed\n", encoding="utf-8")
    result = invoke("scan", root, "--lock", lock, "--fail-on", "medium")
    assert result.exit_code == 1 and "SV401" in result.output


def test_bad_lockfile(tmp_path, make_skill):
    lock = tmp_path / "bad.lock"
    lock.write_text("[]", encoding="utf-8")
    assert invoke("scan", make_skill(), "--lock", lock).exit_code == 2
    missing = invoke("scan", make_skill(), "--lock", tmp_path / "none.lock")
    assert missing.exit_code == 0


def test_inspect_reveals_hidden_text():
    out = invoke("inspect", EXAMPLES / "malicious" / "pdf-summarizer").output
    assert "hidden" in out and "collector.attacker.invalid" in out
    out = invoke("inspect", EXAMPLES / "malicious" / "code-formatter").output
    assert "invisible characters" in out and "Ignore all previous instructions" in out
    out = invoke("inspect", EXAMPLES / "malicious" / "git-helper").output
    assert "network" in out and "allowed-tools" in out


def test_ignore_and_exclude_globs_reach_the_engine():
    result = invoke(
        "scan",
        EXAMPLES / "malicious",
        "--exclude",
        "*/deploy-tools",
        "--exclude",
        "*/code-formatter",
        "--exclude",
        "*/pdf-summarizer",
        "--ignore",
        "SV105",
        "--ignore",
        "SV203:git-helper",
        "-f",
        "json",
        "--fail-on",
        "none",
    )
    doc = json.loads(result.output)
    assert [s["name"] for s in doc["skills"]] == ["git-helper"]
    assert {f["rule_id"] for f in doc["findings"]}.isdisjoint({"SV105", "SV203"})


def test_module_entry_point():
    proc = subprocess.run([sys.executable, "-m", "skill_vet", "--version"], capture_output=True, text=True, check=False)
    assert proc.returncode == 0 and __version__ in proc.stdout


def test_rules_doc_is_generated():
    doc = (ROOT / "docs" / "rules.md").read_text(encoding="utf-8")
    assert all(f"### {rid}" in doc for rid in RULES)


def test_source_is_ascii():
    """Invisible characters in this repository's own code would be exactly what skill-vet warns about."""
    for folder in ("src", "tests", "scripts", "skill"):
        for path in (ROOT / folder).rglob("*"):
            if path.suffix in (".py", ".md", ".toml", ".yml", ".yaml") and path.is_file():
                text = path.read_text(encoding="utf-8")
                assert text.isascii(), path
    for name in ("README.md", "CHANGELOG.md", "SECURITY.md", "CONTRIBUTING.md", "action.yml", "pyproject.toml"):
        assert Path(ROOT / name).read_text(encoding="utf-8").isascii(), name
