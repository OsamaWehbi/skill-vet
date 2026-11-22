"""Find skills in folders and archives and read their files.

Nothing is executed and symbolic links are never followed: a link is recorded with its target so the rules can
check where it points. Archives are read in memory with size limits, so a hostile archive cannot write files,
escape its folder or exhaust memory.
"""

from __future__ import annotations

import codecs
import fnmatch
import hashlib
import os
import posixpath
import re
import stat
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

import yaml

from skill_vet.models import Kind, Skill, SkillFile

MANIFEST = "skill.md"
ARCHIVE_SUFFIXES = (".zip", ".skill")
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".ruff_cache",
    ".pytest_cache",
}

SCRIPT_SUFFIXES = {
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".ksh",
    ".ps1",
    ".psm1",
    ".psd1",
    ".bat",
    ".cmd",
    ".vbs",
    ".py",
    ".pyw",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".mts",
    ".cts",
    ".jsx",
    ".tsx",
    ".rb",
    ".pl",
    ".php",
    ".lua",
    ".r",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".swift",
    ".cs",
    ".applescript",
    ".scpt",
    ".awk",
    ".sql",
}
SCRIPT_NAMES = {"makefile", "dockerfile", "justfile", "rakefile", "gemfile", "procfile"}
MARKDOWN_SUFFIXES = {".md", ".markdown", ".mdx", ".rst", ".adoc"}
CONFIG_SUFFIXES = {".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env", ".properties"}
EXECUTABLE_SUFFIXES = {
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".bin",
    ".com",
    ".scr",
    ".msi",
    ".pyc",
    ".pyo",
    ".pyd",
    ".node",
    ".wasm",
    ".class",
    ".jar",
    ".o",
    ".a",
    ".elf",
    ".app",
    ".deb",
    ".rpm",
}
EXECUTABLE_MAGIC = (
    b"\x7fELF",  # Linux
    b"MZ",  # Windows PE
    b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit
    b"\xce\xfa\xed\xfe",  # Mach-O 32-bit
    b"\xca\xfe\xba\xbe",  # Mach-O universal or Java class
    b"\x00asm",  # WebAssembly
)
ARCHIVE_MAGIC = (b"PK\x03\x04", b"\x1f\x8b", b"7z\xbc\xaf", b"Rar!", b"BZh", b"\xfd7zXZ")

FRONT_MATTER = re.compile(r"\A---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|\Z)", re.S)
MAX_FRONT_MATTER = 64 * 1024


@dataclass
class Limits:
    max_file_bytes: int = 5 * 1024 * 1024
    max_files: int = 5000
    max_archive_bytes: int = 200 * 1024 * 1024


@dataclass
class Discovery:
    skills: list[Skill] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _decode(data: bytes) -> str | None:
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return None
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


def classify(path: str, data: bytes) -> tuple[Kind, str | None]:
    """Return the kind of a file and, for text files, its text."""
    name = PurePosixPath(path).name.lower()
    suffix = PurePosixPath(name).suffix
    if path.lower() == MANIFEST:
        return Kind.MANIFEST, _decode(data) or ""
    if suffix in EXECUTABLE_SUFFIXES or data.startswith(EXECUTABLE_MAGIC):
        return Kind.EXECUTABLE, None
    if data.startswith(ARCHIVE_MAGIC) or (b"\x00" in data[:8192] and not data.startswith(codecs.BOM_UTF16_LE)):
        return Kind.BINARY, None
    text = _decode(data)
    if text is None:
        return Kind.BINARY, None
    if text.startswith("#!") or suffix in SCRIPT_SUFFIXES or name in SCRIPT_NAMES:
        return Kind.SCRIPT, text
    if suffix in MARKDOWN_SUFFIXES:
        return Kind.MARKDOWN, text
    if suffix in CONFIG_SUFFIXES or name.startswith(".env"):
        return Kind.CONFIG, text
    return Kind.TEXT, text


def make_file(path: str, data: bytes, executable: bool = False) -> SkillFile:
    kind, text = classify(path, data)
    return SkillFile(path=path, kind=kind, size=len(data), digest=sha256(data), text=text, executable=executable)


def parse_manifest(skill: Skill) -> None:
    """Fill in name, description and front matter from SKILL.md. Problems go to `manifest_error`."""
    manifest = skill.manifest
    if manifest is None:
        skill.manifest_error = "no SKILL.md"
        return
    m = FRONT_MATTER.match(manifest.text or "")
    if not m:
        skill.manifest_error = "SKILL.md has no YAML front matter (a block between --- lines at the top)"
        return
    if len(m.group(1)) > MAX_FRONT_MATTER:
        skill.manifest_error = "front matter is larger than 64 KB"
        return
    try:
        data = yaml.safe_load(m.group(1))
    except yaml.YAMLError as exc:
        skill.manifest_error = f"front matter is not valid YAML: {str(exc).splitlines()[0]}"
        return
    if not isinstance(data, dict):
        skill.manifest_error = "front matter is not a mapping"
        return
    skill.frontmatter = data
    for key in ("name", "description"):
        value = data.get(key)
        if value is None:
            continue
        if not isinstance(value, str):
            skill.manifest_error = f"'{key}' must be a string"
            continue
        setattr(skill, key, value.strip())


def _display(base: str, rel: str) -> str:
    if not rel or rel == ".":
        return base
    return rel if base in ("", ".") else f"{base.rstrip('/')}/{rel}"


def _excluded(display: str, exclude: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(display, pat) or fnmatch.fnmatch(display + "/", pat) for pat in exclude)


def _inside(target: Path, root: Path) -> bool:
    try:
        target.relative_to(root)
    except ValueError:
        return False
    return True


def load_dir(root: Path, display: str, nested: set[Path] | None = None, limits: Limits | None = None) -> Skill:
    """Read every file of the skill in `root`, skipping nested skills (they are scanned on their own)."""
    limits = limits or Limits()
    nested = nested or set()
    skill = Skill(root=display)
    real_root = root.resolve()
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        keep = []
        for name in sorted(dirnames):
            full = here / name
            if full.is_symlink():
                skill.files.append(_link(full, root, real_root))
            elif name not in SKIP_DIRS and full.resolve() not in nested:
                keep.append(name)
        dirnames[:] = keep
        for name in sorted(filenames):
            full = here / name
            rel = full.relative_to(root).as_posix()
            if full.is_symlink():
                skill.files.append(_link(full, root, real_root))
                continue
            if count >= limits.max_files:
                skill.notes.append(f"stopped after {limits.max_files} files; the rest were not scanned")
                parse_manifest(skill)
                return skill
            count += 1
            try:
                info = full.lstat()
                executable = os.name != "nt" and bool(info.st_mode & 0o111)
                if info.st_size > limits.max_file_bytes:
                    skill.files.append(_oversized(rel, full, info.st_size, limits))
                    continue
                skill.files.append(make_file(rel, full.read_bytes(), executable))
            except OSError as exc:
                skill.files.append(SkillFile(rel, Kind.SKIPPED, note=f"could not be read: {exc.strerror or exc}"))
    parse_manifest(skill)
    return skill


def _link(full: Path, root: Path, real_root: Path) -> SkillFile:
    rel = full.relative_to(root).as_posix()
    try:
        target = os.readlink(full)
    except OSError:
        target = "?"
    resolved = (full.parent / target).resolve() if target != "?" else full
    return SkillFile(rel, Kind.LINK, link=target, escapes=not _inside(resolved, real_root))


def _oversized(rel: str, full: Path, size: int, limits: Limits) -> SkillFile:
    h = hashlib.sha256()
    with full.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    mb = limits.max_file_bytes // (1024 * 1024)
    return SkillFile(rel, Kind.SKIPPED, size=size, digest="sha256:" + h.hexdigest(), note=f"larger than {mb} MB")


def _unsafe_name(name: str) -> bool:
    return name.startswith("/") or bool(re.match(r"^[A-Za-z]:", name)) or ".." in name.split("/")


def load_archive(path: Path, display: str, limits: Limits | None = None) -> Discovery:
    """Read the skills in a .zip or .skill archive. One archive may hold several skill folders."""
    limits = limits or Limits()
    out = Discovery()
    try:
        archive = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as exc:
        out.errors.append(f"{display}: not a readable zip archive ({exc})")
        return out
    with archive:
        infos = [i for i in archive.infolist() if not i.is_dir()]
        names = {i: i.filename.replace("\\", "/") for i in infos}
        roots = sorted(
            {
                posixpath.dirname(n)
                for n in names.values()
                if posixpath.basename(n).lower() == MANIFEST and not _unsafe_name(n)
            },
            key=lambda r: (-len(r), r),
        )
        if not roots:
            out.errors.append(f"{display}: no SKILL.md in the archive")
            return out
        skills = {r: Skill(root=f"{display}!/{r}" if r else display) for r in roots}
        total = 0
        for info in infos:
            name = names[info]
            root = next((r for r in roots if not r or name.startswith(r + "/")), None)
            if _unsafe_name(name):
                owner_root = root if root is not None else roots[-1]
                shown = name[len(owner_root) + 1 :] if owner_root and name.startswith(owner_root + "/") else name
                skills[owner_root].files.append(
                    SkillFile(shown, Kind.LINK, escapes=True, note="archive entry path escapes the skill")
                )
                continue
            if root is None:
                continue  # outside every skill folder in the archive
            skill = skills[root]
            rel = name[len(root) + 1 :] if root else name
            mode = info.external_attr >> 16
            if len(skill.files) >= limits.max_files:
                if not skill.notes:
                    skill.notes.append(f"stopped after {limits.max_files} files; the rest were not scanned")
                continue
            if stat.S_ISLNK(mode):
                target = archive.read(info)[:4096].decode("utf-8", "replace")
                joined = posixpath.normpath(posixpath.join(posixpath.dirname(rel), target))
                escapes = target.startswith("/") or joined == ".." or joined.startswith("../")
                skill.files.append(SkillFile(rel, Kind.LINK, link=target, escapes=escapes))
                continue
            if info.file_size > limits.max_file_bytes or total + info.file_size > limits.max_archive_bytes:
                skill.files.append(SkillFile(rel, Kind.SKIPPED, size=info.file_size, note="over the size limit"))
                continue
            try:
                with archive.open(info) as f:
                    data = f.read(limits.max_file_bytes + 1)
            except (RuntimeError, zipfile.BadZipFile, NotImplementedError, OSError) as exc:
                skill.files.append(SkillFile(rel, Kind.SKIPPED, note=f"could not be read: {exc}"))
                continue
            if len(data) > limits.max_file_bytes:
                skill.files.append(SkillFile(rel, Kind.SKIPPED, note="over the size limit (header was wrong)"))
                continue
            total += len(data)
            skill.files.append(make_file(rel, data, bool(mode & 0o111)))
    for r in sorted(roots):
        skill = skills[r]
        skill.files.sort(key=lambda f: f.path)
        parse_manifest(skill)
        out.skills.append(skill)
    return out


def discover(paths: Iterable[Path], exclude: Iterable[str] = (), limits: Limits | None = None) -> Discovery:
    """Find every skill under `paths`: folders that contain a SKILL.md, and .zip or .skill archives."""
    exclude = list(exclude)
    out = Discovery()
    for path in paths:
        base = path.as_posix()
        if path.is_file():
            if path.name.lower() == MANIFEST:
                parent = path.parent
                out.skills.append(load_dir(parent, parent.as_posix(), limits=limits))
            elif path.suffix.lower() in ARCHIVE_SUFFIXES:
                found = load_archive(path, base, limits)
                out.skills += found.skills
                out.errors += found.errors
            else:
                out.errors.append(f"{base}: not a skill folder, SKILL.md or skill archive")
            continue
        roots: list[Path] = []
        archives: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not Path(dirpath, d).is_symlink())
            if any(f.lower() == MANIFEST for f in filenames):
                roots.append(Path(dirpath))
            archives += [Path(dirpath, f) for f in sorted(filenames) if f.lower().endswith(ARCHIVE_SUFFIXES)]
        resolved = {r.resolve() for r in roots}
        for root in roots:
            display = _display(base, root.relative_to(path).as_posix())
            if _excluded(display, exclude):
                continue
            out.skills.append(load_dir(root, display, resolved - {root.resolve()}, limits))
        for archive in archives:
            if any(_inside(archive.resolve(), r) for r in resolved):
                continue  # part of a skill folder; reported there as a binary file
            display = _display(base, archive.relative_to(path).as_posix())
            if _excluded(display, exclude):
                continue
            found = load_archive(archive, display, limits)
            out.skills += found.skills
            out.errors += found.errors
        if not roots and not archives:
            out.errors.append(f"{base}: no skills found (a skill is a folder with a SKILL.md file)")
    return out
