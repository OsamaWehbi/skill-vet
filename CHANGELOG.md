# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `skill-vet scan` for skill folders, folders of skills and `.zip` or `.skill` archives, with table, JSON, SARIF 2.1.0
  and Markdown output, a per-skill verdict (block, review or pass) and a `--fail-on` threshold.
- Rules for the manifest (SV001, SV002), hidden and injected instructions (SV101 to SV105), dangerous code (SV201 to
  SV208), permissions and agent safety (SV301 to SV304), and integrity (SV401 to SV406).
- Severity that depends on context: credential reads and uploads are raised when the same file makes network
  requests, and hidden Markdown is rated by what it contains.
- `skill-vet pin` to approve skills in a lockfile, and change detection that lists added, removed and changed files.
- `skill-vet inspect` to show a skill's files, what each one does, and its hidden text, decoded.
- A GitHub Action, a skill that makes an agent run skill-vet before installing other skills, example clean and
  malicious skills, and a generated rules reference.
