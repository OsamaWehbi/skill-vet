---
name: changelog-writer
description: Drafts a CHANGELOG entry from the git history since the last tag. Use when the user asks for release notes or a changelog entry.
allowed-tools: Read, Grep, Bash(git log:*), Bash(git describe:*), Bash(python scripts/collect.py:*)
---

# Changelog writer

1. Find the last release tag with `git describe --tags --abbrev=0`.
2. Run `python scripts/collect.py <tag>` to list the commits since that tag, grouped by conventional-commit type.
3. Write the entry in the style described in [references/style.md](references/style.md).
4. Show the draft to the user and ask where to save it before writing any file.

<!-- Keep the type list in sync with scripts/collect.py. -->

Skip merge commits and commits of type `chore` unless the user asks for them.
