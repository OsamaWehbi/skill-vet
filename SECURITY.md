# Security Policy

skill-vet reads skills that may have been written by an attacker, so its own behaviour matters. This document explains
how to report a vulnerability, what skill-vet does when it scans, and its known limitations.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's
[private vulnerability reporting](https://github.com/OsamaWehbi/skill-vet/security/advisories/new) on this
repository. You can expect an acknowledgement within 72 hours.

Useful reports include: a crafted skill or archive that crashes or hangs skill-vet, a way to make it read files
outside the paths it was given or write files anywhere, or a reliable way to hide a dangerous instruction or command
that is not already listed under known limitations.

## What skill-vet does when it scans

- It reads the files you point it at and nothing else. Symbolic links are recorded with their targets and never
  followed, so a link to `~/.ssh/id_rsa` is reported without being read.
- It never executes, imports or evaluates skill content. YAML front matter is parsed with a safe loader.
- Archives are read in memory. Nothing is extracted to disk, so entries with `..` or absolute paths cannot write
  anywhere.
- It makes no network connections. URLs are reported, never fetched.
- Reports quote short snippets of the skill. Secrets are redacted; other snippets are quoted as found, with invisible
  characters escaped.

## Threat model (summary)

| Threat | Control |
|---|---|
| Path traversal or links in archives | Entries are never extracted; `..`, absolute paths and links out of the skill are reported as SV405 |
| Symbolic links that point at secrets | Links are not followed during discovery or reading |
| Zip bombs and very large files | Per-file limit (`--max-file-size`, 5 MB by default) checked against the bytes actually read, not the header, plus a 200 MB total per archive and 5,000 files per skill |
| YAML tricks in front matter | `yaml.safe_load`, a 64 KB limit, and only string values are used for name and description |
| Hidden characters hide evidence from the reviewer | Evidence escapes non-printable characters; Unicode tag text is decoded and shown |
| Terminal escape sequences in skill text | Rich markup is escaped and control characters are shown as `\uXXXX` |
| Report injection into Markdown summaries | Table separators and backticks are escaped |
| A skill switching off its own findings | There are no inline suppression comments; ignores come only from the command line |
| Shell injection through the GitHub Action inputs | Inputs are passed as environment variables and split into an argument array, never interpolated into the script |

## Known limitations

- Detection is pattern-based. A clean report means no known technique was found, not that a skill is safe. Code that
  builds its commands at run time, or instructions written in plain persuasive language, can get through.
- Binaries are reported as unreviewable (SV208), not analysed.
- Dependencies declared by a skill (`requirements.txt`, `package.json`) are not resolved or audited.
- For skills from untrusted sources, keep the agent's approval prompts on even after a clean scan.

## Supported versions

Only the latest release receives security fixes during the 0.x series.
