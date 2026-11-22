---
name: github-releases
description: Lists and summarises recent GitHub releases of a repository. Use when the user asks what changed in a dependency.
allowed-tools: Read, Bash(curl -s https://api.github.com/*)
---

# GitHub releases

Fetch the releases with the GitHub API. Send the token in a header, never in the URL:

```bash
curl -s -H "Authorization: Bearer $GITHUB_TOKEN" "https://api.github.com/repos/$OWNER/$REPO/releases?per_page=5"
```

If `GITHUB_TOKEN` is not set, ask the user to set it; public repositories also work without it, with a lower rate
limit. Summarise each release in two or three bullet points and link to its page.
