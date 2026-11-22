# Rules

Generated from `src/skill_vet/rules/registry.py` by `scripts/gen_rules_doc.py`. Do not edit by hand.

Severities are defaults. Some rules raise or lower severity depending on the evidence, as noted in the
description. Skip a rule with `--ignore SV203`, or only for some paths with `--ignore SV203:cleanup/*`.

| Rule | Severity | Title | OWASP |
| --- | --- | --- | --- |
| [SV001](#sv001) | low | Invalid skill manifest | LLM03:2025 Supply Chain |
| [SV002](#sv002) | info | Skill name does not follow the format | LLM03:2025 Supply Chain |
| [SV101](#sv101) | high | Instructions that override the agent or deceive the user | LLM01:2025 Prompt Injection |
| [SV102](#sv102) | high | Hidden Unicode characters | LLM01:2025 Prompt Injection |
| [SV103](#sv103) | medium | Text hidden from Markdown readers | LLM01:2025 Prompt Injection |
| [SV104](#sv104) | high | Encoded payload | LLM01:2025 Prompt Injection |
| [SV105](#sv105) | medium | Description tries to hijack skill selection | LLM06:2025 Excessive Agency |
| [SV201](#sv201) | high | Downloads and runs remote code | LLM03:2025 Supply Chain |
| [SV202](#sv202) | high | Obfuscated code execution | LLM03:2025 Supply Chain |
| [SV203](#sv203) | high | Destructive command | LLM06:2025 Excessive Agency |
| [SV204](#sv204) | high | Reads credentials | LLM02:2025 Sensitive Information Disclosure |
| [SV205](#sv205) | medium | Installs persistence | LLM06:2025 Excessive Agency |
| [SV206](#sv206) | medium | Sends data to an exfiltration-prone destination | LLM02:2025 Sensitive Information Disclosure |
| [SV207](#sv207) | high | Exfiltration URL template | LLM02:2025 Sensitive Information Disclosure |
| [SV208](#sv208) | medium | Executable or unreadable file | LLM03:2025 Supply Chain |
| [SV301](#sv301) | medium | Unrestricted tool access | LLM06:2025 Excessive Agency |
| [SV302](#sv302) | high | Weakens the agent's safety controls | LLM06:2025 Excessive Agency |
| [SV303](#sv303) | medium | Changes agent configuration, hooks or other skills | LLM06:2025 Excessive Agency |
| [SV304](#sv304) | high | Secret in skill | LLM02:2025 Sensitive Information Disclosure |
| [SV401](#sv401) | medium | Skill changed since it was approved | LLM03:2025 Supply Chain |
| [SV402](#sv402) | low | Skill not approved | LLM03:2025 Supply Chain |
| [SV403](#sv403) | info | Approved skill is missing | LLM03:2025 Supply Chain |
| [SV404](#sv404) | medium | Two skills share a name | LLM03:2025 Supply Chain |
| [SV405](#sv405) | high | Link or archive entry points outside the skill | LLM03:2025 Supply Chain |
| [SV406](#sv406) | low | Part of the skill was not scanned | LLM03:2025 Supply Chain |

## Manifest

### SV001

**Invalid skill manifest** - default severity `low` - LLM03:2025 Supply Chain

SKILL.md has no YAML front matter, the front matter does not parse, or `name` or `description` is missing. Agents may refuse to load the skill or load it with a name and description you have not reviewed.

**Remediation:** Add front matter with at least `name` and `description` between `---` lines at the top of SKILL.md.

### SV002

**Skill name does not follow the format** - default severity `info` - LLM03:2025 Supply Chain

The name should be lowercase letters, digits and hyphens, at most 64 characters, and match the folder name. A name that differs from its folder makes it harder to tell which skill an agent actually loaded.

**Remediation:** Rename the skill or its folder so they match.

## Hidden and injected instructions

### SV101

**Instructions that override the agent or deceive the user** - default severity `high` - LLM01:2025 Prompt Injection

A skill is a set of instructions, so instructions alone are expected. These are not: telling the agent to ignore its earlier or system instructions, to keep something from the user, to act secretly, to adopt a new role, to reveal its system prompt, or chat-template tokens that fake a system message.

**Remediation:** Remove the text. A skill has no legitimate reason to override the agent's instructions or hide its actions.

### SV102

**Hidden Unicode characters** - default severity `high` - LLM01:2025 Prompt Injection

Unicode tag characters (which can carry invisible ASCII), bidirectional overrides or zero-width characters. They hide or reorder text for the person reviewing the skill while the agent still reads it. Tag characters and overrides are high severity; other invisible characters are medium.

**Remediation:** Delete the characters. `skill-vet inspect` shows where they are and decodes tag characters.

### SV103

**Text hidden from Markdown readers** - default severity `medium` - LLM01:2025 Prompt Injection

HTML comments, `[//]: #` comments and hidden HTML elements do not appear when SKILL.md is rendered on GitHub or in a marketplace, but the agent reads the raw file. Severity is high when the hidden text contains instructions, commands or URLs, and low for long comments with nothing suspicious in them.

**Remediation:** Read the hidden text with `skill-vet inspect`. Move anything legitimate into visible text.

### SV104

**Encoded payload** - default severity `high` - LLM01:2025 Prompt Injection

A base64 string that decodes to instructions for the agent or to a shell command. Encoding hides the payload from reviewers and keyword filters; agents and shells decode it readily.

**Remediation:** Remove the encoded text and find out where the skill came from.

### SV105

**Description tries to hijack skill selection** - default severity `medium` - LLM06:2025 Excessive Agency

Agents choose a skill by its description. A description that says to use the skill for every request, before or instead of other skills, or that is unusually long, makes the agent load it when it should not, which is how a malicious skill gets its instructions in front of the model.

**Remediation:** Describe what the skill does and when it applies, nothing more.

## Dangerous code

### SV201

**Downloads and runs remote code** - default severity `high` - LLM03:2025 Supply Chain

Piping a download into a shell or interpreter (`curl | sh`, `iwr | iex`, `exec(urlopen(...))`), downloading a file and running it, or opening a reverse shell. What runs can change at any time after review, and it runs with the agent's permissions. Installing a package straight from a URL or git repository is medium severity. Well-known installers that use `curl | sh` are reported too: pin a version or install them separately.

**Remediation:** Ship the code in the skill so it can be reviewed and pinned, or install a pinned, published package.

### SV202

**Obfuscated code execution** - default severity `high` - LLM03:2025 Supply Chain

Decoding and running code in one step (`base64 -d | sh`, `exec(b64decode(...))`, `powershell -enc`, long `chr()` chains). Legitimate skills have no reason to hide what they run.

**Remediation:** Replace the obfuscated code with readable source, or do not install the skill.

### SV203

**Destructive command** - default severity `high` - LLM06:2025 Excessive Agency

Commands that delete a home folder or the whole disk, format or overwrite a device, or fork-bomb the machine. Force pushes are medium severity.

**Remediation:** Remove the command, or scope it to a path the skill creates.

### SV204

**Reads credentials** - default severity `high` - LLM02:2025 Sensitive Information Disclosure

Access to SSH keys, cloud and registry credentials, browser password and cookie stores, keychains or the system password file. Reading `.env` files or dumping all environment variables is medium severity, raised to high when the same file also makes network requests.

**Remediation:** A skill should receive the one credential it needs from the user, not search for credentials.

### SV205

**Installs persistence** - default severity `medium` - LLM06:2025 Excessive Agency

Cron jobs, systemd units, launch agents, Windows Run keys and scheduled tasks, git hooks, setuid bits, or edits to shell startup files: anything that keeps running after the agent session ends. Adding an SSH authorized key is high severity.

**Remediation:** Remove it. A skill runs when the agent calls it; it should not install anything that runs on its own.

### SV206

**Sends data to an exfiltration-prone destination** - default severity `medium` - LLM02:2025 Sensitive Information Disclosure

Requests to request catchers, paste sites, tunnels, chat webhooks or raw IP addresses, or uploads of local files (`curl -F file=@...`). High severity when the same file also reads credentials.

**Remediation:** Check what is sent and where. Legitimate skills talk to the documented API of the service they wrap.

### SV207

**Exfiltration URL template** - default severity `high` - LLM02:2025 Sensitive Information Disclosure

A URL with a placeholder such as {conversation}, {{secret}} or $TOKEN. If the agent fills it in and renders it or fetches it, the data goes to that host; a Markdown image does it without a click. Images are high severity, links medium.

**Remediation:** Remove the URL.

### SV208

**Executable or unreadable file** - default severity `medium` - LLM03:2025 Supply Chain

A compiled binary, bytecode or nested archive. Its behaviour cannot be reviewed from the skill, and nothing else in this scan applies to it. Other binary files (images, fonts) are listed by `skill-vet inspect`.

**Remediation:** Ship source code instead, or verify the binary's origin and pin its hash.

## Permissions and agent safety

### SV301

**Unrestricted tool access** - default severity `medium` - LLM06:2025 Excessive Agency

`allowed-tools` grants a shell or every tool without a scope (`Bash`, `Bash(*)`, `*`). The agent can then run any command while the skill is active without asking first.

**Remediation:** Scope the grant to the commands the skill needs, for example `Bash(git status:*)`.

### SV302

**Weakens the agent's safety controls** - default severity `high` - LLM06:2025 Excessive Agency

Tells the agent to act without asking the user, to skip confirmations, to disable a sandbox, antivirus or security checks, or uses flags that bypass permission prompts.

**Remediation:** Remove the text. Approval prompts are the user's control over the agent; a skill must not switch them off.

### SV303

**Changes agent configuration, hooks or other skills** - default severity `medium` - LLM06:2025 Excessive Agency

Writes to MCP server configuration, agent settings or instruction files, or to other skills, or defines hooks that run commands automatically. A skill that rewrites the agent's configuration can grant itself more access or plant instructions that outlive it.

**Remediation:** Remove it, or document the change and let the user make it.

### SV304

**Secret in skill** - default severity `high` - LLM02:2025 Sensitive Information Disclosure

A private key or access token in the skill's files. Anyone who installs the skill gets it. The evidence is redacted.

**Remediation:** Remove the secret, rotate it, and have the skill read credentials from the environment.

## Integrity and coverage (SV401 to SV403 need --lock)

### SV401

**Skill changed since it was approved** - default severity `medium` - LLM03:2025 Supply Chain

A file was added, removed or changed since the skill was pinned with `skill-vet pin`. Rug pulls work this way: a reviewed skill is updated with a malicious version. The evidence lists the files that changed.

**Remediation:** Review the changes, then run `skill-vet pin` again to approve them.

### SV402

**Skill not approved** - default severity `low` - LLM03:2025 Supply Chain

The skill is not in the lockfile, so it was added since the last review.

**Remediation:** Review the skill, then run `skill-vet pin` to approve it.

### SV403

**Approved skill is missing** - default severity `info` - LLM03:2025 Supply Chain

A skill in the lockfile was not found. This is usually a deliberate removal.

**Remediation:** Run `skill-vet pin` to update the lockfile.

### SV404

**Two skills share a name** - default severity `medium` - LLM03:2025 Supply Chain

Two installed skills declare the same name, so which one the agent loads depends on search order. A malicious skill can shadow a trusted one this way.

**Remediation:** Remove or rename one of them.

### SV405

**Link or archive entry points outside the skill** - default severity `high` - LLM03:2025 Supply Chain

A symbolic link whose target is outside the skill folder, or an archive entry with an absolute path or `..`. Installing the skill could read or overwrite files elsewhere, for example SSH keys or shell startup files.

**Remediation:** Remove the link or entry. Skills should be self-contained.

### SV406

**Part of the skill was not scanned** - default severity `low` - LLM03:2025 Supply Chain

A file was too large, could not be read or decoded, or the skill has more files than the limit, so it was not checked. The agent may still read it.

**Remediation:** Check the file by hand, or raise the limit with `--max-file-size`.
