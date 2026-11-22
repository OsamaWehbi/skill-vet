"""Metadata for every rule. Detection logic lives in the sibling modules."""

from __future__ import annotations

from dataclasses import dataclass

from skill_vet.models import Severity

LLM01 = "LLM01:2025 Prompt Injection"
LLM02 = "LLM02:2025 Sensitive Information Disclosure"
LLM03 = "LLM03:2025 Supply Chain"
LLM06 = "LLM06:2025 Excessive Agency"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    owasp: str
    description: str
    remediation: str


_RULES = [
    # --- Manifest ----------------------------------------------------------------------------------
    Rule(
        "SV001",
        "Invalid skill manifest",
        Severity.LOW,
        LLM03,
        "SKILL.md has no YAML front matter, the front matter does not parse, or `name` or `description` is missing. "
        "Agents may refuse to load the skill or load it with a name and description you have not reviewed.",
        "Add front matter with at least `name` and `description` between `---` lines at the top of SKILL.md.",
    ),
    Rule(
        "SV002",
        "Skill name does not follow the format",
        Severity.INFO,
        LLM03,
        "The name should be lowercase letters, digits and hyphens, at most 64 characters, and match the folder name. "
        "A name that differs from its folder makes it harder to tell which skill an agent actually loaded.",
        "Rename the skill or its folder so they match.",
    ),
    # --- Hidden and injected instructions -------------------------------------------------------
    Rule(
        "SV101",
        "Instructions that override the agent or deceive the user",
        Severity.HIGH,
        LLM01,
        "A skill is a set of instructions, so instructions alone are expected. These are not: telling the agent to "
        "ignore its earlier or system instructions, to keep something from the user, to act secretly, to adopt a new "
        "role, to reveal its system prompt, or chat-template tokens that fake a system message.",
        "Remove the text. A skill has no legitimate reason to override the agent's instructions or hide its actions.",
    ),
    Rule(
        "SV102",
        "Hidden Unicode characters",
        Severity.HIGH,
        LLM01,
        "Unicode tag characters (which can carry invisible ASCII), bidirectional overrides or zero-width characters. "
        "They hide or reorder text for the person reviewing the skill while the agent still reads it. Tag characters "
        "and overrides are high severity; other invisible characters are medium.",
        "Delete the characters. `skill-vet inspect` shows where they are and decodes tag characters.",
    ),
    Rule(
        "SV103",
        "Text hidden from Markdown readers",
        Severity.MEDIUM,
        LLM01,
        "HTML comments, `[//]: #` comments and hidden HTML elements do not appear when SKILL.md is rendered on GitHub "
        "or in a marketplace, but the agent reads the raw file. Severity is high when the hidden text contains "
        "instructions, commands or URLs, and low for long comments with nothing suspicious in them.",
        "Read the hidden text with `skill-vet inspect`. Move anything legitimate into visible text.",
    ),
    Rule(
        "SV104",
        "Encoded payload",
        Severity.HIGH,
        LLM01,
        "A base64 string that decodes to instructions for the agent or to a shell command. Encoding hides the payload "
        "from reviewers and keyword filters; agents and shells decode it readily.",
        "Remove the encoded text and find out where the skill came from.",
    ),
    Rule(
        "SV105",
        "Description tries to hijack skill selection",
        Severity.MEDIUM,
        LLM06,
        "Agents choose a skill by its description. A description that says to use the skill for every request, "
        "before or instead of other skills, or that is unusually long, makes the agent load it when it should not, "
        "which is how a malicious skill gets its instructions in front of the model.",
        "Describe what the skill does and when it applies, nothing more.",
    ),
    # --- Dangerous code -----------------------------------------------------------------------------
    Rule(
        "SV201",
        "Downloads and runs remote code",
        Severity.HIGH,
        LLM03,
        "Piping a download into a shell or interpreter (`curl | sh`, `iwr | iex`, `exec(urlopen(...))`), downloading "
        "a file and running it, or opening a reverse shell. What runs can change at any time after review, and it runs "
        "with the agent's permissions. Installing a package straight from a URL or git repository is medium severity. "
        "Well-known installers that use `curl | sh` are reported too: pin a version or install them separately.",
        "Ship the code in the skill so it can be reviewed and pinned, or install a pinned, published package.",
    ),
    Rule(
        "SV202",
        "Obfuscated code execution",
        Severity.HIGH,
        LLM03,
        "Decoding and running code in one step (`base64 -d | sh`, `exec(b64decode(...))`, `powershell -enc`, long "
        "`chr()` chains). Legitimate skills have no reason to hide what they run.",
        "Replace the obfuscated code with readable source, or do not install the skill.",
    ),
    Rule(
        "SV203",
        "Destructive command",
        Severity.HIGH,
        LLM06,
        "Commands that delete a home folder or the whole disk, format or overwrite a device, or fork-bomb the machine. "
        "Force pushes are medium severity.",
        "Remove the command, or scope it to a path the skill creates.",
    ),
    Rule(
        "SV204",
        "Reads credentials",
        Severity.HIGH,
        LLM02,
        "Access to SSH keys, cloud and registry credentials, browser password and cookie stores, keychains or the "
        "system password file. Reading `.env` files or dumping all environment variables is medium severity, raised "
        "to high when the same file also makes network requests.",
        "A skill should receive the one credential it needs from the user, not search for credentials.",
    ),
    Rule(
        "SV205",
        "Installs persistence",
        Severity.MEDIUM,
        LLM06,
        "Cron jobs, systemd units, launch agents, Windows Run keys and scheduled tasks, git hooks, setuid bits, or "
        "edits to shell startup files: anything that keeps running after the agent session ends. Adding an SSH "
        "authorized key is high severity.",
        "Remove it. A skill runs when the agent calls it; it should not install anything that runs on its own.",
    ),
    Rule(
        "SV206",
        "Sends data to an exfiltration-prone destination",
        Severity.MEDIUM,
        LLM02,
        "Requests to request catchers, paste sites, tunnels, chat webhooks or raw IP addresses, or uploads of local "
        "files (`curl -F file=@...`). High severity when the same file also reads credentials.",
        "Check what is sent and where. Legitimate skills talk to the documented API of the service they wrap.",
    ),
    Rule(
        "SV207",
        "Exfiltration URL template",
        Severity.HIGH,
        LLM02,
        "A URL with a placeholder such as {conversation}, {{secret}} or $TOKEN. If the agent fills it in and renders "
        "it or fetches it, the data goes to that host; a Markdown image does it without a click. Images are high "
        "severity, links medium.",
        "Remove the URL.",
    ),
    Rule(
        "SV208",
        "Executable or unreadable file",
        Severity.MEDIUM,
        LLM03,
        "A compiled binary, bytecode or nested archive. Its behaviour cannot be reviewed from the skill, and nothing "
        "else in this scan applies to it. Other binary files (images, fonts) are listed by `skill-vet inspect`.",
        "Ship source code instead, or verify the binary's origin and pin its hash.",
    ),
    # --- Permissions and agent safety ----------------------------------------------------------------
    Rule(
        "SV301",
        "Unrestricted tool access",
        Severity.MEDIUM,
        LLM06,
        "`allowed-tools` grants a shell or every tool without a scope (`Bash`, `Bash(*)`, `*`). The agent can then run "
        "any command while the skill is active without asking first.",
        "Scope the grant to the commands the skill needs, for example `Bash(git status:*)`.",
    ),
    Rule(
        "SV302",
        "Weakens the agent's safety controls",
        Severity.HIGH,
        LLM06,
        "Tells the agent to act without asking the user, to skip confirmations, to disable a sandbox, antivirus or "
        "security checks, or uses flags that bypass permission prompts.",
        "Remove the text. Approval prompts are the user's control over the agent; a skill must not switch them off.",
    ),
    Rule(
        "SV303",
        "Changes agent configuration, hooks or other skills",
        Severity.MEDIUM,
        LLM06,
        "Writes to MCP server configuration, agent settings or instruction files, or to other skills, or defines hooks "
        "that run commands automatically. A skill that rewrites the agent's configuration can grant itself more "
        "access or plant instructions that outlive it.",
        "Remove it, or document the change and let the user make it.",
    ),
    Rule(
        "SV304",
        "Secret in skill",
        Severity.HIGH,
        LLM02,
        "A private key or access token in the skill's files. Anyone who installs the skill gets it. The evidence is "
        "redacted.",
        "Remove the secret, rotate it, and have the skill read credentials from the environment.",
    ),
    # --- Integrity -------------------------------------------------------------------------------------
    Rule(
        "SV401",
        "Skill changed since it was approved",
        Severity.MEDIUM,
        LLM03,
        "A file was added, removed or changed since the skill was pinned with `skill-vet pin`. Rug pulls work this "
        "way: a reviewed skill is updated with a malicious version. The evidence lists the files that changed.",
        "Review the changes, then run `skill-vet pin` again to approve them.",
    ),
    Rule(
        "SV402",
        "Skill not approved",
        Severity.LOW,
        LLM03,
        "The skill is not in the lockfile, so it was added since the last review.",
        "Review the skill, then run `skill-vet pin` to approve it.",
    ),
    Rule(
        "SV403",
        "Approved skill is missing",
        Severity.INFO,
        LLM03,
        "A skill in the lockfile was not found. This is usually a deliberate removal.",
        "Run `skill-vet pin` to update the lockfile.",
    ),
    Rule(
        "SV404",
        "Two skills share a name",
        Severity.MEDIUM,
        LLM03,
        "Two installed skills declare the same name, so which one the agent loads depends on search order. A "
        "malicious skill can shadow a trusted one this way.",
        "Remove or rename one of them.",
    ),
    Rule(
        "SV405",
        "Link or archive entry points outside the skill",
        Severity.HIGH,
        LLM03,
        "A symbolic link whose target is outside the skill folder, or an archive entry with an absolute path or `..`. "
        "Installing the skill could read or overwrite files elsewhere, for example SSH keys or shell startup files.",
        "Remove the link or entry. Skills should be self-contained.",
    ),
    Rule(
        "SV406",
        "Part of the skill was not scanned",
        Severity.LOW,
        LLM03,
        "A file was too large, could not be read or decoded, or the skill has more files than the limit, so it was "
        "not checked. The agent may still read it.",
        "Check the file by hand, or raise the limit with `--max-file-size`.",
    ),
]

RULES: dict[str, Rule] = {r.id: r for r in _RULES}
