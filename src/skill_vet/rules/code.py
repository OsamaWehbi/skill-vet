"""Detectors for what a skill's scripts and commands do.

They run on every text file of a skill, not only on scripts: the agent runs the commands in SKILL.md and in
reference documents just as readily as a shipped script. Patterns stay on one line so a report can point at it.
"""

from __future__ import annotations

import re

from skill_vet.models import Severity
from skill_vet.rules.text import Hit, snippet

H, M = Severity.HIGH, Severity.MEDIUM
IC = re.I

SHELLS = r"(sudo\s+(-\S+\s+)*)?(env\s+\S+=\S*\s+)*(ba|z|da|k|fi)?sh\b"

PATTERNS: dict[str, list[tuple[str, re.Pattern[str], Severity]]] = {
    "SV201": [
        (
            "pipes a download into a shell",
            re.compile(
                r"\b(curl|wget)\b[^\n|]*\|\s*" + SHELLS + r"|\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(python[0-9.]*|perl|"
                r"ruby|node|php)\b"
            ),
            H,
        ),
        (
            "shell runs a download",
            re.compile(
                r"\b(ba|z)?sh\s+(-c\s+)?[\"']?\s*(<\(|\$\()\s*(curl|wget)\b|\beval\s+[\"']?\$\(\s*(curl|wget)\b"
                r"|\bsource\s+<\(\s*(curl|wget)\b"
            ),
            H,
        ),
        (
            "PowerShell downloads and runs",
            re.compile(
                r"\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]*\|\s*(iex|Invoke-Expression)\b"
                r"|\b(iex|Invoke-Expression)\b[^\n]{0,20}(New-Object\s+(System\.)?Net\.WebClient|\b(iwr|irm|"
                r"Invoke-WebRequest|Invoke-RestMethod)\b|DownloadString)"
                r"|DownloadString\([^\n]*\|\s*(iex|Invoke-Expression)\b",
                IC,
            ),
            H,
        ),
        (
            "runs code fetched from a URL",
            re.compile(
                r"\b(exec|eval)\s*\([^\n]{0,80}\b(urlopen|urllib\.request|requests\.get|httpx\.get|fetch\(|"
                r"axios\.get|https?\.get)"
            ),
            H,
        ),
        (
            "downloads then runs a file",
            re.compile(
                r"\b(curl|wget)\b[^\n]*\s(-o|-O|--output|-OutFile)\s*\S+[^\n]*(&&|;)\s*(chmod\s+\+x\b|\./|(ba|z)?sh\s+"
                r"\S|python[0-9.]*\s+\S)"
            ),
            H,
        ),
        (
            "opens a reverse shell",
            re.compile(
                r"/dev/tcp/[^\s/]+/\d+|\bnc(at)?\b[^\n]*\s-[a-z]*[ec]\s+(/bin/|cmd|powershell|bash|sh\b)"
                r"|\bsocat\b[^\n]*\bexec:|\bbash\s+-i\s*>&|\bpty\.spawn\(|\bmkfifo\b[^\n]*\bnc\b",
                IC,
            ),
            H,
        ),
        (
            "installs a package from a URL",
            re.compile(
                r"\b(pip3?|uv\s+pip|pipx)\s+install\b[^\n]*\s(git\+|https?://)\S+"
                r"|\bnpm\s+(install|i)\b[^\n]*\s(https?://|git\+|github:)\S+"
            ),
            M,
        ),
    ],
    "SV202": [
        (
            "decodes and runs base64",
            re.compile(
                r"\bbase64\s+(-d|--decode|-D)\b[^\n]*\|\s*"
                + SHELLS
                + r"|\becho\s+[\"']?[A-Za-z0-9+/=]{20,}[\"']?\s*\|\s*base64\s+(-d|--decode|-D)\b"
            ),
            H,
        ),
        (
            "executes decoded data",
            re.compile(
                r"\b(exec|eval)\s*\(\s*([\w.]+\.)?(b64decode|b32decode|a85decode|decodebytes|decompress|fromhex|"
                r"unhexlify)\s*\(|\b(exec|eval)\s*\(\s*(__import__|codecs\.decode|bytes\.fromhex|zlib\.|marshal\.|"
                r"base64\.)"
            ),
            H,
        ),
        (
            "PowerShell encoded command",
            re.compile(
                r"\b(powershell|pwsh)(\.exe)?\b[^\n]*\s-(e|ec|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", IC
            ),
            H,
        ),
        (
            "JavaScript evaluates decoded data",
            re.compile(r"\b(eval|Function)\s*\(\s*(atob\(|Buffer\.from\()|new\s+Function\s*\(\s*(atob|Buffer\.from)"),
            H,
        ),
        (
            "character-code obfuscation",
            re.compile(
                r"(chr\(\s*\d+\s*\)\s*\+\s*){8,}|String\.fromCharCode\(\s*(\d+\s*,\s*){8,}|(\[char\]\s*\d+\s*\+\s*){8,}",
                IC,
            ),
            H,
        ),
    ],
    "SV203": [
        (
            "deletes the home folder or the whole disk",
            re.compile(
                r"\brm\s+(-[a-zA-Z-]+\s+)*-[a-zA-Z]*(r[a-zA-Z]*f|f[a-zA-Z]*r)[a-zA-Z]*\s+(-[a-zA-Z-]+\s+)*[\"']?"
                r"(/|/\*|~|~/|~/\*|\$HOME|\$HOME/|\$HOME/\*|\$\{HOME\}/?)[\"']?(?=\s|;|&|\||$)"
                r"|--no-preserve-root"
            ),
            H,
        ),
        (
            "deletes a home or system folder on Windows",
            re.compile(
                r"\b(Remove-Item|rmdir|rd|del)\b[^\n]*(-Recurse|/s)\b[^\n]*(\$env:USERPROFILE|\$HOME\b|~[\\/]?(\s|$)|"
                r"[\"']?C:\\+(\*|Windows|Users)?[\"']?(\s|$))",
                IC,
            ),
            H,
        ),
        (
            "deletes the home folder or the whole disk from code",
            re.compile(
                r"\b(shutil\.rmtree|fs\.rmSync|fs\.rm|rimraf)\s*\(\s*(os\.path\.expanduser\(\s*[\"']~[\"']\s*\)|"
                r"Path\.home\(\)|os\.homedir\(\)|[\"']/[\"']|[\"']~[\"'])"
            ),
            H,
        ),
        (
            "formats or overwrites a disk",
            re.compile(
                r"\bmkfs(\.\w+)?\s|\bdd\b[^\n]*\bof=/dev/(sd|hd|nvme|disk|mmcblk|xvd|rdisk)|\bformat(\.com)?\s+[a-z]:"
                r"(\s|$)|\bdiskpart\b|\bwipefs\b|\bshred\b[^\n]*/dev/|\bdiskutil\s+(eraseDisk|zeroDisk|secureErase)",
                IC,
            ),
            H,
        ),
        ("fork bomb", re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"), H),
        (
            "opens up the whole file system",
            re.compile(r"\bchmod\s+(-R\s+)?0?777\s+/(\s|$)|\bchown\s+-R\s+\S+\s+/(\s|$)"),
            H,
        ),
        ("force push", re.compile(r"\bgit\s+push\b[^\n]*(\s--force(?!-with-lease)\b|\s-f\b)"), M),
    ],
    "SV204": [
        (
            "SSH private key",
            re.compile(r"\.ssh[/\\]+(id_[a-z0-9]+|identity)\b(?!\.pub)|\bid_(rsa|ed25519|ecdsa|dsa)\b(?!\.pub)"),
            H,
        ),
        (
            "cloud credentials",
            re.compile(
                r"\.aws[/\\]+credentials\b|\.config[/\\]+gcloud\b|application_default_credentials\.json"
                r"|\.azure[/\\]+(accessTokens|msal_token_cache|azureProfile)|\.kube[/\\]+config\b"
                r"|\.docker[/\\]+config\.json|\.oci[/\\]+config\b"
            ),
            H,
        ),
        (
            "git or registry credentials",
            re.compile(
                r"\.netrc\b|\.git-credentials\b|\.config[/\\]+gh[/\\]+hosts\.ya?ml|\bgh\s+auth\s+token\b"
                r"|\.cargo[/\\]+credentials|\.gem[/\\]+credentials|\.terraform\.d[/\\]+credentials"
                r"|\bgit\s+credential\s+fill\b"
            ),
            H,
        ),
        (
            "browser passwords or cookies",
            re.compile(
                r"(Chrome|Chromium|Edge|Brave|BraveSoftware|Firefox|Mozilla|Opera|Vivaldi)[^\n]{0,80}(Login Data|"
                r"Cookies|Local State|logins\.json|key4\.db|cookies\.sqlite|Web Data)\b|\bbrowser_cookie3\b"
            ),
            H,
        ),
        (
            "keychain or credential store",
            re.compile(
                r"\bsecurity\s+(find-generic-password|find-internet-password|dump-keychain)\b|Library/Keychains\b"
                r"|\bcmdkey\s+/list\b|\bvaultcmd\b|Get-StoredCredential\b|\bsecret-tool\s+lookup\b"
                r"|\bkeyring\.get_password\(",
                IC,
            ),
            H,
        ),
        (
            "system password files",
            re.compile(r"/etc/shadow\b|/etc/sudoers\b|\breg(\.exe)?\s+save\s+hklm\\+(sam|security|system)\b", IC),
            H,
        ),
        (
            "crypto wallets",
            re.compile(
                r"\bwallet\.dat\b|[/\\]\.?electrum[/\\]|\bExodus[/\\]|ethereum[/\\]keystore|Local Extension Settings"
            ),
            H,
        ),
        ("GPG secret keys", re.compile(r"\.gnupg[/\\]+(private-keys|secring)|\bgpg\s+--export-secret-keys\b"), H),
        (
            "reads .env or registry config files",
            re.compile(
                r"(\bcat|\btype|Get-Content|\bgc|\bsource|open\(|read_text\(|readFileSync\(|\bless|\bhead|\btail|"
                r"\bstrings)\s*\(?\s*[\"']?[^\s\"'()]*(\.env(\.[a-z]+)?|\.npmrc|\.pypirc)\b(?!\.example|\.sample)",
                IC,
            ),
            M,
        ),
        (
            "dumps every environment variable",
            re.compile(
                r"\bprintenv\s*(\||>|$)|(^|[;&|]\s*)env\s*(\||>)|\bos\.environ\.(items|copy|keys|values)\(\)"
                r"|dict\(\s*os\.environ\s*\)|json\.dumps\(\s*(dict\()?\s*os\.environ\b|JSON\.stringify\(\s*process\.env\b"
                r"|Object\.(entries|keys|values)\(\s*process\.env\s*\)|\b(Get-ChildItem|gci|dir|ls)\s+env:",
                re.I | re.M,
            ),
            M,
        ),
    ],
    "SV205": [
        ("SSH authorized key", re.compile(r"\bauthorized_keys2?\b"), H),
        ("sudoers entry", re.compile(r"\bNOPASSWD\b|(>>?|\btee\b)[^\n]*/etc/sudoers"), H),
        ("cron job", re.compile(r"\bcrontab\b|/etc/cron\.|/var/spool/cron"), M),
        (
            "systemd unit",
            re.compile(r"\bsystemctl\s+(--user\s+)?enable\b|/etc/systemd/system/|\.config/systemd/user/"),
            M,
        ),
        ("launch agent", re.compile(r"\blaunchctl\s+(load|bootstrap|submit)\b|Library/Launch(Agents|Daemons)\b"), M),
        (
            "Windows autorun",
            re.compile(
                r"CurrentVersion\\+Run(Once)?\b|\bschtasks(\.exe)?\s+/create\b|\bRegister-ScheduledTask\b"
                r"|Start Menu\\+Programs\\+Startup|shell:startup|\bNew-Service\b|\bsc(\.exe)?\s+create\b"
                r"|\bWMI\b[^\n]*EventFilter|__EventFilter",
                IC,
            ),
            M,
        ),
        (
            "shell startup file",
            re.compile(
                r"(>>?|\btee\b|Add-Content|Out-File|Set-Content|open\([^)\n]*[\"'][aw]\+?[\"']|appendFile)[^\n]*"
                r"(\.bashrc|\.zshrc|\.bash_profile|\.bash_login|\.profile|\.zprofile|\.zshenv|\.zlogin|config\.fish|"
                r"PowerShell_profile\.ps1|\$PROFILE)\b"
            ),
            M,
        ),
        ("git hooks", re.compile(r"\.git[/\\]+hooks[/\\]|\bcore\.hooksPath\b"), M),
        ("setuid bit", re.compile(r"\bchmod\s+([ugoa]*\+s\b|[4-7][0-7]{3}\b)"), M),
    ],
}

EXFIL_HOST = re.compile(
    r"\b(webhook\.site|requestbin\.(com|net)|[a-z0-9-]+\.m\.pipedream\.net|[a-z0-9-]+\.ngrok(-free)?\.(io|app|dev)|"
    r"ngrok\.io|[a-z0-9-]+\.trycloudflare\.com|pastebin\.com|paste\.ee|hastebin\.com|transfer\.sh|file\.io|0x0\.st|"
    r"temp\.sh|bashupload\.com|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/services|"
    r"[a-z0-9-]+\.oast\.(fun|pro|live|site|online|me)|interact\.sh|[a-z0-9.-]*burpcollaborator\.net|"
    r"[a-z0-9-]+\.requestcatcher\.com|[a-z0-9-]+\.beeceptor\.com|[a-z0-9-]+\.serveo\.net|[a-z0-9-]+\.loca\.lt|"
    r"[a-z0-9-]+\.workers\.dev|[a-z0-9-]+\.free\.pinggy\.io)",
    re.I,
)
RAW_IP_URL = re.compile(
    r"\b(https?|ftp|wss?)://(?!(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0|169\.254\.))"
    r"\d{1,3}(\.\d{1,3}){3}\b",
    re.I,
)
UPLOAD = re.compile(
    r"\bcurl\b[^\n]*\s(-F|--form|-T|--upload-file|--data-binary|--data|--data-raw|--data-urlencode|-d)\s*[\"']?"
    r"[\w.-]*=?@(?!-\s)\S|\bInvoke-(WebRequest|RestMethod)\b[^\n]*-InFile\b|\brequests\.(post|put)\([^\n]*\bfiles\s*="
    r"|\bwget\b[^\n]*--post-file\b|\bscp\s+[^\n]*\s\S+@\S+:",
    re.I,
)
NETWORK = re.compile(
    r"\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|nc|ncat|scp|rsync|ftp|sftp)\b|requests\.(get|post|put|"
    r"patch|request)\(|\bhttpx\.|urllib\.request|\burlopen\(|\bfetch\(|\baxios\b|\bhttp\.client\b|https?\.request\(|"
    r"socket\.(socket|create_connection)\(|net\.connect\(|\bsmtplib\b|WebClient\b|\bdig\b|\bnslookup\b",
    re.I,
)
SHELL_EXEC = re.compile(
    r"\bsubprocess\b|\bos\.(system|popen|exec\w*|spawn\w*)\(|\bchild_process\b|\bexecSync\(|\bspawnSync?\(|"
    r"\bStart-Process\b|\bInvoke-Expression\b|\bRuntime\.getRuntime\(\)\.exec|`[^`\n]*\$\(",
)
FILE_WRITE = re.compile(
    r"\bwrite_text\(|\bwrite_bytes\(|open\([^)\n]*[\"'][wax]b?\+?[\"']|\bwriteFile(Sync)?\(|\bSet-Content\b|"
    r"\bOut-File\b|\bAdd-Content\b|\btee\b|(?<![<>=])>>?\s*[\w~$./\\-]|\bmv\s|\bcp\s|\brm\s|\bshutil\.",
)

CONFIG_TARGET = re.compile(
    r"\.mcp\.json\b|\bmcp\.json\b|\bmcpServers\b|\bmcp_servers\b|\bAGENTS\.md\b|\bsettings(\.local)?\.json\b"
    r"|\.cursorrules\b|\.windsurfrules\b|copilot-instructions\.md\b|\bSKILL\.md\b|[/\\]skills[/\\]"
)
WRITE_VERB = re.compile(
    r"(>>?|\btee\b|write_text|write\(|writeFile|json\.dump|Set-Content|Add-Content|Out-File|\bcp\s|\bmv\s|"
    r"\bcopy\b|\bsed\s+-i|\b(edit|modify|update|overwrite|replace|append|insert|register|add)\b)",
    re.I,
)


def _match(rule: str, label: str, text: str, m: re.Match[str], severity: Severity) -> Hit:
    return Hit(rule, m.start(), m.end(), f"[{label}] {snippet(text, m.start(), m.end())}", severity, label)


def commands(text: str) -> list[Hit]:
    """SV201 to SV206, and SV303 for commands or instructions that write agent configuration or other skills."""
    hits: list[Hit] = []
    for rule, patterns in PATTERNS.items():
        for label, pattern, severity in patterns:
            m = pattern.search(text)
            if m:
                hits.append(_match(rule, label, text, m, severity))
    credentials = any(h.rule_id == "SV204" and h.severity is Severity.HIGH for h in hits)
    network = bool(NETWORK.search(text))
    if network:
        hits = [
            Hit(
                h.rule_id,
                h.start,
                h.end,
                h.evidence + " (the same file makes network requests)",
                Severity.HIGH,
                h.label,
            )
            if h.rule_id == "SV204" and h.severity is Severity.MEDIUM
            else h
            for h in hits
        ]
        credentials = credentials or any(h.rule_id == "SV204" for h in hits)
    severity = Severity.HIGH if credentials else Severity.MEDIUM
    for label, pattern in (
        ("exfiltration-prone host", EXFIL_HOST),
        ("raw IP address", RAW_IP_URL),
        ("file upload", UPLOAD),
    ):
        m = pattern.search(text)
        if m:
            hit = _match("SV206", label, text, m, severity)
            if credentials:
                hit.evidence += " (the same file reads credentials)"
            hits.append(hit)
    offset = 0
    for line in text.splitlines(keepends=True):
        target = CONFIG_TARGET.search(line)
        if target and WRITE_VERB.search(line):
            start = offset + target.start()
            hits.append(
                Hit(
                    "SV303",
                    start,
                    start + len(target.group(0)),
                    f"[writes agent configuration] {snippet(line, 0, len(line), 0)}",
                    Severity.MEDIUM,
                    "config",
                )
            )
            break
        offset += len(line)
    return hits


def is_dangerous(text: str) -> bool:
    """True when the text contains any high-severity command. Used to rate hidden Markdown."""
    return any(h.severity is Severity.HIGH for h in commands(text)) or bool(EXFIL_HOST.search(text))


def capabilities(text: str) -> set[str]:
    """Coarse capabilities for `skill-vet inspect`: network, shell, file-write, credentials, environment."""
    caps = set()
    if NETWORK.search(text):
        caps.add("network")
    if SHELL_EXEC.search(text):
        caps.add("shell")
    if FILE_WRITE.search(text):
        caps.add("file-write")
    for label, pattern, _ in PATTERNS["SV204"]:
        if pattern.search(text):
            caps.add("environment" if label.startswith(("dumps", "reads .env")) else "credentials")
    return caps
