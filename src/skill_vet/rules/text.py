"""Detectors for the instructions in a skill: overrides, hidden text, encoded payloads, exfiltration URLs,
attempts to switch off safety controls, description stuffing and secrets.

Each detector returns Hits with offsets into the text it was given, so the engine can report a line number.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

from skill_vet.models import Severity


@dataclass
class Hit:
    rule_id: str
    start: int
    end: int
    evidence: str
    severity: Severity | None = None
    label: str = ""


def snippet(text: str, start: int, end: int, width: int = 40) -> str:
    lo, hi = max(0, start - width), min(len(text), end + width)
    s = re.sub(r"\s+", " ", text[lo:hi]).strip()
    s = "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in s)
    return ("..." if lo else "") + s[:240] + ("..." if hi < len(text) else "")


def clean(text: str) -> str:
    """The whole text on one line, with invisible characters escaped."""
    return snippet(text, 0, len(text), 0)


def _first(patterns: list[tuple[str, re.Pattern[str]]], text: str) -> list[tuple[str, re.Match[str]]]:
    found = []
    for label, pattern in patterns:
        m = pattern.search(text)
        if m:
            found.append((label, m))
    return sorted(found, key=lambda lm: lm[1].start())


# --- SV101: instructions that override the agent or deceive the user ----------------------------------------

OVERRIDES: list[tuple[str, re.Pattern[str]]] = [
    (
        "ignore earlier instructions",
        re.compile(
            r"\b(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+|your\s+)?(previous|prior|above|earlier|other|"
            r"system|original|developer)\s+(instructions?|prompts?|rules|directions|guidelines|messages)",
            re.I,
        ),
    ),
    (
        "priority over other instructions",
        re.compile(
            r"\b(takes?|has|have)\s+(top\s+|highest\s+|absolute\s+)?(priority|precedence)\s+over\s+(all\s+|any\s+|the\s+|"
            r"your\s+)?(other\s+)?(previous|prior|system|user|developer|other)?\s*(instructions?|prompts?|rules|messages)",
            re.I,
        ),
    ),
    (
        "hide actions from the user",
        re.compile(
            r"\b(do\s+not|don't|never)\s+(tell|inform|mention\s+(this\s+)?to|reveal\s+(this\s+)?to|notify|alert|"
            r"disclose\s+(this\s+)?to)\s+(the\s+)?user"
            r"|\bwithout\s+(telling|informing|notifying|alerting)\s+(the\s+)?user"
            r"|\b(hide|conceal)\s+(this|these|it|them|the\s+\w+)\s+from\s+(the\s+)?user",
            re.I,
        ),
    ),
    (
        "covert behaviour",
        re.compile(
            r"\b(secretly|covertly|quietly|silently)\s+(send|forward|copy|upload|include|exfiltrate|post|transmit|"
            r"append|collect|attach|email|save|store)",
            re.I,
        ),
    ),
    (
        "role reassignment",
        re.compile(
            r"\byou\s+are\s+now\s+(in\s+)?(developer|dan|jailbreak|jailbroken|unrestricted|unfiltered|god|admin|root)\b"
            r"|\bnew\s+system\s+prompt\b|\bdeveloper\s+mode\s+(is\s+)?(enabled|on|activated)\b"
            r"|\byou\s+are\s+no\s+longer\s+(bound|restricted|limited)",
            re.I,
        ),
    ),
    (
        "prompt extraction",
        re.compile(
            r"\b(reveal|print|output|repeat|leak|send|show)\s+(your\s+|the\s+)?(full\s+)?(system\s+prompt|hidden\s+"
            r"instructions|initial\s+instructions|developer\s+message)",
            re.I,
        ),
    ),
    ("fake system block", re.compile(r"<\s*/?\s*(system|system_prompt|secret|hidden|admin|override)\s*>", re.I)),
    ("chat template tokens", re.compile(r"\[/?INST\]|<\|im_(start|end)\|>|<\|(system|user|assistant)\|>|<<SYS>>")),
]


def overrides(text: str) -> list[Hit]:
    found = _first(OVERRIDES, text)
    return [
        Hit("SV101", m.start(), m.end(), f"[{label}] {snippet(text, m.start(), m.end())}", label=label)
        for label, m in found
    ]


# --- SV302: weakens the agent's safety controls ----------------------------------------------------------------------

SAFETY: list[tuple[str, re.Pattern[str], Severity]] = [
    (
        "acts without asking the user",
        re.compile(
            r"\bwithout\s+(asking|prompting|confirming\s+with|checking\s+with|consulting|waiting\s+for)\s+(the\s+)?user"
            r"|\b(do\s+not|don't|never|no\s+need\s+to)\s+(ask|prompt|check\s+with|wait\s+for)\s+(the\s+user\s+)?(for\s+)?"
            r"(permission|confirmation|approval|consent)",
            re.I,
        ),
        Severity.HIGH,
    ),
    (
        "skips confirmations",
        re.compile(
            r"\bskip\s+(all\s+|any\s+|the\s+)?(confirmation|approval|permission|safety|security)\s+"
            r"(prompts?|checks?|steps?|dialogs?|questions?)",
            re.I,
        ),
        Severity.HIGH,
    ),
    (
        "disables protections",
        re.compile(
            r"\b(disable|turn\s+off|switch\s+off|bypass|circumvent|evade)\s+(the\s+|any\s+|all\s+|your\s+)?"
            r"(sandbox(ing)?|safety\s+(checks?|filters?|guidelines|rules)|security\s+(checks?|controls?|software|"
            r"warnings?)|guardrails?|anti-?virus|firewall|windows\s+defender|defender|edr|permission\s+(prompts?|"
            r"checks?|system)|approval\s+(prompts?|checks?))",
            re.I,
        ),
        Severity.HIGH,
    ),
    (
        "permission-bypass flag",
        re.compile(
            r"--dangerously-skip-permissions\b|--dangerously-bypass-approvals-and-sandbox\b|--yolo\b|\bbypassPermissions\b"
            r"|\bapproval[_-]policy\s*[=:]\s*[\"']?never\b|\bsandbox[_-]mode\s*[=:]\s*[\"']?danger-full-access"
            r"|--trust-all-tools\b|--allow-all-tools\b",
            re.I,
        ),
        Severity.HIGH,
    ),
    (
        "disables OS protection",
        re.compile(
            r"Set-MpPreference\b[^\n]*-Disable\w*|Add-MpPreference\b[^\n]*-Exclusion\w*|\bsetenforce\s+0\b"
            r"|\bspctl\s+--master-disable\b|\bcsrutil\s+disable\b|\bufw\s+disable\b|\bnetsh\s+advfirewall\s+set\s+"
            r"\w+\s+state\s+off",
            re.I,
        ),
        Severity.HIGH,
    ),
    (
        "skips checks",
        re.compile(r"\bgit\s+commit\b[^\n]*--no-verify\b|\bxattr\s+-[a-z]*d[a-z]*\s+com\.apple\.quarantine", re.I),
        Severity.MEDIUM,
    ),
]


def safety(text: str) -> list[Hit]:
    hits = []
    for label, pattern, severity in SAFETY:
        m = pattern.search(text)
        if m:
            hits.append(
                Hit("SV302", m.start(), m.end(), f"[{label}] {snippet(text, m.start(), m.end())}", severity, label)
            )
    return hits


# --- SV105: description stuffing ---------------------------------------------------------------------------------------

_SCOPE = (
    r"(every|each|all|any)\s+(single\s+)?(user\s+)?(request|task|message|prompt|conversation|question|query|turn|"
    r"response|session|interaction|reply)s?\b(?!\s+(about|involving|related|that|which|where|mentioning|regarding|"
    r"containing|with|on|for|in|from|to|of|like))"
)
HIJACK: list[tuple[str, re.Pattern[str]]] = [
    (
        "applies to every request",
        re.compile(
            r"\b(use|load|invoke|activate|apply|run|trigger|call|consult|read)\b[^.\n]{0,40}\b(for|on|in|with|before|"
            r"at\s+the\s+start\s+of|during)\s+"
            + _SCOPE
            + r"|\bregardless\s+of\s+(the\s+)?(topic|task|request|question)",
            re.I,
        ),
    ),
    (
        "outranks other skills",
        re.compile(
            r"\b(before|instead\s+of|in\s+place\s+of|rather\s+than|over)\s+(using\s+)?(any|all|every)\s+(other\s+)?"
            r"(skills?|tools?)\b|\b(ignore|disable|override|replace|supersede)s?\s+(all\s+|any\s+)?(other\s+)?skills\b",
            re.I,
        ),
    ),
    ("always on", re.compile(r"\balways\s+(be\s+)?(active|on|enabled|loaded)\b|\b(highest|top)\s+priority\b", re.I)),
]
MAX_DESCRIPTION = 1024


def hijack(description: str) -> list[Hit]:
    hits = [
        Hit("SV105", m.start(), m.end(), f"[{label}] {snippet(description, m.start(), m.end())}", label=label)
        for label, m in _first(HIJACK, description)
    ]
    if len(description) > MAX_DESCRIPTION:
        hits.append(
            Hit("SV105", 0, 0, f"[too long] {len(description)} characters (limit {MAX_DESCRIPTION})", label="long")
        )
    return hits


# --- SV102: hidden Unicode ---------------------------------------------------------------------------------------------

HIDDEN_CHARS = {
    **{cp: "ZERO WIDTH" for cp in (0x200B, 0x200C, 0x2060, 0x180E)},
    **{cp: "BIDI CONTROL" for cp in (0x202A, 0x202B, 0x202C, 0x2066, 0x2067, 0x2068, 0x2069, 0x061C)},
    **{cp: "BIDI OVERRIDE" for cp in (0x202D, 0x202E)},
}


def _decode_tags(text: str) -> str:
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


def hidden_unicode(text: str) -> list[Hit]:
    """Tag characters and overrides are high severity; other invisible characters medium.

    A byte-order mark at the start, zero-width joiners (used in emoji and many scripts) and soft hyphens are
    allowed. Zero-width non-joiners and direction marks are common in Persian, Arabic and Hebrew text, so they are
    only reported when there are many of them.
    """
    counts: dict[str, int] = {}
    first: int | None = None
    severe = False
    marks = 0
    for i, ch in enumerate(text):
        cp = ord(ch)
        if (cp == 0xFEFF and i == 0) or cp in (0x200D, 0x00AD):
            continue
        if cp in (0x200E, 0x200F, 0x200C):
            marks += 1
            continue
        kind = HIDDEN_CHARS.get(cp)
        if kind is None and 0xE0000 <= cp <= 0xE007F:
            kind = "UNICODE TAG"
        if kind is None and unicodedata.category(ch) == "Cf":
            kind = "FORMAT CONTROL"
        if kind is None:
            continue
        severe = severe or kind in ("UNICODE TAG", "BIDI OVERRIDE")
        key = "U+E0000 block (UNICODE TAG)" if kind == "UNICODE TAG" else f"U+{cp:04X} ({kind})"
        counts[key] = counts.get(key, 0) + 1
        if first is None:
            first = i
    if marks > 50 and marks > len(text) // 20:
        counts["direction marks / ZWNJ"] = marks
    if not counts:
        return []
    evidence = ", ".join(f"{k} x{v}" for k, v in counts.items())
    decoded = _decode_tags(text)
    if decoded:
        evidence += f"; decoded tag text: {decoded[:120]!r}"
    pos = first or 0
    return [Hit("SV102", pos, pos + 1, evidence, Severity.HIGH if severe else Severity.MEDIUM)]


# --- SV104: encoded payloads -------------------------------------------------------------------------------------------

BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{40,65536}={0,2}(?![A-Za-z0-9+/=_-])")
HEX_ESCAPES_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){16,}")
COMMANDISH = re.compile(
    r"\b(curl|wget|bash|zsh|powershell|pwsh|Invoke-\w+|iex|nc|ncat|chmod|base64|eval|exec|subprocess|os\.system|"
    r"child_process|rm\s+-rf|/bin/sh|/dev/tcp)\b|https?://",
    re.I,
)


def _try_base64(blob: str) -> str | None:
    if not (re.search(r"[a-z]", blob) and re.search(r"[A-Z]", blob) and re.search(r"[0-9+/]", blob)):
        return None
    try:
        text = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    printable = sum(c.isprintable() or c.isspace() for c in text)
    return text if text and printable / len(text) > 0.9 else None


def _suspicious(decoded: str) -> bool:
    return bool(_first(OVERRIDES, decoded) or COMMANDISH.search(decoded) or safety(decoded))


def encoded(text: str) -> list[Hit]:
    for m in BASE64_RE.finditer(text):
        decoded = _try_base64(m.group(0))
        if decoded and _suspicious(decoded):
            return [Hit("SV104", m.start(), m.end(), f"[base64] decodes to: {decoded[:120]!r}")]
    for m in HEX_ESCAPES_RE.finditer(text):
        try:
            decoded = bytes.fromhex(m.group(0).replace("\\x", "")).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _suspicious(decoded):
            return [Hit("SV104", m.start(), m.end(), f"[hex escapes] decode to: {decoded[:120]!r}")]
    return []


# --- SV103: text hidden from Markdown readers -------------------------------------------------------------------------

HIDDEN_MARKDOWN: list[tuple[str, re.Pattern[str]]] = [
    ("HTML comment", re.compile(r"<!--(.*?)-->", re.S)),
    ("Markdown comment", re.compile(r"^[ \t]*\[[^\]\n]*\]:[ \t]*#[ \t]*(.+)$", re.M)),
    (
        "hidden HTML element",
        re.compile(
            r"<([a-z][a-z0-9]*)\b[^>]*?(?:style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|"
            r"font-size\s*:\s*0|opacity\s*:\s*0)[^\"']*[\"']|\shidden\b)[^>]*>(.*?)</\1\s*>",
            re.S | re.I,
        ),
    ),
]
LONG_COMMENT = 120
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>()\[\]`]+(?:\([^\s)]*\)[^\s\"'<>()\[\]`]*)*", re.I)


def hidden_markdown(text: str, command_check: object = None) -> list[Hit]:
    """`command_check(text) -> bool` lets the engine reuse the code rules without an import cycle."""
    hits = []
    for label, pattern in HIDDEN_MARKDOWN:
        for m in pattern.finditer(text):
            body = (m.group(m.lastindex or 0) or "").strip()
            if not body:
                continue
            dangerous = bool(
                _first(OVERRIDES, body)
                or safety(body)
                or URL_RE.search(body)
                or (callable(command_check) and command_check(body))
            )
            if dangerous:
                severity = Severity.HIGH
            elif len(body) >= LONG_COMMENT:
                severity = Severity.LOW
            else:
                continue
            hits.append(
                Hit("SV103", m.start(), m.end(), f"[{label}] {snippet(body, 0, len(body), 0)}", severity, label)
            )
    return hits


# --- SV207: exfiltration URL templates ---------------------------------------------------------------------------------

PLACEHOLDER_RE = re.compile(
    r"\{\{?[^{}/\s]{1,60}\}?\}|%7B%7B?|%7B[A-Za-z_]|<[A-Za-z_ ]{2,40}>|%3C[A-Za-z_]+%3E|\$\{?[A-Z][A-Z0-9_]{2,}"
    r"|\[(?:insert|add|put|include|data|secret|summary|conversation|chat|user)[^\]]*\]"
    r"|\b(?:INSERT|REPLACE|ADD)_?[A-Z_]{2,}|=(?:[A-Z]{2,}_)+[A-Z]{2,}\b"
)
IMAGE_BEFORE_RE = re.compile(r"!\[[^\]\n]*\]\(\s*<?$|<img\b[^>]*\bsrc\s*=\s*[\"']?$", re.I)
DATA_WORDS = re.compile(
    r"conversation|chat|history|messages?|secret|summary|summari[sz]e|data|user|email|password|passwd|token|"
    r"api[_-]?key|credential|context|prompt|answer|query|memory|session|cookie|ssn|card|file|content|env",
    re.I,
)


def _is_exfil(url: str, image: bool) -> bool:
    """Images with any placeholder can leak data without a click. Links need a placeholder in the query or
    fragment, or one naming data, so documentation such as /repos/{owner}/{repo} is not reported."""
    rest = unquote(url.split("://", 1)[1] if "://" in url else url)
    found = [m.group(0) for m in PLACEHOLDER_RE.finditer(rest)]
    if not found:
        return False
    if image:
        return True
    query = re.split(r"[?#]", rest, maxsplit=1)[1] if re.search(r"[?#]", rest) else ""
    return bool(PLACEHOLDER_RE.search(query)) or any(DATA_WORDS.search(p) for p in found)


def exfil_urls(text: str) -> list[Hit]:
    hits: list[Hit] = []
    seen: set[str] = set()
    for m in URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:")
        image = bool(IMAGE_BEFORE_RE.search(text[max(0, m.start() - 200) : m.start()]))
        if url in seen or not _is_exfil(url, image):
            continue
        seen.add(url)
        kind = "image" if image else "link"
        hits.append(
            Hit(
                "SV207",
                m.start(),
                m.end(),
                f"[{kind}] {snippet(url, 0, len(url), 0)[:200]}",
                Severity.HIGH if image else Severity.MEDIUM,
                kind,
            )
        )
    return hits


# --- SV304: secrets ----------------------------------------------------------------------------------------------------

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{24,}\b")),
    ("model provider API key", re.compile(r"\bsk-[A-Za-z0-9_-]{40,}\b")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("JSON web token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
]


def secrets(text: str) -> list[Hit]:
    hits = []
    for label, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            value = m.group(0)
            if "EXAMPLE" in value or re.search(r"(.)\1{9,}", value):
                continue  # documented placeholders such as AKIAIOSFODNN7EXAMPLE or sk-xxxxxxxx...
            shown = value if label == "private key" else value[:4] + "... (redacted)"
            hits.append(Hit("SV304", m.start(), m.end(), f"[{label}] {shown}", label=label))
            break
    return hits
