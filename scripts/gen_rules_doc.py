"""Regenerate docs/rules.md from the rule registry: python scripts/gen_rules_doc.py"""

from pathlib import Path

from skill_vet.rules import RULES

SECTIONS = {
    "SV0": "Manifest",
    "SV1": "Hidden and injected instructions",
    "SV2": "Dangerous code",
    "SV3": "Permissions and agent safety",
    "SV4": "Integrity and coverage (SV401 to SV403 need --lock)",
}

lines = [
    "# Rules",
    "",
    "Generated from `src/skill_vet/rules/registry.py` by `scripts/gen_rules_doc.py`. Do not edit by hand.",
    "",
    "Severities are defaults. Some rules raise or lower severity depending on the evidence, as noted in the",
    "description. Skip a rule with `--ignore SV203`, or only for some paths with `--ignore SV203:cleanup/*`.",
    "",
    "| Rule | Severity | Title | OWASP |",
    "| --- | --- | --- | --- |",
]
lines += [f"| [{r.id}](#{r.id.lower()}) | {r.severity} | {r.title} | {r.owasp} |" for r in RULES.values()]
current = None
for r in RULES.values():
    section = SECTIONS[r.id[:3]]
    if section != current:
        lines += ["", f"## {section}"]
        current = section
    lines += [
        "",
        f"### {r.id}",
        "",
        f"**{r.title}** - default severity `{r.severity}` - {r.owasp}",
        "",
        r.description,
        "",
        f"**Remediation:** {r.remediation}",
    ]
Path(__file__).resolve().parent.parent.joinpath("docs", "rules.md").write_text(
    "\n".join(lines) + "\n", encoding="utf-8", newline="\n"
)
