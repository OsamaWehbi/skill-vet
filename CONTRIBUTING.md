# Contributing to skill-vet

Thanks for your interest in improving skill-vet. Contributions of all sizes are welcome, including bug reports,
false-positive reports, new rules and documentation fixes.

## Getting set up

```bash
git clone https://github.com/OsamaWehbi/skill-vet.git
cd skill-vet
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
```

## Before you open a pull request

```bash
ruff check .
ruff format --check .
pytest
```

CI runs the same checks on Python 3.11, 3.12 and 3.13 on Linux and on Windows, plus Bandit, pip-audit, Gitleaks and a
self-test of the GitHub Action against the example skills.

## Adding or changing a rule

1. Add the rule's metadata to `src/skill_vet/rules/registry.py`. Pick the next free ID in the right family (SV0
   manifest, SV1 hidden and injected instructions, SV2 dangerous code, SV3 permissions and agent safety, SV4
   integrity and coverage).
2. Implement detection in `src/skill_vet/rules/text.py` (instructions and text), `src/skill_vet/rules/code.py`
   (commands and scripts) or `src/skill_vet/engine.py` (manifest and cross-file checks).
3. Add tests with at least one input that must trigger the rule and one realistic, benign input that must not. A
   scanner that cries wolf gets switched off, so false-positive tests matter as much as detections.
4. Regenerate the reference: `python scripts/gen_rules_doc.py`.
5. If the examples should show the new technique, add it to `scripts/make_examples.py` and run it. The clean examples
   and the bundled skill in `skill/` must keep producing no findings.

## Guidelines

- Open an issue first for larger changes so we can agree on the approach.
- Keep pull requests focused. One topic per PR is easier to review.
- Use conventional commit messages such as `feat`, `fix`, `docs`, `test` and `chore`.
- Never add real malware, real secrets or real attacker infrastructure. Use `.invalid` hosts and made-up values.
- skill-vet must stay offline and must never execute, import or follow anything it scans.
- Source files stay plain ASCII; build invisible characters with `chr()` in tests and in the examples script.
