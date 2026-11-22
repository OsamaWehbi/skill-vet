"""List commits since a tag, grouped by conventional-commit type."""

import subprocess
import sys
from collections import defaultdict

TYPES = {"feat": "Added", "fix": "Fixed", "refactor": "Changed", "perf": "Changed", "revert": "Removed"}


def main(tag: str) -> None:
    log = subprocess.run(
        ["git", "log", "--no-merges", "--format=%s", f"{tag}..HEAD"], capture_output=True, text=True, check=True
    ).stdout
    groups = defaultdict(list)
    for subject in log.splitlines():
        kind, _, rest = subject.partition(":")
        section = TYPES.get(kind.split("(")[0].strip())
        if section and rest:
            groups[section].append(rest.strip())
    for section, items in groups.items():
        print(f"### {section}")
        for item in items:
            print(f"- {item}")


if __name__ == "__main__":
    main(sys.argv[1])
