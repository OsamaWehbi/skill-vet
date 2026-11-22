---
name: vet-skills
description: Checks an agent skill for hidden instructions, dangerous scripts and broad permissions before it is installed or updated. Use when the user asks to install, add, update or review a skill.
allowed-tools: Read, Bash(skill-vet scan:*), Bash(skill-vet inspect:*)
---

# Vet a skill before installing it

Skills run with the agent's permissions, so check one before it is installed and again before an update.

1. Get the skill onto disk without installing it: a folder, a `.zip` or a `.skill` file.
2. Run `skill-vet scan <path> --format markdown` and read the result. If `skill-vet` is missing, ask the user to
   install it (see https://github.com/OsamaWehbi/skill-vet) and stop until it is installed.
3. Report the verdict to the user:
   - **block**: at least one high-severity finding. Do not install the skill. List the findings and their files.
   - **review**: medium-severity findings. Show them to the user and install only if the user agrees.
   - **pass**: no findings at medium or above. Say so and continue with the installation.
4. If a finding is unclear, run `skill-vet inspect <path>` to see the skill's files, what each one does, and any
   text hidden from Markdown readers.

Never edit the skill to make findings go away. If the user wants to ignore a finding, they can pass `--ignore`.
