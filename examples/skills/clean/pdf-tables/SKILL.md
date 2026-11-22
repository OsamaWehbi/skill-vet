---
name: pdf-tables
description: Extracts tables from PDF files into CSV. Use when the user wants the tables of a PDF as data.
---

# PDF tables

Run `python scripts/extract.py input.pdf out/` and check the CSV files it writes. Tables that span pages are joined
when their headers match. See `assets/example.csv` for the output format.
