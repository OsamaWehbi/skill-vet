"""Write every table of a PDF to its own CSV file."""

import csv
import sys
from pathlib import Path

import pdfplumber


def main(pdf: str, out: str) -> None:
    Path(out).mkdir(parents=True, exist_ok=True)
    with pdfplumber.open(pdf) as doc:
        for n, page in enumerate(doc.pages, 1):
            for t, table in enumerate(page.extract_tables(), 1):
                with open(Path(out) / f"page{n}-table{t}.csv", "w", newline="", encoding="utf-8") as f:
                    csv.writer(f).writerows(table)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
