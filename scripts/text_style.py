from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TextStyleFinding:
    code: str
    path: str
    line: int | None
    message: str


def inspect_text_style(path: str, text: str) -> tuple[TextStyleFinding, ...]:
    findings: list[TextStyleFinding] = []

    for line_number, line in enumerate(text.splitlines(), 1):
        if line.endswith((" ", "\t")):
            findings.append(
                TextStyleFinding(
                    "TRAILING_WHITESPACE",
                    path,
                    line_number,
                    "trailing spaces or tabs are forbidden",
                )
            )

    if text.endswith(("\n\n", "\r\n\r\n")):
        findings.append(
            TextStyleFinding(
                "EXTRA_EOF_BLANK_LINES",
                path,
                len(text.splitlines()),
                "text files must end with exactly one newline",
            )
        )

    return tuple(findings)
