from __future__ import annotations

import unittest

from scripts.text_style import inspect_text_style


class TextStylePolicyTests(unittest.TestCase):
    def test_rejects_trailing_spaces_with_exact_location(self) -> None:
        sample = "clean\ntrailing spaces" + (" " * 2) + "\n"
        findings = inspect_text_style("README.md", sample)

        self.assertTrue(
            any(
                finding.code == "TRAILING_WHITESPACE"
                and finding.path == "README.md"
                and finding.line == 2
                for finding in findings
            )
        )

    def test_rejects_trailing_tab(self) -> None:
        sample = "key = 1" + chr(9) + "\n"
        findings = inspect_text_style("config.toml", sample)

        self.assertEqual(("TRAILING_WHITESPACE",), tuple(item.code for item in findings))

    def test_rejects_extra_eof_blank_lines(self) -> None:
        findings = inspect_text_style("src/starcom/module.py", "VALUE = 1\n\n")

        self.assertIn("EXTRA_EOF_BLANK_LINES", {finding.code for finding in findings})

    def test_accepts_exactly_one_terminal_newline(self) -> None:
        findings = inspect_text_style("src/starcom/module.py", "VALUE = 1\n")

        self.assertEqual((), findings)


if __name__ == "__main__":
    unittest.main()
