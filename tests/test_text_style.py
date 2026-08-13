from __future__ import annotations

import unittest

from scripts.text_style import inspect_text_style


class TextStylePolicyTests(unittest.TestCase):
    def test_accepts_clean_text(self) -> None:
        self.assertEqual((), inspect_text_style("src/starcom/module.py", "VALUE = 1\n"))


if __name__ == "__main__":
    unittest.main()
