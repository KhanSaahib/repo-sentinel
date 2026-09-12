"""What every scanner has to look like, checked rather than assumed.

Fifteen scanners now, written over a long stretch, each one copied from
whichever came before. The things they share -- a suppression parameter, a
marker-honouring flag, a docstring saying what the module is for -- are
conventions, and a convention nobody checks is one the sixteenth scanner
quietly breaks.
"""

import inspect
import unittest

from repo_sentinel import scanners, suppression


def content_scanners():
    return [
        (name, getattr(scanners, name))
        for name in scanners.__all__
        if hasattr(getattr(scanners, name), "scan_files")
    ]


class TestContract(unittest.TestCase):
    def test_there_are_scanners_to_check(self):
        # A discovery-based test that discovers nothing passes silently.
        self.assertGreaterEqual(len(content_scanners()), 15)

    def test_every_scanner_takes_pairs_and_returns_a_list(self):
        for name, module in content_scanners():
            with self.subTest(scanner=name):
                self.assertEqual(module.scan_files([]), [])

    def test_every_scanner_can_be_told_to_ignore_markers(self):
        for name, module in content_scanners():
            with self.subTest(scanner=name):
                parameter = inspect.signature(module.scan_files).parameters.get(
                    "honour_markers"
                )
                self.assertIsNotNone(parameter, f"{name}.scan_files has no honour_markers")
                self.assertIs(parameter.default, True)
                self.assertEqual(parameter.kind, inspect.Parameter.KEYWORD_ONLY)

    def test_every_scanner_can_be_handed_suppressions_it_did_not_parse(self):
        # The engine parses a file's markers once; a scanner that cannot accept
        # them has to re-parse, and --no-suppression then has no way in.
        for name, module in content_scanners():
            accepting = [
                key
                for key, value in vars(module).items()
                if key.startswith("scan_")
                and callable(value)
                and "marks" in inspect.signature(value).parameters
            ]
            with self.subTest(scanner=name):
                self.assertTrue(accepting, f"{name} has no entry point taking marks")

    def test_no_scanner_obeys_markers_when_told_not_to(self):
        for name, module in content_scanners():
            with self.subTest(scanner=name):
                self.assertEqual(module.scan_files([], honour_markers=False), [])

    def test_every_scanner_module_says_what_it_is_for(self):
        for name, module in content_scanners():
            with self.subTest(scanner=name):
                self.assertTrue((module.__doc__ or "").strip(), f"{name} has no docstring")
                self.assertGreater(len(module.__doc__.split()), 30, f"{name}'s docstring is a stub")


class TestSharedSuppression(unittest.TestCase):
    def test_the_shared_empty_suppressions_really_is_empty(self):
        self.assertFalse(suppression.NONE.whole_file)
        self.assertFalse(suppression.NONE.suppresses(1))
        self.assertFalse(suppression.NONE.suppresses(1, "SEC001"))
        self.assertEqual(suppression.NONE.filter_findings([]), [])


if __name__ == "__main__":
    unittest.main()
