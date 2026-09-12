"""The measurement harness and its pinned corpus.

Neither is shipped, but both rot the same way documentation does: a corpus
entry whose commit was never fetched, or a comparison that silently reports
nothing, would make a measured claim in a commit message worth nothing.
"""

import contextlib
import io
import json
import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import measure  # noqa: E402  (after the path fix above)

SHA = re.compile(r"^[0-9a-f]{40}$")


class TestPinnedCorpus(unittest.TestCase):
    def setUp(self):
        self.repositories = json.loads((ROOT / "tools" / "corpus.json").read_text())["repositories"]

    def test_every_entry_is_complete(self):
        for repository in self.repositories:
            with self.subTest(repository=repository.get("name")):
                self.assertEqual(
                    set(repository), {"name", "url", "commit", "for"},
                    "a pin needs a name, a URL, a commit and a reason to be here",
                )

    def test_every_commit_is_a_full_sha(self):
        # A branch name would defeat the point: the tree would move under the
        # numbers measured on it.
        for repository in self.repositories:
            with self.subTest(repository=repository["name"]):
                self.assertRegex(repository["commit"], SHA)

    def test_names_are_unique_and_usable_as_directories(self):
        names = [repository["name"] for repository in self.repositories]
        self.assertEqual(len(names), len(set(names)))
        for name in names:
            with self.subTest(name=name):
                self.assertRegex(name, r"^[\w.-]+$")

    def test_the_harness_reads_the_same_file(self):
        self.assertEqual(
            [repository["name"] for repository in measure.pins()],
            [repository["name"] for repository in self.repositories],
        )

    def test_the_vulnerable_repositories_are_still_in_it(self):
        # They measure the other direction. A corpus of clean repositories
        # rewards a rule that finds nothing.
        names = {repository["name"] for repository in self.repositories}
        self.assertTrue({"terragoat", "kubernetes-goat"} <= names)


class TestComparison(unittest.TestCase):
    def compare(self, before, after):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            measure.compare(before, after)
        return out.getvalue()

    def test_a_rule_that_went_quiet_is_named_with_its_delta(self):
        text = self.compare({"cli": {"SEC100": 9}}, {"cli": {"SEC100": 7}})
        self.assertIn("SEC100", text)
        self.assertIn("(-2)", text)

    def test_a_rule_that_stopped_firing_entirely_is_still_shown(self):
        text = self.compare({"goat": {"TF001": 3}}, {"goat": {}})
        self.assertIn("TF001", text)
        self.assertIn("-> 0", text)

    def test_an_unchanged_run_says_so_rather_than_printing_a_table(self):
        text = self.compare({"cli": {"SEC100": 7}}, {"cli": {"SEC100": 7}})
        self.assertIn("nothing moved", text)

    def test_a_repository_added_since_the_saved_run_is_reported(self):
        text = self.compare({}, {"new": {"SEC001": 1}})
        self.assertIn("new", text)
        self.assertIn("(+1)", text)


if __name__ == "__main__":
    unittest.main()
