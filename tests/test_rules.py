"""The rule catalogue must describe exactly what the scanners can emit."""

import pathlib
import unittest

import corpus
from repo_sentinel import rules
from repo_sentinel.scanners import (
    cloudformation,
    compose,
    dockerfiles,
    filenames,
    gitlab,
    kubernetes,
    secrets,
    terraform,
    workflows,
)


def emitted_rule_ids():
    findings = secrets.scan_files(corpus.FILES)
    findings += workflows.scan_files(corpus.FILES)
    findings += dockerfiles.scan_files(corpus.FILES)
    findings += terraform.scan_files(corpus.FILES)
    findings += kubernetes.scan_files(corpus.FILES)
    findings += compose.scan_files(corpus.FILES)
    findings += filenames.scan_paths(corpus.PATHS)
    findings += gitlab.scan_files(corpus.FILES)
    findings += cloudformation.scan_files(corpus.FILES)
    return {finding.rule_id for finding in findings}


class TestCatalogue(unittest.TestCase):
    def test_every_emitted_rule_is_catalogued(self):
        undescribed = emitted_rule_ids() - set(rules.RULES)
        self.assertEqual(undescribed, set(), "scanners emit rules the catalogue omits")

    def test_every_catalogued_rule_can_fire(self):
        # The other direction, which is the one that rots quietly: a rule
        # renamed or deleted in a scanner leaves its entry behind, and the
        # README grows a row for a check that no longer exists.
        unreachable = set(rules.RULES) - emitted_rule_ids()
        self.assertEqual(unreachable, set(), "catalogue describes rules nothing emits")

    def test_the_candidate_gate_lets_every_provider_rule_through(self):
        # secrets._CANDIDATE decides which lines are worth looking at closely,
        # and a line it rejects is never looked at again. Every line of the
        # corpus that trips a provider rule has to clear it.
        for path, text in corpus.FILES:
            for number, line in enumerate(text.splitlines(), start=1):
                hits = [
                    finding
                    for finding in secrets.scan_line(path, number, line)
                    if not finding.rule_id.startswith("SEC1")
                ]
                if hits:
                    with self.subTest(rule=hits[0].rule_id):
                        self.assertIsNotNone(secrets._CANDIDATE.search(line))

    def test_provider_rules_agree_with_the_catalogue_on_severity(self):
        for rule in secrets._PROVIDER_RULES:
            with self.subTest(rule=rule.rule_id):
                self.assertEqual(rules.RULES[rule.rule_id].severity, rule.severity)

    def test_every_rule_is_documented(self):
        # The catalogue keeps the scanners honest; this keeps the prose honest.
        # A rule table nobody is forced to update is a rule table that
        # describes the release before last.
        root = pathlib.Path(__file__).resolve().parents[1]
        documentation = (root / "docs" / "RULES.md").read_text(encoding="utf-8")
        undocumented = sorted(
            rule_id for rule_id in rules.RULES if rule_id not in documentation
        )
        self.assertEqual(undocumented, [], "rules missing from docs/RULES.md")

    def test_the_readme_summary_counts_the_rules_correctly(self):
        # The README quotes a total. A number in prose is a number that rots.
        root = pathlib.Path(__file__).resolve().parents[1]
        readme = (root / "README.md").read_text(encoding="utf-8")
        words = {
            60: "Sixty", 61: "Sixty-one", 62: "Sixty-two", 63: "Sixty-three",
            64: "Sixty-four", 65: "Sixty-five", 66: "Sixty-six", 67: "Sixty-seven",
            68: "Sixty-eight", 69: "Sixty-nine", 70: "Seventy", 71: "Seventy-one",
            72: "Seventy-two", 73: "Seventy-three", 74: "Seventy-four",
            75: "Seventy-five", 76: "Seventy-six", 77: "Seventy-seven",
            78: "Seventy-eight", 79: "Seventy-nine", 80: "Eighty",
        }
        spelled = words.get(len(rules.RULES))
        self.assertIsNotNone(spelled, "extend the number words in this test")
        self.assertIn(f"{spelled} rules", readme)

    def test_ids_are_unique_and_sorted_within_a_category(self):
        for category, catalogued in rules.by_category().items():
            ids = [rule.id for rule in catalogued]
            with self.subTest(category=category):
                self.assertEqual(ids, sorted(ids))
                self.assertEqual(len(ids), len(set(ids)))


if __name__ == "__main__":
    unittest.main()
