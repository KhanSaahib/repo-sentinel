"""The rule catalogue must describe exactly what the scanners can emit."""

import unittest

import corpus
from repo_sentinel import rules
from repo_sentinel.scanners import dockerfiles, kubernetes, secrets, terraform, workflows


def emitted_rule_ids():
    findings = secrets.scan_files(corpus.FILES)
    findings += workflows.scan_files(corpus.FILES)
    findings += dockerfiles.scan_files(corpus.FILES)
    findings += terraform.scan_files(corpus.FILES)
    findings += kubernetes.scan_files(corpus.FILES)
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

    def test_provider_rules_agree_with_the_catalogue_on_severity(self):
        for rule in secrets._PROVIDER_RULES:
            with self.subTest(rule=rule.rule_id):
                self.assertEqual(rules.RULES[rule.rule_id].severity, rule.severity)

    def test_ids_are_unique_and_sorted_within_a_category(self):
        for category, catalogued in rules.by_category().items():
            ids = [rule.id for rule in catalogued]
            with self.subTest(category=category):
                self.assertEqual(ids, sorted(ids))
                self.assertEqual(len(ids), len(set(ids)))


if __name__ == "__main__":
    unittest.main()
