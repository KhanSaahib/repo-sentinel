"""Output formats: what the person, the pipeline and GitHub each get told."""

import json
import unittest

from repo_sentinel import report, rules
from repo_sentinel.findings import Confidence, Finding, Severity

CRITICAL = Finding(
    rule_id="SEC001",
    severity=Severity.CRITICAL,
    title="AWS access key id",
    path="terraform/main.tf",
    line=14,
    evidence="AKIA****LM3D",
    remediation="Deactivate the key in IAM.",
)
GUESS = Finding(
    rule_id="SEC100",
    severity=Severity.HIGH,
    title="High-entropy quoted string assigned to 'api_key'",
    path="app.py",
    line=2,
    evidence="Qq7Z****Rt8W",
    confidence=Confidence.MEDIUM,
)


class TestText(unittest.TestCase):
    def test_clean_run_says_so_without_claiming_safety(self):
        self.assertIn("not proof of safety", report.format_text([], colour=False))

    def test_confidence_is_shown_only_when_it_is_not_certain(self):
        certain = report.format_text([CRITICAL], colour=False)
        guess = report.format_text([GUESS], colour=False)
        self.assertNotIn("confidence", certain)
        self.assertIn("(medium confidence)", guess)

    def test_notes_follow_the_summary(self):
        text = report.format_text([CRITICAL], colour=False, notes=["3 accepted."])
        self.assertTrue(text.endswith("3 accepted."))
        self.assertIn("1 finding(s): 1 critical", text)

    def test_colour_is_off_by_request(self):
        self.assertNotIn("\033", report.format_text([CRITICAL], colour=False))
        self.assertIn("\033", report.format_text([CRITICAL], colour=True))


class TestJson(unittest.TestCase):
    def test_every_finding_carries_a_fingerprint_and_confidence(self):
        payload = json.loads(report.format_json([CRITICAL, GUESS], version="0.2.0"))
        self.assertEqual(payload["finding_count"], 2)
        for record in payload["findings"]:
            self.assertIn("fingerprint", record)
            self.assertIn("confidence", record)


class TestSarif(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(report.format_sarif([CRITICAL, GUESS], version="0.2.0"))
        self.run = self.document["runs"][0]

    def test_shape_matches_the_schema_github_expects(self):
        self.assertEqual(self.document["version"], "2.1.0")
        self.assertEqual(self.run["tool"]["driver"]["name"], "repo-sentinel")
        self.assertEqual(len(self.run["results"]), 2)

    def test_rules_are_described_once_and_referenced_by_index(self):
        described = self.run["tool"]["driver"]["rules"]
        self.assertEqual([rule["id"] for rule in described], ["SEC001", "SEC100"])
        for result in self.run["results"]:
            self.assertEqual(described[result["ruleIndex"]]["id"], result["ruleId"])

    def test_only_rules_that_fired_are_described(self):
        self.assertLess(len(self.run["tool"]["driver"]["rules"]), len(rules.RULES))

    def test_severity_is_expressed_the_way_github_reads_it(self):
        first = self.run["tool"]["driver"]["rules"][0]
        self.assertEqual(first["defaultConfiguration"]["level"], "error")
        self.assertEqual(first["properties"]["security-severity"], "9.0")

    def test_fingerprints_survive_a_reformatted_file(self):
        moved = json.loads(
            report.format_sarif([Finding(**{**CRITICAL.__dict__, "line": 400})], version="0.2.0")
        )
        self.assertEqual(
            moved["runs"][0]["results"][0]["partialFingerprints"],
            self.run["results"][0]["partialFingerprints"],
        )

    def test_a_clean_run_is_still_a_valid_document(self):
        empty = json.loads(report.format_sarif([], version="0.2.0"))
        self.assertEqual(empty["runs"][0]["results"], [])
        self.assertEqual(empty["runs"][0]["tool"]["driver"]["rules"], [])


class TestCatalogueOutput(unittest.TestCase):
    def test_text_lists_every_rule_under_its_category(self):
        text = report.format_rule_catalogue()
        self.assertIn("secrets:", text)
        self.assertIn("dockerfiles:", text)
        for rule_id in rules.RULES:
            self.assertIn(rule_id, text)

    def test_json_is_machine_readable(self):
        payload = json.loads(report.format_rule_catalogue(as_json=True))
        self.assertEqual(len(payload["rules"]), len(rules.RULES))
        self.assertEqual(payload["rules"][0]["id"], "SEC001")


if __name__ == "__main__":
    unittest.main()
