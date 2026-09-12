"""Severity, confidence, and the shape of a finding."""

import unittest

from repo_sentinel.findings import Confidence, Finding, Severity


class TestOrdering(unittest.TestCase):
    def test_severities_compare_by_rank_not_alphabetically(self):
        self.assertGreater(Severity.CRITICAL, Severity.HIGH)
        self.assertGreater(Severity.MEDIUM, Severity.LOW)
        self.assertLess(Severity.LOW, Severity.CRITICAL)
        self.assertLessEqual(Severity.HIGH, Severity.HIGH)
        self.assertGreaterEqual(Severity.HIGH, Severity.MEDIUM)

    def test_confidence_orders_the_same_way(self):
        self.assertGreater(Confidence.HIGH, Confidence.LOW)
        self.assertLess(Confidence.MEDIUM, Confidence.HIGH)
        self.assertLessEqual(Confidence.LOW, Confidence.MEDIUM)
        self.assertGreaterEqual(Confidence.MEDIUM, Confidence.MEDIUM)

    def test_the_two_scales_do_not_compare_with_each_other(self):
        # They answer different questions, and a comparison between them would
        # be a bug worth hearing about rather than a quietly wrong answer.
        for operation in ("__lt__", "__gt__", "__le__", "__ge__"):
            with self.subTest(operation=operation):
                self.assertIs(
                    getattr(Severity.HIGH, operation)(Confidence.HIGH), NotImplemented
                )
                self.assertIs(getattr(Severity.HIGH, operation)("high"), NotImplemented)


class TestParsing(unittest.TestCase):
    def test_case_and_whitespace_are_forgiven(self):
        self.assertEqual(Severity.parse("  CRITICAL "), Severity.CRITICAL)
        self.assertEqual(Confidence.parse("Medium"), Confidence.MEDIUM)

    def test_the_error_names_the_valid_values(self):
        with self.assertRaises(ValueError) as caught:
            Confidence.parse("certain")
        message = str(caught.exception)
        self.assertIn("confidence", message)
        self.assertIn("low, medium, high", message)


class TestSerialisation(unittest.TestCase):
    def finding(self, **overrides):
        fields = dict(
            rule_id="SEC001",
            severity=Severity.CRITICAL,
            title="AWS access key id",
            path="app.py",
            line=3,
            evidence="AKIA****LM3D",
            subject="AKIA****LM3D",
        )
        fields.update(overrides)
        return Finding(**fields)

    def test_enums_become_their_values(self):
        data = self.finding().to_dict()
        self.assertEqual(data["severity"], "critical")
        self.assertEqual(data["confidence"], "high")

    def test_the_fingerprint_travels_with_the_finding(self):
        data = self.finding().to_dict()
        self.assertEqual(data["fingerprint"], self.finding().fingerprint)

    def test_the_deduplication_subject_stays_internal(self):
        # It exists so two scanners can recognise one problem. A consumer of
        # the report has no use for it, and it is a second copy of a redacted
        # credential, which is a thing to have fewer of rather than more.
        self.assertNotIn("subject", self.finding().to_dict())

    def test_sorting_puts_the_worst_and_surest_first(self):
        findings = [
            self.finding(rule_id="SEC100", severity=Severity.HIGH, confidence=Confidence.MEDIUM),
            self.finding(rule_id="SEC002", severity=Severity.HIGH),
            self.finding(rule_id="SEC001"),
        ]
        ordered = [finding.rule_id for finding in sorted(findings, key=lambda f: f.sort_key)]
        self.assertEqual(ordered, ["SEC001", "SEC002", "SEC100"])


if __name__ == "__main__":
    unittest.main()
