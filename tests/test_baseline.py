"""Baselines: accepting what is already there without going blind to it."""

import json
import os
import tempfile
import unittest

from bluerayscan import baseline
from bluerayscan.findings import Finding, Severity


def finding(rule_id="SEC001", path="app.py", line=3, evidence="AKIA****LM3D"):
    return Finding(
        rule_id=rule_id,
        severity=Severity.CRITICAL,
        title="AWS access key id",
        path=path,
        line=line,
        evidence=evidence,
    )


class TestFingerprints(unittest.TestCase):
    def test_moving_a_finding_down_a_file_keeps_its_identity(self):
        self.assertEqual(finding(line=3).fingerprint, finding(line=90).fingerprint)

    def test_changing_the_value_makes_a_new_finding(self):
        self.assertNotEqual(
            finding().fingerprint, finding(evidence="AKIA****QQ99").fingerprint
        )

    def test_moving_a_finding_to_another_file_makes_a_new_finding(self):
        self.assertNotEqual(finding().fingerprint, finding(path="other.py").fingerprint)


class TestPartition(unittest.TestCase):
    def test_known_findings_are_accepted_and_new_ones_are_not(self):
        known, fresh = finding(), finding(rule_id="SEC005", evidence="sk_l****90ab")
        recorded = baseline.Baseline((baseline.Entry.of(known),))
        new, accepted, stale = recorded.partition([known, fresh])
        self.assertEqual(new, [fresh])
        self.assertEqual(accepted, [known])
        self.assertEqual(stale, [])

    def test_an_entry_that_matches_nothing_is_reported_as_stale(self):
        recorded = baseline.Baseline((baseline.Entry.of(finding()),))
        new, accepted, stale = recorded.partition([])
        self.assertEqual((new, accepted), ([], []))
        self.assertEqual(len(stale), 1)
        self.assertEqual(stale[0].rule_id, "SEC001")

    def test_an_empty_baseline_accepts_nothing(self):
        new, accepted, stale = baseline.Baseline().partition([finding()])
        self.assertEqual(len(new), 1)
        self.assertEqual((accepted, stale), ([], []))


class TestDocument(unittest.TestCase):
    def test_the_file_never_contains_the_evidence_let_alone_a_secret(self):
        raw = "AKIA" + "ZZ7Q4TWFN2XKLM3D"
        text = baseline.dumps([finding(evidence=raw)], version="0.2.0")
        self.assertNotIn(raw, text)
        self.assertNotIn("AKIA****LM3D", baseline.dumps([finding()], version="0.2.0"))

    def test_regenerating_an_unchanged_scan_produces_an_identical_file(self):
        first = baseline.dumps([finding(), finding(rule_id="SEC005")], version="0.2.0")
        second = baseline.dumps([finding(rule_id="SEC005"), finding()], version="0.2.0")
        self.assertEqual(first, second)

    def test_duplicate_findings_collapse_to_one_entry(self):
        payload = json.loads(baseline.dumps([finding(), finding(line=99)], version="0.2.0"))
        self.assertEqual(len(payload["findings"]), 1)


class TestLoad(unittest.TestCase):
    def _write(self, text):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        handle.write(text)
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_round_trips_through_a_file(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "nested", "baseline.json")
            count = baseline.write(path, [finding()], version="0.2.0")
            self.assertEqual(count, 1)
            self.assertEqual(baseline.load(path).fingerprints, {finding().fingerprint})

    def test_a_missing_file_says_how_to_make_one(self):
        with self.assertRaises(baseline.BaselineError) as caught:
            baseline.load(os.path.join(tempfile.gettempdir(), "does-not-exist.json"))
        self.assertIn("--write-baseline", str(caught.exception))

    def test_broken_json_is_an_error_not_an_empty_baseline(self):
        # Silently treating an unreadable baseline as empty would be safe; as
        # ignorable it would not. The failure mode to avoid is the opposite one,
        # where a corrupt file accidentally accepts everything.
        with self.assertRaises(baseline.BaselineError):
            baseline.load(self._write("{not json"))

    def test_a_foreign_document_is_rejected(self):
        with self.assertRaises(baseline.BaselineError):
            baseline.load(self._write('{"hello": "world"}'))

    def test_an_unknown_schema_version_is_rejected(self):
        path = self._write('{"baseline_version": 99, "findings": []}')
        with self.assertRaises(baseline.BaselineError) as caught:
            baseline.load(path)
        self.assertIn("regenerate", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
