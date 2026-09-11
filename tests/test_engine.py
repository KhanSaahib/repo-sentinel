"""Running every scanner over a real tree, and reporting what was looked at."""

import os
import tempfile
import unittest

import fixtures
from repo_sentinel import engine


def repository(files):
    root = tempfile.mkdtemp()
    for relative, text in files.items():
        path = os.path.join(root, relative.replace("/", os.sep))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
    return root


class TestScan(unittest.TestCase):
    def test_every_scanner_contributes(self):
        root = repository(
            {
                "app.py": f'KEY = "{fixtures.REALISTIC_AWS_KEY_ID}"\n',
                ".github/workflows/ci.yml": "jobs:\n  build:\n    steps:\n      - uses: a/b@v1\n",
                "Dockerfile": "FROM debian:latest\nRUN echo hi\n",
                ".env": "DATABASE_PASSWORD=Tv8nRw1YXk92mQp7Lz4T\n",
            }
        )
        rules = {finding.rule_id for finding in engine.scan(root).findings}
        self.assertIn("SEC001", rules)
        self.assertIn("SEC101", rules)
        self.assertIn("WF001", rules)
        self.assertIn("DK001", rules)

    def test_report_counts_what_it_read(self):
        result = engine.scan(repository({"a.py": "x = 1\n", "b.py": "y = 2\n"}))
        self.assertEqual(result.file_count, 2)
        self.assertEqual(result.findings, [])
        self.assertGreaterEqual(result.duration, 0.0)

    def test_findings_are_sorted_worst_and_surest_first(self):
        root = repository(
            {
                "app.py": (
                    f'KEY = "{fixtures.REALISTIC_AWS_KEY_ID}"\n'
                    'api_key = "Qq7Zx9Lm2Pv4Rt8WcY6h"\n'
                    'sid = "SK' + "0a1b" * 8 + '"\n'
                )
            }
        )
        keys = [
            (-finding.severity.rank, -finding.confidence.rank)
            for finding in engine.scan(root).findings
        ]
        self.assertEqual(keys, sorted(keys))

    def test_scan_path_is_the_same_run_without_the_bookkeeping(self):
        root = repository({"app.py": f'KEY = "{fixtures.REALISTIC_AWS_KEY_ID}"\n'})
        self.assertEqual(engine.scan_path(root), engine.scan(root).findings)


class TestCollapse(unittest.TestCase):
    """Scanners overlap on purpose; reports should not."""

    def finding(self, rule_id, severity, evidence="AKIA****LM3D", line=6):
        from repo_sentinel.findings import Finding, Severity

        return Finding(
            rule_id=rule_id,
            severity=Severity.parse(severity),
            title=rule_id,
            path="s.yaml",
            line=line,
            evidence=evidence,
        )

    def test_the_same_value_at_the_same_line_is_reported_once(self):
        kept = engine.collapse([self.finding("SEC022", "high"), self.finding("K8S007", "critical")])
        self.assertEqual([finding.rule_id for finding in kept], ["K8S007"])

    def test_a_tie_keeps_the_format_specific_rule(self):
        kept = engine.collapse(
            [self.finding("SEC022", "critical"), self.finding("K8S007", "critical")]
        )
        self.assertEqual([finding.rule_id for finding in kept], ["K8S007"])

    def test_different_values_on_one_line_both_survive(self):
        kept = engine.collapse(
            [self.finding("SEC001", "critical"), self.finding("SEC005", "critical", "sk_l****90ab")]
        )
        self.assertEqual(len(kept), 2)

    def test_the_same_value_on_different_lines_both_survive(self):
        kept = engine.collapse([self.finding("SEC001", "critical"), self.finding("SEC001", "critical", line=9)])
        self.assertEqual(len(kept), 2)


if __name__ == "__main__":
    unittest.main()
