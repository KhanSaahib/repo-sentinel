"""Running every scanner over a real tree, and reporting what was looked at."""

import dataclasses
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


class TestEveryScannerRuns(unittest.TestCase):
    def test_the_engine_calls_every_scanner_the_package_has(self):
        # A scanner missing from the engine runs in its own unit tests and
        # nowhere else, which nothing else would notice.
        from repo_sentinel import scanners

        available = {
            getattr(scanners, name)
            for name in scanners.__all__
            if hasattr(getattr(scanners, name), "scan_files")
        }
        called = set(engine.FORMAT_SCANNERS) | {scanners.secrets}
        self.assertEqual(available, called)


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


class TestDocumentationWeighting(unittest.TestCase):
    """A config file under docs/ illustrates something; it does not run."""

    MANIFEST = (
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata:\n  name: web\n"
        "spec:\n"
        "  containers:\n"
        "    - name: web\n"
        "      image: nginx:latest\n"
    )

    def confidences(self, relative):
        report = engine.scan(repository({relative: self.MANIFEST}))
        return {finding.rule_id: finding.confidence for finding in report.findings}

    def test_the_same_file_is_weaker_in_a_documentation_tree(self):
        deployed = self.confidences("deploy/web.yaml")
        documented = self.confidences("docs/examples/web.yaml")
        self.assertIn("K8S008", deployed)
        self.assertIn("K8S008", documented)
        self.assertLess(documented["K8S008"], deployed["K8S008"])

    def test_a_manifest_in_a_fixture_tree_is_weaker_too(self):
        # A manifest under testdata/ exists to be diffed or parsed rather than
        # applied. Argo CD has four hundred of them.
        deployed = self.confidences("deploy/web.yaml")
        fixture = self.confidences("pkg/health/testdata/web.yaml")
        self.assertLess(fixture["K8S008"], deployed["K8S008"])

    def test_it_is_weakened_rather_than_silenced(self):
        # Repositories do ship the manifest they actually apply inside their
        # documentation. The finding stays; --min-confidence decides.
        self.assertIn("K8S008", self.confidences("docs/examples/web.yaml"))


class TestScale(unittest.TestCase):
    """A guard against accidental quadratic behaviour in the walk."""

    def test_a_thousand_files_stay_well_under_a_second_each(self):
        import time

        files = {
            f"pkg{index // 50}/module{index}.py": "def f():\n    return 1\n" * 10
            for index in range(1000)
        }
        root = repository(files)
        started = time.monotonic()
        result = engine.scan(root)
        elapsed = time.monotonic() - started
        self.assertEqual(result.file_count, 1000)
        # Generous by two orders of magnitude: this is here to catch an O(n^2)
        # walk or a per-file re-read, not to police the constant factor.
        self.assertLess(elapsed, 20.0, f"1000 files took {elapsed:.1f}s")


class TestCollapse(unittest.TestCase):
    """Scanners overlap on purpose; reports should not."""

    def finding(self, rule_id, severity, evidence="AKIA****LM3D", line=6, subject="AKIA****LM3D"):
        from repo_sentinel.findings import Finding, Severity

        return Finding(
            rule_id=rule_id,
            severity=Severity.parse(severity),
            title=rule_id,
            path="s.yaml",
            line=line,
            evidence=evidence,
            subject=subject,
        )

    def test_the_same_value_at_the_same_line_is_reported_once(self):
        kept = engine.collapse([self.finding("SEC022", "high"), self.finding("K8S008", "critical")])
        self.assertEqual([finding.rule_id for finding in kept], ["K8S008"])

    def test_a_tie_keeps_the_format_specific_rule(self):
        kept = engine.collapse(
            [self.finding("SEC022", "critical"), self.finding("K8S008", "critical")]
        )
        self.assertEqual([finding.rule_id for finding in kept], ["K8S008"])

    def test_different_values_on_one_line_both_survive(self):
        kept = engine.collapse(
            [
                self.finding("SEC001", "critical"),
                self.finding("SEC005", "critical", subject="sk_l****90ab"),
            ]
        )
        self.assertEqual(len(kept), 2)

    def test_findings_with_no_subject_are_never_collapsed(self):
        # Two Dockerfile rules can report the same line with the same evidence
        # and mean entirely different things. An unpinned base image is not the
        # same problem as a container running as root.
        kept = engine.collapse(
            [
                self.finding("DK001", "medium", evidence="FROM debian", subject=""),
                self.finding("DK002", "medium", evidence="FROM debian", subject=""),
            ]
        )
        self.assertEqual(sorted(finding.rule_id for finding in kept), ["DK001", "DK002"])

    def test_the_same_value_repeated_in_one_file_is_counted_not_repeated(self):
        # One credential is one thing to rotate however many times it was
        # pasted. The finding points at the first occurrence.
        kept = engine.collapse(
            [
                self.finding("SEC001", "critical", line=9),
                self.finding("SEC001", "critical"),
                self.finding("SEC001", "critical", line=40),
            ]
        )
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].occurrences, 3)
        self.assertEqual(kept[0].line, 6)

    def test_the_same_value_in_two_files_is_two_findings(self):
        kept = engine.collapse(
            [
                self.finding("SEC001", "critical"),
                dataclasses.replace(self.finding("SEC001", "critical"), path="other.py"),
            ]
        )
        self.assertEqual(len(kept), 2)
        self.assertEqual({finding.occurrences for finding in kept}, {1})


if __name__ == "__main__":
    unittest.main()
