import contextlib
import io
import json
import os
import tempfile
import unittest

import fixtures
from repo_sentinel import cli
from repo_sentinel.discovery import iter_files
from repo_sentinel.findings import Severity


@contextlib.contextmanager
def sample_repo():
    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, ".github", "workflows"))
        os.makedirs(os.path.join(root, "node_modules"))
        with open(os.path.join(root, "app.py"), "w", encoding="utf-8") as handle:
            handle.write(f'AWS_KEY = "{fixtures.REALISTIC_AWS_KEY_ID}"\n')
        with open(os.path.join(root, ".github", "workflows", "ci.yml"), "w", encoding="utf-8") as handle:
            handle.write("jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n")
        with open(os.path.join(root, "node_modules", "leak.py"), "w", encoding="utf-8") as handle:
            handle.write(f'KEY = "{fixtures.REALISTIC_AWS_KEY_ID}"\n')
        with open(os.path.join(root, "logo.png"), "wb") as handle:
            handle.write(b"\x89PNG\x00\x00binary")
        yield root


def run(argv):
    """Run the CLI, returning ``(exit_code, stdout)``.

    Standard error is captured too, and dropped: the tests that care about a
    failure assert on the exit code, and a suite that prints the tool's error
    messages between its own dots is a suite people stop reading.
    """
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = cli.main(argv)
    return code, stdout.getvalue()


class TestDiscovery(unittest.TestCase):
    def test_skips_excluded_directories_and_binaries(self):
        with sample_repo() as root:
            paths = {path for path, _ in iter_files(root)}
        self.assertIn("app.py", paths)
        self.assertIn(".github/workflows/ci.yml", paths)
        self.assertNotIn("node_modules/leak.py", paths)
        self.assertNotIn("logo.png", paths)


class TestScanPath(unittest.TestCase):
    def test_findings_are_sorted_worst_first(self):
        with sample_repo() as root:
            findings = cli.scan_path(root)
        self.assertTrue(findings)
        severities = [finding.severity.rank for finding in findings]
        self.assertEqual(severities, sorted(severities, reverse=True))

    def test_both_scanners_contribute(self):
        with sample_repo() as root:
            rules = {finding.rule_id for finding in cli.scan_path(root)}
        self.assertIn("SEC001", rules)
        self.assertIn("WF001", rules)


class TestCli(unittest.TestCase):
    def test_json_output_is_valid_and_complete(self):
        with sample_repo() as root:
            code, output = run(["scan", root, "--format", "json"])
        payload = json.loads(output)
        self.assertEqual(code, cli.EXIT_FINDINGS)
        self.assertEqual(payload["finding_count"], len(payload["findings"]))
        self.assertIn("severity", payload["findings"][0])

    def test_min_severity_filters_output(self):
        with sample_repo() as root:
            _, output = run(["scan", root, "--format", "json", "--min-severity", "critical"])
        payload = json.loads(output)
        self.assertTrue(payload["findings"])
        for finding in payload["findings"]:
            self.assertEqual(finding["severity"], "critical")

    def test_fail_on_threshold_controls_exit_code(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "a.py"), "w", encoding="utf-8") as handle:
                handle.write('k = "sk_test_abcdefghij0123456789"\n')
            low, _ = run(["scan", root, "--fail-on", "low"])
            high, _ = run(["scan", root, "--fail-on", "high"])
        self.assertEqual(low, cli.EXIT_FINDINGS)
        self.assertEqual(high, cli.EXIT_OK)

    def test_clean_repository_exits_zero(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "README.md"), "w", encoding="utf-8") as handle:
                handle.write("# Nothing to see\n")
            code, output = run(["scan", root])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("No findings", output)

    def test_documentation_credentials_do_not_fail_the_build(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "README.md"), "w", encoding="utf-8") as handle:
                handle.write('    aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"\n')
            code, output = run(["scan", root])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("No findings", output)

    def test_no_example_allowlist_reports_them_again(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "README.md"), "w", encoding="utf-8") as handle:
                handle.write('    aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"\n')
            code, output = run(
                ["scan", root, "--format", "json", "--no-example-allowlist"]
            )
        self.assertEqual(code, cli.EXIT_FINDINGS)
        rules = {finding["rule_id"] for finding in json.loads(output)["findings"]}
        self.assertIn("SEC001", rules)

    def test_extra_excludes_are_honoured(self):
        with sample_repo() as root:
            _, output = run(["scan", root, "--format", "json", "--exclude", "app.py"])
        paths = {finding["path"] for finding in json.loads(output)["findings"]}
        self.assertNotIn("app.py", paths)


class TestSeverityParsing(unittest.TestCase):
    def test_parses_case_insensitively(self):
        self.assertEqual(Severity.parse("  HIGH "), Severity.HIGH)

    def test_rejects_nonsense(self):
        with self.assertRaises(ValueError):
            Severity.parse("catastrophic")


class TestRulesCommand(unittest.TestCase):
    def test_lists_the_catalogue_without_scanning_anything(self):
        code, output = run(["rules"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("SEC001", output)
        self.assertIn("DK003", output)

    def test_json_form_is_parseable(self):
        _, output = run(["rules", "--format", "json"])
        self.assertTrue(json.loads(output)["rules"])


class TestSarifOutput(unittest.TestCase):
    def test_emits_a_document_github_can_ingest(self):
        with sample_repo() as root:
            code, output = run(["scan", root, "--format", "sarif"])
        document = json.loads(output)
        self.assertEqual(code, cli.EXIT_FINDINGS)
        self.assertEqual(document["version"], "2.1.0")
        self.assertTrue(document["runs"][0]["results"])

    def test_writes_to_a_file_when_asked(self):
        with sample_repo() as root:
            destination = os.path.join(root, "out", "results.sarif")
            code, output = run(["scan", root, "--format", "sarif", "--output", destination])
            with open(destination, encoding="utf-8") as handle:
                document = json.load(handle)
        self.assertEqual(code, cli.EXIT_FINDINGS)
        self.assertEqual(output, "")
        self.assertTrue(document["runs"][0]["results"])


class TestConfidenceFilter(unittest.TestCase):
    def test_min_confidence_hides_the_heuristics(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "app.py"), "w", encoding="utf-8") as handle:
                handle.write('api_key = "Qq7Zx9Lm2Pv4Rt8WcY6h"\n')
            loose, _ = run(["scan", root, "--fail-on", "high"])
            strict, output = run(
                ["scan", root, "--fail-on", "high", "--min-confidence", "high"]
            )
        self.assertEqual(loose, cli.EXIT_FINDINGS)
        self.assertEqual(strict, cli.EXIT_OK)
        self.assertIn("No findings", output)


class TestBaselineIntegration(unittest.TestCase):
    def test_recording_then_scanning_leaves_a_clean_run(self):
        with sample_repo() as root:
            path = os.path.join(root, "baseline.json")
            code, output = run(["scan", root, "--write-baseline", path])
            self.assertEqual(code, cli.EXIT_OK)
            self.assertIn("Recorded", output)

            code, output = run(["scan", root, "--baseline", path])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("accepted by", output)

    def test_a_new_finding_still_fails_the_build(self):
        with sample_repo() as root:
            path = os.path.join(root, "baseline.json")
            run(["scan", root, "--write-baseline", path])
            with open(os.path.join(root, "new.py"), "w", encoding="utf-8") as handle:
                handle.write(f'KEY = "{fixtures.REALISTIC_AWS_KEY_ID}"\n')
            code, output = run(["scan", root, "--baseline", path])
        self.assertEqual(code, cli.EXIT_FINDINGS)
        self.assertIn("new.py", output)

    def test_a_fixed_finding_is_reported_as_a_stale_entry(self):
        with sample_repo() as root:
            path = os.path.join(root, "baseline.json")
            run(["scan", root, "--write-baseline", path])
            os.remove(os.path.join(root, "app.py"))
            _, output = run(["scan", root, "--baseline", path])
        self.assertIn("no longer match", output)

    def test_a_missing_baseline_is_an_error_not_a_pass(self):
        with sample_repo() as root:
            code, _ = run(["scan", root, "--baseline", os.path.join(root, "absent.json")])
        self.assertEqual(code, cli.EXIT_ERROR)


class TestRunSummary(unittest.TestCase):
    def test_reports_how_much_was_scanned(self):
        with sample_repo() as root:
            _, output = run(["scan", root])
        self.assertIn("file(s) in", output)

    def test_an_empty_scan_says_so_rather_than_looking_clean(self):
        with tempfile.TemporaryDirectory() as root:
            _, output = run(["scan", root])
        self.assertIn("Scanned 0 files", output)


if __name__ == "__main__":
    unittest.main()
