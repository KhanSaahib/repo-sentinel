import contextlib
import io
import json
import os
import tempfile
import unittest

import fixtures
from repo_sentinel import cli
from repo_sentinel.baseline import Baseline, BaselineError, fingerprint, serialise
from repo_sentinel.findings import Finding, Severity


def make_finding(**overrides):
    fields = {
        "rule_id": "SEC001",
        "severity": Severity.CRITICAL,
        "title": "AWS access key id",
        "path": "app.py",
        "line": 3,
        "evidence": "AKIA****************WXYZ",
    }
    fields.update(overrides)
    return Finding(**fields)


def run(argv):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = cli.main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


@contextlib.contextmanager
def leaky_repo():
    """A repository with one critical secret and one workflow finding."""
    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, ".github", "workflows"))
        with open(os.path.join(root, "app.py"), "w", encoding="utf-8") as handle:
            handle.write(f'AWS_KEY = "{fixtures.REALISTIC_AWS_KEY_ID}"\n')
        with open(
            os.path.join(root, ".github", "workflows", "ci.yml"), "w", encoding="utf-8"
        ) as handle:
            handle.write("jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n")
        yield root


class TestFingerprint(unittest.TestCase):
    def test_survives_the_finding_moving_down_the_file(self):
        self.assertEqual(
            fingerprint(make_finding(line=3)),
            fingerprint(make_finding(line=91)),
        )

    def test_survives_a_severity_retune(self):
        self.assertEqual(
            fingerprint(make_finding(severity=Severity.CRITICAL)),
            fingerprint(make_finding(severity=Severity.HIGH)),
        )

    def test_distinguishes_the_same_secret_in_another_file(self):
        self.assertNotEqual(
            fingerprint(make_finding(path="app.py")),
            fingerprint(make_finding(path="lib/app.py")),
        )

    def test_distinguishes_a_different_secret_in_the_same_file(self):
        self.assertNotEqual(
            fingerprint(make_finding(evidence="AKIA****************WXYZ")),
            fingerprint(make_finding(evidence="AKIA****************0000")),
        )

    def test_distinguishes_two_rules_firing_on_one_line(self):
        self.assertNotEqual(
            fingerprint(make_finding(rule_id="SEC001")),
            fingerprint(make_finding(rule_id="SEC100")),
        )


class TestSerialise(unittest.TestCase):
    def test_is_stable_across_runs_and_input_order(self):
        one = make_finding(path="a.py")
        two = make_finding(path="b.py", evidence="AKIA****************0000")
        self.assertEqual(serialise([one, two]), serialise([two, one]))

    def test_collapses_the_same_secret_repeated_in_one_file(self):
        payload = json.loads(serialise([make_finding(line=3), make_finding(line=9)]))
        self.assertEqual(len(payload["findings"]), 1)

    def test_records_only_redacted_evidence(self):
        with leaky_repo() as root:
            findings = cli.scan_path(root)
        text = serialise(findings)
        self.assertNotIn(fixtures.REALISTIC_AWS_KEY_ID, text)


class TestLoad(unittest.TestCase):
    def _write(self, root, payload):
        path = os.path.join(root, "baseline.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(payload if isinstance(payload, str) else json.dumps(payload))
        return path

    def test_missing_file_is_an_error_not_an_empty_baseline(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(BaselineError):
                Baseline.load(os.path.join(root, "nope.json"))

    def test_corrupt_json_is_an_error(self):
        with tempfile.TemporaryDirectory() as root:
            path = self._write(root, "{not json")
            with self.assertRaises(BaselineError):
                Baseline.load(path)

    def test_a_future_format_version_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            path = self._write(root, {"baseline_version": 99, "findings": []})
            with self.assertRaises(BaselineError):
                Baseline.load(path)

    def test_an_entry_without_a_fingerprint_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            path = self._write(
                root, {"baseline_version": 1, "findings": [{"rule_id": "SEC001"}]}
            )
            with self.assertRaises(BaselineError):
                Baseline.load(path)

    def test_round_trips_what_serialise_wrote(self):
        with tempfile.TemporaryDirectory() as root:
            path = self._write(root, serialise([make_finding()]))
            self.assertEqual(len(Baseline.load(path)), 1)


class TestFilter(unittest.TestCase):
    def test_accepted_findings_are_removed_and_new_ones_are_not(self):
        accepted = make_finding()
        fresh = make_finding(path="new.py")
        recorded = Baseline([fingerprint(accepted)])
        self.assertEqual(recorded.filter([accepted, fresh]), [fresh])

    def test_stale_entries_are_counted(self):
        recorded = Baseline([fingerprint(make_finding()), "deadbeef"])
        recorded.filter([make_finding()])
        self.assertEqual(recorded.stale_count, 1)


class TestCliIntegration(unittest.TestCase):
    def test_write_then_scan_is_green_and_a_new_secret_turns_it_red(self):
        with leaky_repo() as root:
            path = os.path.join(root, "baseline.json")
            written, out, _ = run(["scan", root, "--write-baseline", path])
            self.assertEqual(written, cli.EXIT_OK)
            self.assertIn("Recorded", out)

            clean, out, _ = run(["scan", root, "--baseline", path])
            self.assertEqual(clean, cli.EXIT_OK)
            self.assertIn("hidden by the baseline", out)

            with open(os.path.join(root, "later.py"), "w", encoding="utf-8") as handle:
                handle.write(f'KEY = "{fixtures.REALISTIC_AWS_KEY_ID}"\n')
            dirty, _, _ = run(["scan", root, "--baseline", path])
            self.assertEqual(dirty, cli.EXIT_FINDINGS)

    def test_baselined_findings_survive_the_file_growing(self):
        with leaky_repo() as root:
            path = os.path.join(root, "baseline.json")
            run(["scan", root, "--write-baseline", path])
            app = os.path.join(root, "app.py")
            with open(app, encoding="utf-8") as handle:
                body = handle.read()
            with open(app, "w", encoding="utf-8") as handle:
                handle.write("import os\nimport sys\n\n" + body)
            code, _, _ = run(["scan", root, "--baseline", path])
        self.assertEqual(code, cli.EXIT_OK)

    def test_json_output_reports_what_the_baseline_did(self):
        with leaky_repo() as root:
            path = os.path.join(root, "baseline.json")
            run(["scan", root, "--write-baseline", path])
            _, out, _ = run(["scan", root, "--baseline", path, "--format", "json"])
        report = json.loads(out)["baseline"]
        self.assertGreater(report["suppressed"], 0)
        self.assertEqual(report["stale_entries"], 0)

    def test_a_fixed_finding_is_reported_as_a_stale_entry(self):
        with leaky_repo() as root:
            path = os.path.join(root, "baseline.json")
            run(["scan", root, "--write-baseline", path])
            with open(os.path.join(root, "app.py"), "w", encoding="utf-8") as handle:
                handle.write("AWS_KEY = os.environ['AWS_KEY']\n")
            _, out, _ = run(["scan", root, "--baseline", path, "--format", "json"])
        self.assertEqual(json.loads(out)["baseline"]["stale_entries"], 1)

    def test_a_missing_baseline_fails_loudly_rather_than_scanning_clean(self):
        with leaky_repo() as root:
            code, _, err = run(
                ["scan", root, "--baseline", os.path.join(root, "absent.json")]
            )
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertIn("not found", err)

    def test_write_baseline_records_findings_below_min_severity(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "a.py"), "w", encoding="utf-8") as handle:
                handle.write('k = "sk_test_abcdefghij0123456789"\n')
            path = os.path.join(root, "baseline.json")
            run(["scan", root, "--min-severity", "critical", "--write-baseline", path])
            with open(path, encoding="utf-8") as handle:
                recorded = json.load(handle)["findings"]
        self.assertEqual([entry["rule_id"] for entry in recorded], ["SEC010"])

    def test_the_two_baseline_flags_are_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                cli.main(["scan", ".", "--baseline", "a.json", "--write-baseline", "b.json"])


if __name__ == "__main__":
    unittest.main()
