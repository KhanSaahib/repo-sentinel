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


class TestInit(unittest.TestCase):
    """The first five minutes: what is here, what to accept, what to run."""

    def repository(self, root):
        with open(os.path.join(root, "Dockerfile"), "w", encoding="utf-8") as handle:
            handle.write("FROM debian:latest\nRUN curl -s https://x/i.sh | sh\n")

    def test_writes_a_config_a_baseline_and_a_snippet(self):
        with tempfile.TemporaryDirectory() as root:
            self.repository(root)
            code, output = run(["init", root])
            config_path = os.path.join(root, ".repo-sentinel.json")
            with open(config_path, encoding="utf-8") as handle:
                settings = json.load(handle)
        self.assertEqual(code, cli.EXIT_OK)
        self.assertEqual(settings["fail_on"], "high")
        self.assertEqual(settings["baseline"], ".repo-sentinel-baseline.json")
        self.assertIn("repo-sentinel", output)
        self.assertIn("uses: KhanSaahib/repo-sentinel", output)

    def test_the_repository_is_green_immediately_afterwards(self):
        # The point of the baseline is that the first pipeline run passes and
        # every later one is about new work.
        with tempfile.TemporaryDirectory() as root:
            self.repository(root)
            run(["init", root])
            code, _ = run(["scan", root])
        self.assertEqual(code, cli.EXIT_OK)

    def test_a_clean_repository_gets_a_config_and_no_baseline(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "README.md"), "w", encoding="utf-8") as handle:
                handle.write("# nothing\n")
            run(["init", root])
            self.assertTrue(os.path.exists(os.path.join(root, ".repo-sentinel.json")))
            self.assertFalse(os.path.exists(os.path.join(root, ".repo-sentinel-baseline.json")))

    def test_existing_files_are_left_alone(self):
        with tempfile.TemporaryDirectory() as root:
            self.repository(root)
            with open(os.path.join(root, ".repo-sentinel.json"), "w", encoding="utf-8") as handle:
                handle.write('{"fail_on": "critical"}')
            _, output = run(["init", root])
            with open(os.path.join(root, ".repo-sentinel.json"), encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["fail_on"], "critical")
        self.assertIn("exists already", output)

    def test_force_overwrites(self):
        with tempfile.TemporaryDirectory() as root:
            self.repository(root)
            with open(os.path.join(root, ".repo-sentinel.json"), "w", encoding="utf-8") as handle:
                handle.write('{"fail_on": "critical"}')
            run(["init", root, "--force"])
            with open(os.path.join(root, ".repo-sentinel.json"), encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["fail_on"], "high")

    def test_no_baseline_records_nothing(self):
        with tempfile.TemporaryDirectory() as root:
            self.repository(root)
            run(["init", root, "--no-baseline"])
            self.assertFalse(os.path.exists(os.path.join(root, ".repo-sentinel-baseline.json")))

    def test_the_snippet_matches_the_ci_system_the_repository_has(self):
        with tempfile.TemporaryDirectory() as root:
            self.repository(root)
            with open(os.path.join(root, ".gitlab-ci.yml"), "w", encoding="utf-8") as handle:
                handle.write("stages: [test]\n")
            _, output = run(["init", root])
        self.assertIn(".gitlab-ci.yml", output)
        self.assertNotIn("runs-on", output)


class TestRulesCommand(unittest.TestCase):
    def test_lists_the_catalogue_without_scanning_anything(self):
        code, output = run(["rules"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("SEC001", output)
        self.assertIn("DK003", output)

    def test_a_pattern_narrows_the_list(self):
        code, output = run(["rules", "compose"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("DC001", output)
        self.assertNotIn("SEC001", output)

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


class TestMarkdownOutput(unittest.TestCase):
    def test_emits_a_table_for_a_pull_request_comment(self):
        with sample_repo() as root:
            code, output = run(["scan", root, "--format", "markdown"])
        self.assertEqual(code, cli.EXIT_FINDINGS)
        self.assertIn("### repo-sentinel:", output)
        self.assertIn("| --- |", output)


class TestGitHubOutput(unittest.TestCase):
    def test_emits_annotations_the_runner_understands(self):
        with sample_repo() as root:
            code, output = run(["scan", root, "--format", "github"])
        self.assertEqual(code, cli.EXIT_FINDINGS)
        self.assertTrue(any(line.startswith("::error ") for line in output.splitlines()))


class TestFailureModes(unittest.TestCase):
    """The paths a pipeline hits at three in the morning."""

    def test_an_unwritable_output_path_is_an_error_not_a_traceback(self):
        with sample_repo() as root:
            blocker = os.path.join(root, "blocker")
            with open(blocker, "w", encoding="utf-8") as handle:
                handle.write("not a directory\n")
            code, output = run(["scan", root, "--output", os.path.join(blocker, "out.txt")])
        self.assertEqual(code, cli.EXIT_ERROR)
        self.assertEqual(output, "")

    def test_a_nonsense_severity_is_rejected_by_the_parser(self):
        with sample_repo() as root:
            with self.assertRaises(SystemExit) as caught:
                run(["scan", root, "--min-severity", "catastrophic"])
        self.assertEqual(caught.exception.code, 2)

    def test_a_nonsense_confidence_is_rejected_too(self):
        with sample_repo() as root:
            with self.assertRaises(SystemExit):
                run(["scan", root, "--min-confidence", "certain"])


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

    def test_pruning_removes_stale_entries_and_accepts_nothing(self):
        # The difference from --write-baseline is the whole point of having
        # both: rewriting accepts everything the scan just found.
        with sample_repo() as root:
            path = os.path.join(root, "baseline.json")
            run(["scan", root, "--write-baseline", path])
            os.remove(os.path.join(root, "app.py"))
            with open(os.path.join(root, "new.py"), "w", encoding="utf-8") as handle:
                handle.write(f'KEY = "{fixtures.REALISTIC_AWS_KEY_ID}"\n')

            code, output = run(["scan", root, "--prune-baseline", path])
            self.assertEqual(code, cli.EXIT_OK)
            self.assertIn("Pruned", output)
            self.assertIn("Nothing new was accepted", output)

            code, output = run(["scan", root, "--baseline", path])
        self.assertEqual(code, cli.EXIT_FINDINGS)
        self.assertIn("new.py", output)
        self.assertNotIn("no longer match", output)

    def test_pruning_a_baseline_with_nothing_stale_says_so(self):
        with sample_repo() as root:
            path = os.path.join(root, "baseline.json")
            run(["scan", root, "--write-baseline", path])
            code, output = run(["scan", root, "--prune-baseline", path])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("Nothing to prune", output)

    def test_pruning_a_missing_baseline_is_an_error(self):
        with sample_repo() as root:
            code, _ = run(["scan", root, "--prune-baseline", os.path.join(root, "absent.json")])
        self.assertEqual(code, cli.EXIT_ERROR)

    def test_a_missing_baseline_is_an_error_not_a_pass(self):
        with sample_repo() as root:
            code, _ = run(["scan", root, "--baseline", os.path.join(root, "absent.json")])
        self.assertEqual(code, cli.EXIT_ERROR)


class TestRunSummary(unittest.TestCase):
    def test_reports_how_much_was_scanned(self):
        with sample_repo() as root:
            _, output = run(["scan", root])
        self.assertIn("file(s) in", output)

    def test_a_directory_that_could_not_be_read_is_named(self):
        import stat

        with tempfile.TemporaryDirectory() as root:
            locked = os.path.join(root, "locked")
            os.makedirs(locked)
            with open(os.path.join(locked, "app.py"), "w", encoding="utf-8") as handle:
                handle.write("x = 1\n")
            os.chmod(locked, 0)
            try:
                _, output = run(["scan", root])
            finally:
                os.chmod(locked, stat.S_IRWXU)
        # Nothing was readable, so the file count is zero -- the case where a
        # silent scan reads as "clean" and the warning matters most.
        self.assertIn("Scanned 0 files", output)
        self.assertIn("could not be opened", output)

    def test_a_path_that_does_not_exist_is_an_error_not_a_clean_scan(self):
        with tempfile.TemporaryDirectory() as root:
            code, output = run(["scan", os.path.join(root, "nope")])
        self.assertEqual(code, 2)
        self.assertNotIn("No findings", output)

    def test_a_root_that_cannot_be_read_is_named_by_the_path_given(self):
        import stat

        with tempfile.TemporaryDirectory() as root:
            locked = os.path.join(root, "locked")
            os.makedirs(locked)
            os.chmod(locked, 0)
            try:
                _, output = run(["scan", locked])
            finally:
                os.chmod(locked, stat.S_IRWXU)
        # The root's path relative to itself is the empty string, which would
        # otherwise be reported as "starting with ''".
        self.assertNotIn("starting with ''", output)
        self.assertIn("locked", output)

    def test_an_empty_scan_says_so_rather_than_looking_clean(self):
        with tempfile.TemporaryDirectory() as root:
            _, output = run(["scan", root])
        self.assertIn("Scanned 0 files", output)


class TestPathList(unittest.TestCase):
    def test_only_the_listed_files_are_scanned(self):
        with sample_repo() as root:
            listing = os.path.join(root, "changed.txt")
            with open(listing, "w", encoding="utf-8") as handle:
                handle.write(".github/workflows/ci.yml\n")
            _, output = run(["scan", root, "--format", "json", "--paths-from", listing])
        paths = {finding["path"] for finding in json.loads(output)["findings"]}
        self.assertEqual(paths, {".github/workflows/ci.yml"})

    def test_a_deleted_path_is_skipped_not_fatal(self):
        # A diff lists deletions too, and a scanner that fails on one is a
        # scanner nobody puts in a pipeline.
        with sample_repo() as root:
            listing = os.path.join(root, "changed.txt")
            with open(listing, "w", encoding="utf-8") as handle:
                handle.write("app.py\ndeleted.py\n")
            code, output = run(["scan", root, "--paths-from", listing])
        self.assertEqual(code, cli.EXIT_FINDINGS)
        self.assertIn("Scanned 1 file(s)", output)

    def test_a_missing_list_is_a_usage_error(self):
        with sample_repo() as root:
            code, _ = run(["scan", root, "--paths-from", os.path.join(root, "absent.txt")])
        self.assertEqual(code, cli.EXIT_ERROR)

    def test_an_ignored_file_is_still_scanned_when_named(self):
        # The caller named it. Second-guessing an explicit list is how a tool
        # acquires a reputation for missing things.
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, ".gitignore"), "w", encoding="utf-8") as handle:
                handle.write("secrets.py\n")
            with open(os.path.join(root, "secrets.py"), "w", encoding="utf-8") as handle:
                handle.write(f'KEY = "{fixtures.REALISTIC_AWS_KEY_ID}"\n')
            listing = os.path.join(root, "changed.txt")
            with open(listing, "w", encoding="utf-8") as handle:
                handle.write("secrets.py\n")
            walked, _ = run(["scan", root])
            listed, _ = run(["scan", root, "--paths-from", listing])
        self.assertEqual(walked, cli.EXIT_OK)
        self.assertEqual(listed, cli.EXIT_FINDINGS)


class TestSuppressionVisibility(unittest.TestCase):
    """Silence is always counted, and can always be read past."""

    def repository(self, root):
        with open(os.path.join(root, "Dockerfile"), "w", encoding="utf-8") as handle:
            handle.write("FROM debian:latest  # repo-sentinel: ignore\nUSER app\n")

    def test_the_markers_are_counted_even_when_obeyed(self):
        with tempfile.TemporaryDirectory() as root:
            self.repository(root)
            code, output = run(["scan", root])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("carry a suppression marker", output)

    def test_no_suppression_reads_past_them(self):
        with tempfile.TemporaryDirectory() as root:
            self.repository(root)
            code, output = run(["scan", root, "--no-suppression"])
        self.assertEqual(code, cli.EXIT_FINDINGS)
        self.assertIn("DK001", output)

    def test_a_repository_with_no_markers_says_nothing_about_them(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "Dockerfile"), "w", encoding="utf-8") as handle:
                handle.write("FROM debian:12@sha256:" + "a" * 64 + "\nUSER app\n")
            _, output = run(["scan", root])
        self.assertNotIn("suppression marker", output)


class TestQuietAndSort(unittest.TestCase):
    def test_quiet_keeps_the_counts_and_drops_the_detail(self):
        with sample_repo() as root:
            _, output = run(["scan", root, "--quiet"])
        self.assertIn("finding(s):", output)
        self.assertNotIn("evidence:", output)

    def test_sorting_by_path_groups_a_file_together(self):
        with sample_repo() as root:
            _, output = run(["scan", root, "--format", "json", "--sort", "path"])
        paths = [finding["path"] for finding in json.loads(output)["findings"]]
        self.assertEqual(paths, sorted(paths))

    def test_default_order_is_worst_first(self):
        with sample_repo() as root:
            _, output = run(["scan", root, "--format", "json"])
        ranks = [
            ["low", "medium", "high", "critical"].index(finding["severity"])
            for finding in json.loads(output)["findings"]
        ]
        self.assertEqual(ranks, sorted(ranks, reverse=True))


if __name__ == "__main__":
    unittest.main()
