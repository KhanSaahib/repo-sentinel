"""Reading history: what a commit added, and when it became public."""

import contextlib
import io
import os
import sys
import tempfile
import unittest

import fixtures
from bluerayscan import cli, diffs, history


#: Assembled rather than written out, like every other fixture here: a test
#: file that spells a documented shape contiguously is a test file every
#: credential scanner in the world reports, and there is a test asserting so.
_PEM_HEADER = "-----" + "BEGIN OPENSSH PRIVATE KEY" + "-----"


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


def run(argv, stdin=None):
    stdout, stderr = io.StringIO(), io.StringIO()
    saved = sys.stdin
    if stdin is not None:
        sys.stdin = io.StringIO(stdin)
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(argv)
    finally:
        sys.stdin = saved
    return code, stdout.getvalue(), stderr.getvalue()


def commit(sha, date, body):
    return (
        f"commit {sha}\n"
        "Author: A Developer <dev@example.invalid>\n"
        f"Date:   {date}\n"
        "\n"
        "    A message\n"
        "\n"
        f"{body}"
    )


def added(path, start, lines):
    """One file's hunk, adding ``lines`` beginning at ``start``."""
    body = "".join(f"+{line}\n" for line in lines)
    return (
        f"diff --git a/{path} b/{path}\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        f"@@ -{start},0 +{start},{len(lines)} @@\n"
        f"{body}"
    )


class TestReadingADiff(unittest.TestCase):
    def test_added_lines_keep_the_numbers_they_landed_on(self):
        stream = commit("abc1234", "2026-03-04 10:00:00 +0000", added("app.py", 12, ["x = 1", "y = 2"]))
        additions = list(diffs.parse(stream.splitlines()))
        self.assertEqual(len(additions), 1)
        lines = additions[0].text.splitlines()
        self.assertEqual(len(lines), 13)
        self.assertEqual(lines[11], "x = 1")
        self.assertEqual(lines[12], "y = 2")
        self.assertEqual(lines[0], "")

    def test_a_removed_line_is_not_this_commit_s_news(self):
        # The whole point of reading history this way: what a commit took out
        # was still committed, and what it put in is what it is answerable for.
        body = (
            "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n"
            "@@ -1,3 +1,3 @@\n context\n-gone = 1\n+kept = 2\n"
        )
        addition = next(diffs.parse(commit("a" * 40, "x", body).splitlines()))
        self.assertNotIn("gone", addition.text)
        self.assertIn("kept", addition.text)

    def test_a_deletion_adds_nothing(self):
        body = (
            "diff --git a/gone.py b/gone.py\n--- a/gone.py\n+++ /dev/null\n"
            "@@ -1,1 +0,0 @@\n-x = 1\n"
        )
        self.assertEqual(list(diffs.parse(commit("b" * 40, "x", body).splitlines())), [])

    def test_several_files_in_several_commits(self):
        stream = (
            commit("1111111", "2026-03-04 10:00:00 +0000",
                   added("a.py", 1, ["one"]) + added("b.py", 1, ["two"]))
            + commit("2222222", "2026-03-05 10:00:00 +0000", added("c.py", 1, ["three"]))
        )
        additions = list(diffs.parse(stream.splitlines()))
        self.assertEqual([a.path for a in additions], ["a.py", "b.py", "c.py"])
        self.assertEqual([a.commit.short for a in additions], ["1111111", "1111111", "2222222"])

    def test_the_author_and_date_are_read_from_the_header(self):
        addition = next(diffs.parse(
            commit("c" * 40, "2026-03-04 10:00:00 +0000", added("a.py", 1, ["x"])).splitlines()
        ))
        self.assertIn("A Developer", addition.commit.author)
        self.assertEqual(addition.commit.describe(), "ccccccc on 2026-03-04")

    def test_a_line_of_source_is_not_read_as_a_header(self):
        # "Date: ..." in somebody's source file is a line of their source.
        stream = commit("d" * 40, "2026-03-04 10:00:00 +0000",
                        added("doc.txt", 1, ["Date:   not a header", "Author: nor this"]))
        addition = next(diffs.parse(stream.splitlines()))
        self.assertEqual(addition.commit.date, "2026-03-04 10:00:00 +0000")
        self.assertIn("A Developer", addition.commit.author)

    def test_nothing_at_all(self):
        self.assertEqual(list(diffs.parse([])), [])

    def test_a_diff_with_no_commit_header_still_reads(self):
        # `git diff` on its own has no commits in it, and is a reasonable thing
        # to pipe in. The finding simply has no commit to name.
        additions = list(diffs.parse(added("a.py", 1, ["x = 1"]).splitlines()))
        self.assertEqual(len(additions), 1)
        self.assertEqual(additions[0].commit.describe(), "an unnamed commit")


class TestDates(unittest.TestCase):
    def test_the_two_shapes_git_writes(self):
        for value in ("Thu Mar 4 10:00:00 2026 +0000", "2026-03-04 10:00:00 +0000"):
            with self.subTest(value=value):
                parsed = diffs.parse_date(value)
                self.assertIsNotNone(parsed)
                self.assertEqual(parsed.date().isoformat(), "2026-03-04")

    def test_anything_else_is_left_alone_rather_than_guessed_at(self):
        self.assertIsNone(diffs.parse_date("last Tuesday"))


class TestScanningHistory(unittest.TestCase):
    LEAK = f'AWS_KEY = "{fixtures.REALISTIC_AWS_KEY_ID}"'

    def test_a_credential_a_commit_added(self):
        stream = commit("abc1234", "2026-03-04 10:00:00 +0000", added("app.py", 3, [self.LEAK]))
        report = history.scan_stream(stream.splitlines())
        self.assertEqual(report.commit_count, 1)
        self.assertEqual(report.file_count, 1)
        finding = report.findings[0]
        self.assertEqual(finding.path, "app.py")
        self.assertEqual(finding.line, 3)
        self.assertEqual(finding.origin, "abc1234 on 2026-03-04")

    def test_the_oldest_commit_is_the_one_that_matters(self):
        # A value added, reverted and added again is public from the first
        # time, which is the date a rotation decision turns on.
        stream = (
            commit("2222222", "2026-05-01 10:00:00 +0000", added("app.py", 3, [self.LEAK]))
            + commit("1111111", "2026-03-04 10:00:00 +0000", added("app.py", 3, [self.LEAK]))
        )
        report = history.scan_stream(stream.splitlines())
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].origin, "1111111 on 2026-03-04")

    def test_without_readable_dates_the_stream_order_decides(self):
        # git log prints newest first, so the last time something is seen is
        # the earliest it was committed.
        stream = (
            commit("2222222", "yesterday", added("app.py", 3, [self.LEAK]))
            + commit("1111111", "the day before", added("app.py", 3, [self.LEAK]))
        )
        report = history.scan_stream(stream.splitlines())
        self.assertEqual(report.findings[0].origin, "1111111")

    def test_the_same_value_in_two_files_is_two_findings(self):
        stream = commit(
            "abc1234", "2026-03-04 10:00:00 +0000",
            added("a.py", 1, [self.LEAK]) + added("b.py", 1, [self.LEAK]),
        )
        report = history.scan_stream(stream.splitlines())
        self.assertEqual({f.path for f in report.findings}, {"a.py", "b.py"})

    def test_a_file_named_like_a_credential(self):
        stream = commit("abc1234", "2026-03-04 10:00:00 +0000",
                        added("deploy/id_rsa", 1, [_PEM_HEADER]))
        self.assertTrue(history.scan_stream(stream.splitlines()).findings)

    def test_an_unterminated_block_is_not_a_finding_about_a_diff(self):
        # A reconstruction holds one commit's added lines, so a block opened in
        # an older commit has no end in it. That rule is about a file as it
        # stands.
        stream = commit("abc1234", "2026-03-04 10:00:00 +0000",
                        added("app.py", 1, ["# bluerayscan: ignore-start", "x = 1"]))
        self.assertNotIn("SEC900", rule_ids(history.scan_stream(stream.splitlines()).findings))

    def test_a_marker_on_the_added_line_is_still_obeyed(self):
        stream = commit("abc1234", "2026-03-04 10:00:00 +0000",
                        added("app.py", 1, [self.LEAK + "  # bluerayscan: ignore"]))
        self.assertEqual(history.scan_stream(stream.splitlines()).findings, [])

    def test_configuration_in_history_is_history(self):
        # A Dockerfile that ran as root in 2021 and does not today is fixed.
        # Only the credential rules run here, and this is the assertion that
        # says so rather than a comment hoping so.
        stream = commit("abc1234", "2026-03-04 10:00:00 +0000",
                        added("Dockerfile", 1, ["FROM debian:latest", "USER root"]))
        self.assertEqual(history.scan_stream(stream.splitlines()).findings, [])


class TestTheCommand(unittest.TestCase):
    LEAK = f'AWS_KEY = "{fixtures.REALISTIC_AWS_KEY_ID}"'

    def stream(self):
        return commit("abc1234", "2026-03-04 10:00:00 +0000", added("app.py", 3, [self.LEAK]))

    def test_it_reads_standard_input_by_default(self):
        code, output, _ = run(["history", "--fail-on", "none"], stdin=self.stream())
        self.assertEqual(code, 0)
        self.assertIn("added in: abc1234 on 2026-03-04", output)

    def test_it_reads_a_file_when_given_one(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "log.diff")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(self.stream())
            code, output, _ = run(["history", path, "--fail-on", "none"])
        self.assertEqual(code, 0)
        self.assertIn("app.py:3", output)

    def test_a_finding_fails_the_run(self):
        code, _, _ = run(["history"], stdin=self.stream())
        self.assertEqual(code, 1)

    def test_a_missing_file_is_an_error_not_a_clean_history(self):
        code, _, errors = run(["history", "does/not/exist.diff"])
        self.assertEqual(code, 2)
        self.assertIn("could not read", errors)

    def test_an_empty_pipe_says_so(self):
        # "git log" with no -p has no diffs in it, and reports nothing found,
        # which is the most dangerous answer this tool can give.
        code, output, _ = run(["history"], stdin="")
        self.assertEqual(code, 0)
        self.assertIn("No commits in the input", output)

    def test_the_summary_counts_what_it_read(self):
        code, output, _ = run(["history", "--fail-on", "none"], stdin=self.stream())
        self.assertIn("Read 1 commit(s) and 1 file revision(s).", output)

    def test_json_carries_the_commit(self):
        import json

        code, output, _ = run(
            ["history", "--fail-on", "none", "--format", "json"], stdin=self.stream()
        )
        payload = json.loads(output)
        self.assertEqual(payload["findings"][0]["origin"], "abc1234 on 2026-03-04")
        self.assertEqual(payload["scan"], {"commits": 1, "file_revisions": 1})

    def test_sarif_carries_the_commit_too(self):
        import json

        from bluerayscan import report as report_module

        code, output, _ = run(
            ["history", "--fail-on", "none", "--format", "sarif"], stdin=self.stream()
        )
        result = json.loads(output)["runs"][0]["results"][0]
        self.assertEqual(result["properties"]["origin"], "abc1234 on 2026-03-04")
        self.assertIn(report_module.SARIF_FINGERPRINT_KEY, result["partialFingerprints"])

    def test_the_other_formats_all_render(self):
        for shape in ("sarif", "markdown", "github", "junit"):
            with self.subTest(format=shape):
                code, output, _ = run(
                    ["history", "--fail-on", "none", "--format", shape], stdin=self.stream()
                )
                self.assertEqual(code, 0)
                self.assertTrue(output.strip())

    def test_an_unreadable_threshold_is_an_error(self):
        code, _, errors = run(["history", "--min-severity", "urgent"], stdin="")
        self.assertEqual(code, 2)
        self.assertIn("urgent", errors)


class TtyStringIO(io.StringIO):
    def isatty(self):
        return True


def run_tty(argv, stdin=None):
    stdout, stderr = TtyStringIO(), io.StringIO()
    saved = sys.stdin
    if stdin is not None:
        sys.stdin = io.StringIO(stdin)
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(argv)
    finally:
        sys.stdin = saved
    return code, stdout.getvalue(), stderr.getvalue()


@contextlib.contextmanager
def temporary_env(**kwargs):
    old = {}
    for key, value in kwargs.items():
        old[key] = os.environ.get(key)
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    try:
        yield
    finally:
        for key, value in old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class TestHistoryColor(unittest.TestCase):
    LEAK = f'AWS_KEY = "{fixtures.REALISTIC_AWS_KEY_ID}"'

    def stream(self):
        return commit("abc1234", "2026-03-04 10:00:00 +0000", added("app.py", 3, [self.LEAK]))

    def test_explicit_no_color_flag_disables_colour(self):
        with temporary_env(NO_COLOR=None):
            _, output, _ = run_tty(
                ["history", "--fail-on", "none", "--no-color"], stdin=self.stream()
            )
        self.assertNotIn("\033", output)

    def test_no_color_unset_keeps_colour(self):
        with temporary_env(NO_COLOR=None):
            _, output, _ = run_tty(["history", "--fail-on", "none"], stdin=self.stream())
        self.assertIn("\033", output)

    def test_no_color_empty_string_keeps_colour(self):
        with temporary_env(NO_COLOR=""):
            _, output, _ = run_tty(["history", "--fail-on", "none"], stdin=self.stream())
        self.assertIn("\033", output)

    def test_no_color_non_empty_disables_colour(self):
        with temporary_env(NO_COLOR="1"):
            _, output, _ = run_tty(
                ["history", "--fail-on", "none"], stdin=self.stream()
            )
        self.assertNotIn("\033", output)


if __name__ == "__main__":
    unittest.main()
