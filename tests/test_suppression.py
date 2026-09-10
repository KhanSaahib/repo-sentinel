"""Tests for line, block and file level suppression.

The markers are assembled from a prefix rather than written out, for the same
reason the scanner's own regex is: a test file full of verbatim directives
would suppress itself the moment anyone pointed the scanner at it.
"""

import unittest

import fixtures
from repo_sentinel import suppression
from repo_sentinel.scanners import secrets, workflows

_MARK = "repo-sentinel:"
LINE = f"# {_MARK} ignore"
FILE = f"# {_MARK} ignore-file"
START = f"# {_MARK} ignore-start"
END = f"# {_MARK} ignore-end"

SECRET_LINE = f'key = "{fixtures.REALISTIC_AWS_KEY_ID}"'


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


class TestMarkerScope(unittest.TestCase):
    def test_each_form_is_recognised(self):
        self.assertEqual(suppression.marker_scope(f"x = 1  {LINE}"), "line")
        self.assertEqual(suppression.marker_scope(FILE), "file")
        self.assertEqual(suppression.marker_scope(START), "start")
        self.assertEqual(suppression.marker_scope(END), "end")

    def test_a_plain_line_carries_no_directive(self):
        self.assertIsNone(suppression.marker_scope("just some code"))
        self.assertIsNone(suppression.marker_scope("# ignore this please"))

    def test_a_mistyped_scope_suppresses_nothing(self):
        # Failing towards reporting matters more than being forgiving: a typo
        # that silently degraded to a line-level ignore would hide findings.
        self.assertIsNone(suppression.marker_scope(f"# {_MARK} ignore-fil"))
        self.assertIsNone(suppression.marker_scope(f"# {_MARK} ignore_file"))

    def test_optional_whitespace_after_the_colon(self):
        self.assertEqual(suppression.marker_scope(f"#{_MARK}ignore"), "line")
        self.assertEqual(suppression.marker_scope(f"#{_MARK}\tignore-start"), "start")


class TestParse(unittest.TestCase):
    def test_a_file_without_markers_suppresses_nothing(self):
        marks = suppression.parse("one\ntwo\nthree\n")
        self.assertFalse(marks.whole_file)
        self.assertEqual(marks.lines, frozenset())
        self.assertIsNone(marks.unterminated_start)

    def test_a_block_covers_its_markers_and_everything_between(self):
        marks = suppression.parse("\n".join(["a", START, "b", "c", END, "d"]))
        self.assertEqual(marks.lines, frozenset({2, 3, 4, 5}))
        self.assertIsNone(marks.unterminated_start)

    def test_an_unterminated_block_runs_to_the_end_of_the_file(self):
        marks = suppression.parse("\n".join(["a", START, "b", "c"]))
        self.assertEqual(marks.lines, frozenset({2, 3, 4}))
        self.assertEqual(marks.unterminated_start, 2)

    def test_a_second_start_is_not_a_nesting_level(self):
        # Counting starts would let a missing end hide behind a later pair.
        marks = suppression.parse("\n".join([START, "a", START, "b", END, "c"]))
        self.assertEqual(marks.lines, frozenset({1, 2, 3, 4, 5}))
        self.assertIsNone(marks.unterminated_start)

    def test_a_stray_end_only_suppresses_its_own_line(self):
        marks = suppression.parse("\n".join(["a", END, "b"]))
        self.assertEqual(marks.lines, frozenset({2}))
        self.assertIsNone(marks.unterminated_start)

    def test_file_marker_in_the_header_covers_everything(self):
        marks = suppression.parse("\n".join([FILE, "a", "b"]))
        self.assertTrue(marks.whole_file)
        self.assertTrue(marks.suppresses(999))

    def test_file_marker_below_the_header_is_only_a_mention(self):
        padding = ["filler"] * suppression.FILE_MARKER_MAX_LINE
        marks = suppression.parse("\n".join(padding + [FILE, "a"]))
        self.assertFalse(marks.whole_file)
        self.assertFalse(marks.suppresses(len(padding) + 2))

    def test_the_last_header_line_still_counts(self):
        padding = ["filler"] * (suppression.FILE_MARKER_MAX_LINE - 1)
        marks = suppression.parse("\n".join(padding + [FILE, "a"]))
        self.assertTrue(marks.whole_file)


class TestSecretsHonourSuppression(unittest.TestCase):
    def test_line_marker_still_works(self):
        self.assertEqual(secrets.scan_text("a.py", f"{SECRET_LINE}  {LINE}"), [])

    def test_block_hides_the_lines_it_wraps(self):
        text = "\n".join([START, SECRET_LINE, END, SECRET_LINE])
        findings = secrets.scan_text("a.py", text)
        self.assertEqual([finding.line for finding in findings], [4])

    def test_file_marker_hides_the_whole_file(self):
        text = "\n".join([FILE, SECRET_LINE, SECRET_LINE])
        self.assertEqual(secrets.scan_text("a.py", text), [])

    def test_a_mention_below_the_header_does_not_blind_the_scanner(self):
        padding = ["filler"] * suppression.FILE_MARKER_MAX_LINE
        text = "\n".join(padding + [f"see {FILE}", SECRET_LINE])
        self.assertEqual(rule_ids(secrets.scan_text("README.md", text)), {"SEC001"})


class TestUnterminatedBlockIsReported(unittest.TestCase):
    def test_an_open_block_is_a_finding_of_its_own(self):
        text = "\n".join(["a", START, SECRET_LINE])
        findings = secrets.scan_text("a.py", text)
        self.assertEqual(rule_ids(findings), {suppression.UNTERMINATED_RULE_ID})
        self.assertEqual(findings[0].line, 2)

    def test_the_warning_never_echoes_the_secret_it_hid(self):
        text = "\n".join([START, SECRET_LINE])
        for finding in secrets.scan_text("a.py", text):
            self.assertNotIn(fixtures.REALISTIC_AWS_KEY_ID, finding.evidence)

    def test_a_closed_block_raises_no_warning(self):
        text = "\n".join([START, SECRET_LINE, END])
        self.assertEqual(secrets.scan_text("a.py", text), [])

    def test_a_whole_file_directive_makes_the_warning_moot(self):
        text = "\n".join([FILE, START, SECRET_LINE])
        self.assertEqual(secrets.scan_text("a.py", text), [])


class TestWorkflowsHonourSuppression(unittest.TestCase):
    def test_line_marker_suppresses_a_workflow_finding(self):
        text = (
            "permissions:\n  contents: read\n"
            f"jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4  {LINE}\n"
        )
        self.assertEqual(workflows.scan_workflow(".github/workflows/ci.yml", text), [])

    def test_file_marker_silences_the_workflow(self):
        text = f"{FILE}\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n"
        self.assertEqual(workflows.scan_workflow(".github/workflows/ci.yml", text), [])

    def test_an_unmarked_workflow_is_still_checked(self):
        text = "permissions:\n  contents: read\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n"
        findings = workflows.scan_workflow(".github/workflows/ci.yml", text)
        self.assertEqual(rule_ids(findings), {"WF001"})


if __name__ == "__main__":
    unittest.main()
