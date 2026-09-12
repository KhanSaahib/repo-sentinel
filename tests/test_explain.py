"""Answering the question a scanner's silence cannot answer."""

import contextlib
import io
import sys
import unittest

import fixtures
from bluerayscan import cli, explain, heuristics


def run(argv, stdin=None):
    stdout = io.StringIO()
    saved = sys.stdin
    if stdin is not None:
        sys.stdin = io.StringIO(stdin)
    try:
        with contextlib.redirect_stdout(stdout):
            code = cli.main(argv)
    finally:
        sys.stdin = saved
    return code, stdout.getvalue()


#: Assembled, like every fixture here.
GENERATED = "Xk92" + "mQp7Lz4TvB8n" + "Rw1Y"


class TestTheMeasurements(unittest.TestCase):
    def test_it_says_what_it_measured(self):
        answer = explain.explain(GENERATED, "api_key")
        body = answer.render()
        for word in ("length", "alphabet", "entropy", "floor", "shape", "name"):
            self.assertIn(word, body)

    def test_the_value_is_redacted_like_any_other_report(self):
        # This prints a value somebody pasted from a file they are worried
        # about. Printing it back whole would be the one thing this tool
        # promises not to do.
        body = explain.explain(GENERATED, "api_key").render()
        self.assertNotIn(GENERATED, body)
        self.assertIn("*", body)

    def test_the_alphabet_named_is_the_alphabet_counted(self):
        # The name and the number have to come from one decision. They did
        # not, in the first draft: "aA1" counted as 16 and read as "letters
        # and digits", because the hex set rebuilt here was lowercase only.
        for value in ("1234", "deadbeef", "DEADBEEF", "aZ1", "a-z_1", "A-Z_1",
                      "aZ1+/=", "aZ1 !", GENERATED):
            with self.subTest(value=value):
                described = explain.describe_alphabet(value)
                self.assertTrue(
                    described.startswith(f"{heuristics.alphabet_size(value)} symbols "),
                    f"{value!r}: {described}",
                )

    def test_the_names_are_the_classes_the_heuristic_has(self):
        self.assertIn("digits", explain.describe_alphabet("1234"))
        self.assertIn("hex", explain.describe_alphabet("deadbeef"))
        self.assertIn("letters and digits", explain.describe_alphabet("aZ1"))
        self.assertIn("punctuation", explain.describe_alphabet("aZ1 !"))


class TestTheVerdict(unittest.TestCase):
    def verdict(self, value, name=""):
        return explain.explain(value, name).verdict

    def test_a_documented_shape_is_reported_whatever_it_is_called(self):
        answer = explain.explain(fixtures.REALISTIC_AWS_KEY_ID, "banana")
        self.assertTrue(answer.reported)
        self.assertIn("SEC001", answer.verdict)

    def test_a_published_example_is_not(self):
        # The AWS documentation's own key. It matches the shape and is not a
        # credential, which is what the allowlist is for.
        answer = explain.explain("AKIAIOSFODNN7EXAMPLE", "aws_access_key_id")
        self.assertFalse(answer.reported)
        self.assertIn("--no-example-allowlist", answer.verdict)

    def test_a_generated_value_beside_a_credential_name(self):
        answer = explain.explain(GENERATED, "api_key")
        self.assertTrue(answer.reported)
        self.assertIn("SEC100", answer.verdict)

    def test_the_same_value_beside_an_ordinary_name(self):
        answer = explain.explain(GENERATED, "build_id")
        self.assertFalse(answer.reported)
        self.assertIn("build id", answer.verdict)

    def test_with_no_name_it_says_the_name_is_the_missing_half(self):
        answer = explain.explain(GENERATED)
        self.assertFalse(answer.reported)
        self.assertIn("--name", answer.verdict)

    def test_too_short_says_how_short(self):
        self.assertIn("entropy rules start at", self.verdict("hunter2", "password"))

    def test_below_the_floor_says_by_how_much(self):
        verdict = self.verdict("this-is-a-bad-password-", "password")
        self.assertIn("bits below the floor", verdict)
        self.assertIn("0.10", verdict)

    def test_a_placeholder_is_named_as_one(self):
        self.assertIn("placeholder", self.verdict("<YOUR_TOKEN_HERE>", "token"))

    def test_text_in_another_script_is_not_a_credential(self):
        # Discourse's translated interface strings, which measured as
        # high-entropy for a reason that has nothing to do with randomness.
        self.assertIn("ASCII", self.verdict("كلمة المرور الخاصة بك هنا", "password"))

    def test_nothing_to_measure(self):
        self.assertIn("Nothing to measure", self.verdict("", "password"))


class TestTheCommand(unittest.TestCase):
    def test_it_prints_the_explanation(self):
        code, output = run(["explain", GENERATED, "--name", "api_key"])
        self.assertIn("entropy", output)

    def test_the_exit_code_answers_the_question(self):
        # So a shell can ask without reading the prose.
        reported, _ = run(["explain", GENERATED, "--name", "api_key"])
        quiet, _ = run(["explain", GENERATED, "--name", "build_id"])
        self.assertEqual((reported, quiet), (1, 0))

    def test_it_reads_a_value_from_stdin(self):
        code, output = run(["explain", "-", "--name", "api_key"], stdin=GENERATED + "\n")
        self.assertEqual(code, 1)
        self.assertIn("api_key", output)

    def test_a_value_with_no_name_at_all(self):
        code, output = run(["explain", GENERATED])
        self.assertEqual(code, 0)
        self.assertIn("--name", output)


if __name__ == "__main__":
    unittest.main()
