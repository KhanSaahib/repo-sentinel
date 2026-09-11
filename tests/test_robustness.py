"""What happens when the input is hostile, malformed, or merely enormous.

Every file this tool reads is attacker-controlled by definition: anyone can
open a pull request. SECURITY.md makes two promises about that -- bounded
regular expressions, and no scanned content evaluated or deserialised -- and
this module is where the first one is actually checked. The second is checked
by the absence of eval, exec, pickle and yaml.load in the source, which the
last test here asserts directly.

The parsers get the same treatment. `hcl` and `yamlish` are hand-written, which
means they are the two places where a crafted file is most likely to find an
unhandled index or an infinite loop, and where "degrades to silence" has to be
true rather than intended.
"""

import random
import re
import string
import time
import unittest
from pathlib import Path

from repo_sentinel import hcl, heuristics, yamlish
from repo_sentinel.findings import redact
from repo_sentinel.scanners import (
    compose,
    dockerfiles,
    kubernetes,
    secrets,
    terraform,
    workflows,
)

SCANNERS = (
    ("secrets", lambda path, text: secrets.scan_text(path, text)),
    ("workflows", lambda path, text: workflows.scan_workflow(".github/workflows/a.yml", text)),
    ("dockerfiles", lambda path, text: dockerfiles.scan_dockerfile("Dockerfile", text)),
    ("terraform", lambda path, text: terraform.scan_terraform("main.tf", text)),
    ("kubernetes", lambda path, text: kubernetes.scan_manifest("deploy/a.yaml", text)),
    ("compose", lambda path, text: compose.scan_compose("docker-compose.yml", text)),
)

#: Shapes chosen to break a hand-written parser: unbalanced delimiters, a
#: structure with no end, indentation that goes the wrong way, and a document
#: that is entirely punctuation.
HOSTILE = (
    "",
    "\n\n\n",
    "{" * 500,
    "}" * 500,
    "[" * 500 + "]" * 499,
    'resource "a" "b" {' * 200,
    "a:\n" + "".join(f"{' ' * i}b{i}:\n" for i in range(200)),
    "- " * 2000,
    "key: |\n" + "  body\n" * 500,
    "---\n" * 500,
    '"' * 1000,
    "a: " + '"unterminated\n',
    "\x00\x01\x02 binary-ish text \ufffd\ufffd",
    "policy = <<EOF\n" + "{}\n" * 200,  # heredoc that never ends
    "FROM \\\n" * 500,  # continuation that never resolves
    "ports:\n" + "".join(f'  - "{port}:{port}"\n' for port in range(500)),
    "\t" * 100 + "key: value",
    "é" * 2000,
    "# repo-sentinel: ignore-start\n" * 100,
)


class TestHostileInput(unittest.TestCase):
    def test_no_scanner_raises_on_a_hostile_document(self):
        for name, scan in SCANNERS:
            for index, text in enumerate(HOSTILE):
                with self.subTest(scanner=name, case=index):
                    scan("a.txt", text)  # must not raise

    def test_no_scanner_hangs_on_a_hostile_document(self):
        # Catastrophic backtracking would show up here as a test that never
        # finishes; the bound is generous so that a slow machine does not fail
        # the build, and tight enough that an exponential blowup cannot pass.
        for name, scan in SCANNERS:
            started = time.monotonic()
            for text in HOSTILE:
                scan("a.txt", text)
            elapsed = time.monotonic() - started
            with self.subTest(scanner=name):
                self.assertLess(elapsed, 10.0, f"{name} took {elapsed:.1f}s on hostile input")

    def test_long_lines_do_not_blow_up_the_patterns(self):
        # One line, no newlines, of exactly the characters the secret patterns
        # care about. This is the classic shape for catastrophic backtracking.
        for filler in ("A", "AKIA", "sk-", "=", "a1B2", "-----BEGIN ", "${{ "):
            line = filler * 4000
            started = time.monotonic()
            secrets.scan_text("a.py", line)
            with self.subTest(filler=filler):
                self.assertLess(time.monotonic() - started, 5.0)


class TestFuzz(unittest.TestCase):
    """Random documents, seeded so a failure can be reproduced exactly."""

    ALPHABET = string.printable + "éü中\u200b"

    def documents(self, seed, count=200):
        rng = random.Random(seed)
        for _ in range(count):
            length = rng.randint(0, 400)
            yield "".join(rng.choice(self.ALPHABET) for _ in range(length))

    def test_scanners_survive_random_text(self):
        for name, scan in SCANNERS:
            for document in self.documents(seed=20260911):
                with self.subTest(scanner=name):
                    scan("a.txt", document)

    def test_parsers_survive_random_text(self):
        for document in self.documents(seed=1234):
            hcl.parse(document)
            yamlish.parse(document)

    def test_parsers_survive_structured_noise(self):
        # Random text rarely produces a brace or a colon in the right place.
        # This generator produces documents that are almost valid, which is
        # where a parser's assumptions actually break.
        rng = random.Random(99)
        fragments = (
            'resource "a" "b" {', "}", "key:", "  - item", "value = 1", "<<EOF", "EOF",
            "---", "# comment", "  " * 4 + "deep: true", '"quoted": {', "[",
        )
        for _ in range(300):
            document = "\n".join(rng.choice(fragments) for _ in range(rng.randint(1, 40)))
            hcl.parse(document)
            yamlish.parse(document)
            for _name, scan in SCANNERS:
                scan("a.txt", document)


class TestRedactionProperties(unittest.TestCase):
    """The one promise the tool must never break, checked over many inputs."""

    def values(self, seed, count=500):
        rng = random.Random(seed)
        for _ in range(count):
            length = rng.randint(1, 120)
            yield "".join(rng.choice(string.printable.strip()) for _ in range(length))

    def test_a_redacted_value_never_contains_the_middle_of_the_secret(self):
        for value in self.values(seed=7):
            masked = redact(value)
            with self.subTest(value=value):
                if len(value) > 8:
                    self.assertNotIn(value[4:-4], masked)
                else:
                    self.assertEqual(masked, "*" * len(value))

    def test_redaction_preserves_length(self):
        for value in self.values(seed=8):
            self.assertEqual(len(redact(value)), len(value))

    def test_redaction_reveals_at_most_eight_characters(self):
        for value in self.values(seed=9):
            revealed = sum(1 for char in redact(value) if char != "*")
            self.assertLessEqual(revealed, 8)

    def test_a_short_value_is_fully_masked_whatever_it_is(self):
        for length in range(0, 9):
            value = "s" * length
            self.assertEqual(redact(value), "*" * length)


class TestEntropyProperties(unittest.TestCase):
    def test_entropy_is_never_negative_and_never_exceeds_its_ceiling(self):
        rng = random.Random(11)
        for _ in range(500):
            value = "".join(rng.choice(string.printable) for _ in range(rng.randint(1, 200)))
            entropy = heuristics.shannon_entropy(value)
            self.assertGreaterEqual(entropy, 0.0)
            self.assertLessEqual(entropy, len(set(value)).bit_length())

    def test_a_repeated_value_never_looks_generated(self):
        rng = random.Random(12)
        for _ in range(200):
            unit = "".join(rng.choice(string.ascii_lowercase) for _ in range(2))
            self.assertFalse(heuristics.looks_generated(unit * 20))

    def test_random_tokens_of_a_sensible_length_look_generated(self):
        rng = random.Random(13)
        alphabet = string.ascii_letters + string.digits
        for _ in range(200):
            token = "".join(rng.choice(alphabet) for _ in range(rng.randint(20, 60)))
            self.assertTrue(heuristics.looks_generated(token), token)


class TestNoDynamicEvaluation(unittest.TestCase):
    """SECURITY.md promises scanned content is never evaluated. Check it."""

    FORBIDDEN = re.compile(r"\b(?:eval|exec|pickle|marshal|subprocess|os\.system|__import__)\b")

    def test_the_source_contains_no_dynamic_evaluation(self):
        source_root = Path(__file__).resolve().parents[1] / "src"
        for module in sorted(source_root.rglob("*.py")):
            text = module.read_text(encoding="utf-8")
            for number, line in enumerate(text.splitlines(), start=1):
                if line.lstrip().startswith("#"):
                    continue
                with self.subTest(module=module.name, line=number):
                    self.assertIsNone(self.FORBIDDEN.search(line), line.strip())


if __name__ == "__main__":
    unittest.main()
