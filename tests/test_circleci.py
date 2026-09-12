"""CircleCI rules: the same injection a fourth time, and orbs that move."""

import unittest

from repo_sentinel.findings import Severity
from repo_sentinel.scanners import circleci


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


def scan(text, path=".circleci/config.yml"):
    return circleci.scan_config(path, text)


def config(body):
    return "version: 2.1\njobs:\n  build:\n" + body


class TestRecognition(unittest.TestCase):
    def test_recognised_by_its_one_path(self):
        self.assertTrue(circleci.is_named_config(".circleci/config.yml"))
        self.assertTrue(circleci.is_named_config("sub/.circleci/config.yaml"))
        self.assertFalse(circleci.is_named_config("config.yml"))

    def test_recognised_by_shape_elsewhere(self):
        text = config('    steps:\n      - run: echo "$CIRCLE_BRANCH"\n')
        self.assertIn("CC001", rule_ids(scan(text, "ci/shared.yml")))

    def test_other_yaml_is_left_alone(self):
        self.assertEqual(scan("services:\n  db:\n    image: postgres\n", "compose.yml"), [])


class TestInjection(unittest.TestCase):
    def test_untrusted_variables(self):
        for variable in ("CIRCLE_BRANCH", "CIRCLE_TAG", "CIRCLE_PR_USERNAME"):
            with self.subTest(variable=variable):
                text = config(f'    steps:\n      - run: echo "${variable}"\n')
                findings = scan(text)
                self.assertIn("CC001", rule_ids(findings))
                self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_the_long_form_of_a_step(self):
        text = config(
            '    steps:\n      - run:\n          name: Greet\n'
            '          command: echo "$CIRCLE_BRANCH"\n'
        )
        self.assertIn("CC001", rule_ids(scan(text)))

    def test_a_trusted_variable_is_not_a_finding(self):
        text = config('    steps:\n      - run: echo "$CIRCLE_BUILD_NUM"\n')
        self.assertEqual(scan(text), [])


class TestOrbs(unittest.TestCase):
    def test_moving_references(self):
        for reference in ("circleci/aws-cli@volatile", "acme/tools@dev:feature"):
            with self.subTest(reference=reference):
                text = f"version: 2.1\norbs:\n  tool: {reference}\njobs:\n  build:\n    steps: []\n"
                findings = scan(text)
                self.assertIn("CC002", rule_ids(findings))
                self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_a_released_version_is_a_pin(self):
        text = "version: 2.1\norbs:\n  node: circleci/node@5.1.0\njobs:\n  build:\n    steps: []\n"
        self.assertEqual(scan(text), [])


class TestImagesAndDownloads(unittest.TestCase):
    def test_a_floating_image(self):
        text = config("    docker:\n      - image: cimg/node\n    steps: []\n")
        self.assertIn("CC003", rule_ids(scan(text)))

    def test_a_pinned_image(self):
        text = config("    docker:\n      - image: cimg/node:20.11\n    steps: []\n")
        self.assertEqual(scan(text), [])

    def test_pipe_to_shell(self):
        text = config("    steps:\n      - run: curl -sSL https://x.invalid/i.sh | sh\n")
        self.assertIn("CC004", rule_ids(scan(text)))

    def test_a_verified_download_is_fine(self):
        text = config(
            "    steps:\n      - run: curl -sSLo i.sh https://x.invalid/i.sh\n"
            "      - run: sha256sum -c i.sha\n"
        )
        self.assertEqual(scan(text), [])


class TestSuppression(unittest.TestCase):
    def test_line_marker(self):
        text = config('    steps:\n      - run: echo "$CIRCLE_BRANCH"  # repo-sentinel: ignore\n')
        self.assertEqual(scan(text), [])


if __name__ == "__main__":
    unittest.main()
