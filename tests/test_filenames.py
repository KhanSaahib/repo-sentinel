"""Findings that a file's name justifies on its own."""

import unittest

from repo_sentinel.findings import Confidence, Severity
from repo_sentinel.scanners import filenames


def scan(path, readable=False):
    return list(filenames.scan_name(path, readable))


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


class TestKeyMaterial(unittest.TestCase):
    def test_an_ssh_private_key_is_critical_and_certain(self):
        finding = scan("deploy/id_rsa")[0]
        self.assertEqual(finding.rule_id, "FN001")
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertEqual(finding.confidence, Confidence.HIGH)

    def test_the_public_half_is_not_a_finding(self):
        self.assertEqual(scan("deploy/id_rsa.pub", readable=True), [])

    def test_keystores_are_reported_because_nothing_can_read_them(self):
        for name in ("app.p12", "release.jks", "signing.pfx", "server.keystore"):
            with self.subTest(name=name):
                self.assertIn("FN001", rule_ids(scan(name)))

    def test_an_ambiguous_extension_that_could_be_read_is_left_to_the_text_rules(self):
        # If it is text, SEC004 has looked inside and either found a private
        # key block or not. That answer beats a guess about the extension.
        self.assertEqual(scan("certs/server.pem", readable=True), [])

    def test_an_ambiguous_extension_that_could_not_be_read_is_reported(self):
        finding = scan("certs/server.pem", readable=False)[0]
        self.assertEqual(finding.rule_id, "FN002")
        self.assertEqual(finding.confidence, Confidence.MEDIUM)

    def test_a_fixture_directory_lowers_the_confidence_rather_than_the_report(self):
        finding = scan("tests/fixtures/server.key", readable=False)[0]
        self.assertEqual(finding.confidence, Confidence.LOW)


class TestCredentialFiles(unittest.TestCase):
    def test_files_that_exist_to_hold_a_credential(self):
        for name in (".npmrc", ".pypirc", ".netrc", ".pgpass", "kubeconfig", "terraform.tfvars"):
            with self.subTest(name=name):
                self.assertIn("FN003", rule_ids(scan(name, readable=True)))

    def test_dotenv_in_its_several_spellings(self):
        for name in (".env", ".env.production", "config/.env.local"):
            with self.subTest(name=name):
                self.assertIn("FN003", rule_ids(scan(name, readable=True)))

    def test_example_files_are_the_right_thing_to_do(self):
        for name in (".env.example", ".npmrc.sample", "terraform.tfvars.template", ".env.dist"):
            with self.subTest(name=name):
                self.assertEqual(scan(name, readable=True), [])

    def test_an_ordinary_file_is_not_a_finding(self):
        for name in ("README.md", "src/main.py", "package.json", "environment.yml"):
            with self.subTest(name=name):
                self.assertEqual(scan(name, readable=True), [])


class TestScanPaths(unittest.TestCase):
    def test_aggregates_over_the_walk(self):
        findings = filenames.scan_paths(
            [("app.py", True), ("deploy/id_rsa", False), ("README.md", True)]
        )
        self.assertEqual([finding.path for finding in findings], ["deploy/id_rsa"])

    def test_paths_are_reported_with_forward_slashes(self):
        finding = filenames.scan_paths([("deploy\\\\id_rsa", False)])[0]
        self.assertIn("/", finding.path)


if __name__ == "__main__":
    unittest.main()
