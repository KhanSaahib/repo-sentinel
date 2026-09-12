"""Findings that a file's name justifies on its own."""

import unittest

from bluerayscan.findings import Confidence, Severity
from bluerayscan.scanners import filenames


def scan(path, text=None):
    """Scan one path. ``text`` is None for a file the walk could not read."""
    return list(filenames.scan_name(path, text))


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


class TestKeyMaterial(unittest.TestCase):
    def test_an_ssh_private_key_is_critical_and_certain(self):
        finding = scan("deploy/id_rsa")[0]
        self.assertEqual(finding.rule_id, "FN001")
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertEqual(finding.confidence, Confidence.HIGH)

    def test_the_public_half_is_not_a_finding(self):
        self.assertEqual(scan("deploy/id_rsa.pub", "ssh-rsa AAAA...\n"), [])

    def test_keystores_are_reported_because_nothing_can_read_them(self):
        for name in ("app.p12", "release.jks", "signing.pfx", "server.keystore"):
            with self.subTest(name=name):
                self.assertIn("FN001", rule_ids(scan(name)))

    def test_an_ambiguous_extension_that_could_be_read_is_left_to_the_text_rules(self):
        # If it is text, SEC004 has looked inside and either found a private
        # key block or not. That answer beats a guess about the extension.
        self.assertEqual(scan("certs/server.pem", "-----BEGIN CERTIFICATE-----\n"), [])

    def test_an_ambiguous_extension_that_could_not_be_read_is_reported(self):
        finding = scan("certs/server.pem")[0]
        self.assertEqual(finding.rule_id, "FN002")
        self.assertEqual(finding.confidence, Confidence.MEDIUM)

    def test_a_fixture_directory_lowers_the_confidence_rather_than_the_report(self):
        finding = scan("tests/fixtures/server.key")[0]
        self.assertEqual(finding.confidence, Confidence.LOW)


class TestCredentialFiles(unittest.TestCase):
    """Files that exist to hold a credential, and files that merely might."""

    SECRET = "API_TOKEN=Tv8nRw1YXk92mQp7Lz4T\n"

    def test_files_with_no_legitimate_committed_form(self):
        # The file is the credential; its contents change nothing.
        for name in (".netrc", ".pgpass", "kubeconfig", ".my.cnf", "credentials"):
            with self.subTest(name=name):
                self.assertIn("FN003", rule_ids(scan(name, "anything at all\n")))

    def test_a_file_that_might_hold_one_is_judged_on_what_it_holds(self):
        for name in (".npmrc", ".pypirc", "terraform.tfvars", ".env"):
            with self.subTest(name=name):
                self.assertIn("FN003", rule_ids(scan(name, self.SECRET)))
                self.assertEqual(scan(name, "ignore-scripts=true\n"), [])

    def test_a_template_value_is_not_a_credential(self):
        # This is what a committed .env almost always is: documented defaults.
        self.assertEqual(scan(".env", "POSTGRES_PASSWORD=changeit\nHOST=localhost\n"), [])

    def test_an_unreadable_one_falls_back_to_its_name(self):
        self.assertIn("FN003", rule_ids(scan(".npmrc")))

    def test_dotenv_in_its_several_spellings(self):
        for name in (".env", ".env.production", "config/.env.local"):
            with self.subTest(name=name):
                self.assertIn("FN003", rule_ids(scan(name, self.SECRET)))

    def test_example_files_are_the_right_thing_to_do(self):
        for name in (".env.example", ".npmrc.sample", "terraform.tfvars.template", ".env.dist"):
            with self.subTest(name=name):
                self.assertEqual(scan(name, self.SECRET), [])

    def test_an_ordinary_file_is_not_a_finding(self):
        for name in ("README.md", "src/main.py", "package.json", "environment.yml"):
            with self.subTest(name=name):
                self.assertEqual(scan(name, self.SECRET), [])


class TestPasswordDatabases(unittest.TestCase):
    """A committed vault is one master password away from everything."""

    def test_a_keepass_database_is_reported_by_name(self):
        findings = scan("ops/secrets.kdbx")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "FN003")
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_the_other_vault_formats(self):
        for path in ("team.psafe3", "personal.opvault", "old.agilekeychain", "legacy.kdb"):
            with self.subTest(path=path):
                self.assertIn("FN003", rule_ids(scan(path)))

    def test_a_file_that_merely_mentions_one_is_not_one(self):
        self.assertEqual(scan("docs/how-we-use-keepass.md", "kdbx files stay out\n"), [])


class TestByproducts(unittest.TestCase):
    """Files that hold secrets as a side effect of what they are."""

    def test_terraform_state_is_critical(self):
        finding = scan("infra/terraform.tfstate", '{"version": 4}')[0]
        self.assertEqual(finding.rule_id, "FN004")
        self.assertEqual(finding.severity, Severity.CRITICAL)

    def test_a_state_backup_counts_too(self):
        self.assertIn("FN004", rule_ids(scan("terraform.tfstate.backup", "{}")))

    def test_a_kubeconfig_by_suffix(self):
        self.assertIn("FN004", rule_ids(scan("clusters/prod.kubeconfig", "apiVersion: v1\n")))

    def test_shell_and_client_histories(self):
        for name in (".bash_history", ".zsh_history", ".psql_history", ".mysql_history"):
            with self.subTest(name=name):
                finding = scan(name, "ls -la\n")[0]
                self.assertEqual(finding.severity, Severity.MEDIUM)

    def test_an_example_state_file_is_still_an_example(self):
        self.assertEqual(scan("terraform.tfstate.example", "{}"), [])

    def test_ordinary_files_are_not_byproducts(self):
        for name in ("main.tf", "state.py", "history.md"):
            with self.subTest(name=name):
                self.assertEqual(scan(name, "x\n"), [])


class TestFixtureTreesForByproducts(unittest.TestCase):
    """A state file under testdata/ is a fixture, like its siblings' files."""

    def test_a_state_file_in_a_test_tree_drops_a_step(self):
        shipped = scan("infra/terraform.tfstate")[0]
        fixture = scan("internal/providers/testdata/basic.tfstate")[0]
        self.assertEqual(shipped.rule_id, "FN004")
        self.assertLess(fixture.confidence, shipped.confidence)

    def test_it_is_weakened_rather_than_dropped(self):
        # Terraform's own repository has 162 of these. A real state file does
        # end up in a test directory, and that one is worth the look.
        self.assertIn("FN004", rule_ids(scan("internal/providers/testdata/basic.tfstate")))

    def test_a_history_file_is_weighed_the_same_way(self):
        shipped = scan(".bash_history")[0]
        fixture = scan("spec/fixtures/.bash_history")[0]
        self.assertLess(fixture.confidence, shipped.confidence)


class TestSuppression(unittest.TestCase):
    """A file that can be read can carry a marker, like every other file."""

    def test_a_marker_in_the_file_silences_the_name_rule(self):
        found = filenames.scan_paths(
            [(".npmrc", "# repo-sentinel: ignore-file\nAPI_TOKEN=Tv8nRw1YXk92mQp7Lz4T\n")]
        )
        self.assertEqual(found, [])

    def test_a_rule_scoped_marker_works_too(self):
        text = "# repo-sentinel: ignore-file[FN003]\nAPI_TOKEN=Tv8nRw1YXk92mQp7Lz4T\n"
        self.assertEqual(filenames.scan_paths([(".npmrc", text)]), [])

    def test_no_suppression_reads_past_it(self):
        text = "# repo-sentinel: ignore-file\nAPI_TOKEN=Tv8nRw1YXk92mQp7Lz4T\n"
        found = filenames.scan_paths([(".npmrc", text)], honour_markers=False)
        self.assertEqual([finding.rule_id for finding in found], ["FN003"])

    def test_an_unreadable_file_has_nowhere_to_put_a_marker(self):
        # Which is what the paths table in the config file is for.
        self.assertEqual(len(filenames.scan_paths([("deploy/id_rsa", None)])), 1)


class TestScanPaths(unittest.TestCase):
    def test_aggregates_over_the_walk(self):
        findings = filenames.scan_paths(
            [("app.py", "x = 1\n"), ("deploy/id_rsa", None), ("README.md", "# hi\n")]
        )
        self.assertEqual([finding.path for finding in findings], ["deploy/id_rsa"])

    def test_paths_are_reported_with_forward_slashes(self):
        finding = filenames.scan_paths([("deploy\\\\id_rsa", None)])[0]
        self.assertIn("/", finding.path)


if __name__ == "__main__":
    unittest.main()
