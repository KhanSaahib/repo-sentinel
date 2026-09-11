import base64
import unittest

import fixtures
from repo_sentinel.findings import Confidence, Severity, redact
from repo_sentinel.scanners import secrets


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


class TestRedaction(unittest.TestCase):
    def test_long_value_keeps_only_the_edges(self):
        self.assertEqual(redact("ABCD" + "x" * 12 + "WXYZ"), "ABCD" + "*" * 12 + "WXYZ")

    def test_short_value_is_fully_masked(self):
        self.assertEqual(redact("abcdefgh"), "*" * 8)

    def test_findings_never_echo_the_raw_secret(self):
        raw = fixtures.REALISTIC_AWS_KEY_ID
        findings = secrets.scan_text("app.py", f'key = "{raw}"')
        self.assertTrue(findings)
        for finding in findings:
            self.assertNotIn(raw, finding.evidence)


class TestProviderPatterns(unittest.TestCase):
    def test_detects_aws_access_key_id(self):
        findings = secrets.scan_text(
            "cfg.tf", f'access_key = "{fixtures.REALISTIC_AWS_KEY_ID}"'
        )
        self.assertIn("SEC001", rule_ids(findings))
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_detects_github_token(self):
        token = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
        self.assertIn("SEC002", rule_ids(secrets.scan_text("ci.sh", f"export T={token}")))

    def test_detects_private_key_header(self):
        findings = secrets.scan_text("id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----")
        self.assertIn("SEC004", rule_ids(findings))

    def test_live_and_test_stripe_keys_differ_in_severity(self):
        live = secrets.scan_text("a.py", 'k = "sk_live_abcdefghij0123456789"')[0]
        test = secrets.scan_text("a.py", 'k = "sk_test_abcdefghij0123456789"')[0]
        self.assertGreater(live.severity, test.severity)

    def test_reports_correct_line_number(self):
        text = "\n".join(
            ["import os", "", f'KEY = "{fixtures.REALISTIC_AWS_KEY_ID}"']
        )
        self.assertEqual(secrets.scan_text("a.py", text)[0].line, 3)


class TestEntropyAssignments(unittest.TestCase):
    def test_flags_high_entropy_password(self):
        findings = secrets.scan_text("settings.py", 'DB_PASSWORD = "Xk92mQp7Lz4TvB8nRw1Y"')
        self.assertIn("SEC100", rule_ids(findings))

    def test_ignores_placeholders(self):
        for value in (
            "your-password-here",
            "changeme_please",
            "xxxxxxxxxxxxxxxx",
            "<INSERT TOKEN HERE>",
            "${DATABASE_PASSWORD}",
            "aaaaaaaaaaaaaaaa",
        ):
            with self.subTest(value=value):
                findings = secrets.scan_text("cfg.yaml", f'password = "{value}"')
                self.assertNotIn("SEC100", rule_ids(findings), value)

    def test_ignores_low_entropy_values(self):
        findings = secrets.scan_text("cfg.py", 'api_key = "aaaabbbbccccdddd"')
        self.assertNotIn("SEC100", rule_ids(findings))

    def test_ignores_unrelated_variable_names(self):
        findings = secrets.scan_text("a.py", 'greeting = "Xk92mQp7Lz4TvB8nRw1Y"')
        self.assertEqual(findings, [])

    def test_does_not_double_report_a_provider_token(self):
        text = 'api_key = "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"'
        self.assertEqual(rule_ids(secrets.scan_text("a.py", text)), {"SEC002"})


class TestIgnoreMarker(unittest.TestCase):
    def test_marker_suppresses_the_line(self):
        line = f'key = "{fixtures.REALISTIC_AWS_KEY_ID}"  # repo-sentinel: ignore'
        self.assertEqual(secrets.scan_text("a.py", line), [])


class TestScanFiles(unittest.TestCase):
    def test_aggregates_across_files(self):
        findings = secrets.scan_files(
            [
                ("a.py", f'k = "{fixtures.REALISTIC_AWS_KEY_ID}"'),
                ("b.py", "nothing to see here"),
                ("c.py", "-----BEGIN RSA PRIVATE KEY-----"),
            ]
        )
        self.assertEqual({finding.path for finding in findings}, {"a.py", "c.py"})


class TestAdditionalProviders(unittest.TestCase):
    """The rules added after the first ten, spot-checked one apiece."""

    def assert_rule(self, rule_id, line):
        self.assertIn(rule_id, rule_ids(secrets.scan_text("config.py", line)))

    def test_azure_storage_key(self):
        self.assert_rule("SEC011", "AccountKey=" + "aB3dEf7h" * 10 + "aB3dEf" + "==")

    def test_google_oauth_client_secret(self):
        self.assert_rule("SEC012", 'secret = "GOC' + "SPX-" + "a" * 28 + '"')

    def test_sendgrid_key(self):
        self.assert_rule("SEC013", 'k = "S' + "G." + "a" * 22 + "." + "b" * 43 + '"')

    def test_npm_token(self):
        self.assert_rule("SEC015", "//registry.npmjs.org/:_authToken=np" + "m_" + "a" * 36)

    def test_pypi_token(self):
        self.assert_rule("SEC016", "password = pyp" + "i-AgEIcHlwaS5vcmc" + "a" * 60)

    def test_docker_hub_token(self):
        self.assert_rule("SEC017", 'token = "dck' + "r_pat_" + "a" * 24 + '"')

    def test_slack_webhook_url(self):
        self.assert_rule("SEC018", "https://hooks.sl" + "ack.com/services/T" + "a" * 32)

    def test_huggingface_token(self):
        self.assert_rule("SEC019", 'HF = "h' + "f_" + "a" * 34 + '"')

    def test_a_loose_shape_is_reported_at_lower_confidence(self):
        findings = secrets.scan_text("t.py", 'sid = "S' + "K" + "0a1b" * 8 + '"')
        twilio = next(f for f in findings if f.rule_id == "SEC014")
        self.assertEqual(twilio.confidence, Confidence.MEDIUM)


class TestFixtureTrees(unittest.TestCase):
    """Invented credentials live in fixture directories. So do real ones."""

    LINE = 'api_key = "Qq7Zx9Lm2Pv4Rt8WcY6h"'

    def test_a_guess_in_a_fixture_tree_is_reported_at_lower_confidence(self):
        ordinary = secrets.scan_text("app/config.py", self.LINE)[0]
        fixture = secrets.scan_text("config/testdata/conf.py", self.LINE)[0]
        self.assertEqual(ordinary.confidence, Confidence.MEDIUM)
        self.assertEqual(fixture.confidence, Confidence.LOW)

    def test_a_documented_token_shape_keeps_its_confidence_anywhere(self):
        # The entropy rules are guessing and fixtures make the guess worse. A
        # provider pattern is not guessing, and a real key does get committed
        # to a fixture tree -- that one is exactly what nobody is looking for.
        finding = secrets.scan_text(
            "tests/fixtures/creds.py", f'k = "{fixtures.REALISTIC_AWS_KEY_ID}"'
        )[0]
        self.assertEqual(finding.confidence, Confidence.HIGH)
        self.assertEqual(finding.severity, Severity.CRITICAL)


class TestUrlCredentials(unittest.TestCase):
    def test_reports_a_password_in_a_connection_string(self):
        findings = secrets.scan_text("db.py", 'DSN = "postgres://svc:Xk92mQp7Lz4TvB8n@db.internal:5432/app"')
        self.assertIn("SEC020", rule_ids(findings))

    def test_keeps_the_host_but_redacts_the_password(self):
        findings = secrets.scan_text("db.py", 'DSN = "postgres://svc:Xk92mQp7Lz4TvB8n@db.internal:5432/app"')
        evidence = next(f.evidence for f in findings if f.rule_id == "SEC020")
        self.assertIn("db.internal", evidence)
        self.assertNotIn("Xk92mQp7Lz4TvB8n", evidence)

    def test_ignores_documentation_and_placeholders(self):
        for line in (
            'DSN = "postgres://user:password@localhost:5432/app"',
            'DSN = "postgres://user:${PGPASSWORD}@db/app"',
            'DSN = "https://user:pass@example.com/"',
            "connect with scheme://user:password@host",
        ):
            with self.subTest(line=line):
                self.assertNotIn("SEC020", rule_ids(secrets.scan_text("db.py", line)))


class TestValuePositions(unittest.TestCase):
    """Formats that write credentials bare, with no quoting to key on."""

    def test_recognises_the_formats(self):
        for path in (".env", ".env.production", "config/app.ini", "docker-compose.yml", ".npmrc"):
            with self.subTest(path=path):
                self.assertTrue(secrets.has_value_positions(path))

    def test_leaves_source_code_alone(self):
        # In Python, `key = value` without quotes is a reference to another
        # variable. Reporting it as a credential would be nonsense.
        for path in ("app.py", "main.go", "index.ts"):
            with self.subTest(path=path):
                self.assertFalse(secrets.has_value_positions(path))
        self.assertEqual(secrets.scan_text("app.py", "api_key = Tv8nRw1YXk92mQp7"), [])

    def test_reports_an_unquoted_env_value(self):
        findings = secrets.scan_text(".env", "DATABASE_PASSWORD=Tv8nRw1YXk92mQp7Lz4T")
        self.assertIn("SEC101", rule_ids(findings))
        self.assertEqual(findings[0].confidence, Confidence.MEDIUM)

    def test_ignores_ordinary_settings(self):
        text = "APP_NAME=billing\nLOG_LEVEL=debug\nPORT=8080\nAPI_URL=https://api.internal/v1"
        self.assertEqual(secrets.scan_text(".env", text), [])

    def test_ignores_an_interpolated_reference(self):
        self.assertEqual(secrets.scan_text(".env", "API_TOKEN=${API_TOKEN}"), [])

    def test_reports_a_compose_environment_value(self):
        text = "services:\n  db:\n    environment:\n      MYSQL_ROOT_PASSWORD: Qq7Zx9Lm2Pv4Rt8W\n"
        self.assertIn("SEC101", rule_ids(secrets.scan_text("docker-compose.yml", text)))

    def test_does_not_report_the_same_value_twice(self):
        text = "AWS_SECRET_ACCESS_KEY=" + fixtures.REALISTIC_AWS_KEY_ID
        self.assertEqual(len(secrets.scan_text(".env", text)), 1)


class TestEncodedCredentials(unittest.TestCase):
    """base64 is an encoding, and encodings are not hiding places."""

    def encoded(self, value):
        return base64.b64encode(value.encode()).decode()

    def test_finds_a_provider_token_inside_base64(self):
        line = "token: " + self.encoded(fixtures.REALISTIC_AWS_KEY_ID)
        findings = secrets.scan_text("kubeconfig.yaml", line)
        self.assertEqual(rule_ids(findings), {"SEC022"})
        self.assertIn("base64", findings[0].title)

    def test_the_name_in_front_of_the_value_does_not_hide_it(self):
        # "TOKEN=QUtJ..." is one unbroken run of base64 characters if "=" is
        # part of the alphabet, and the joined string decodes to nothing.
        for line in (
            "TOKEN=" + self.encoded(fixtures.REALISTIC_AWS_KEY_ID),
            "aws_" + self.encoded(fixtures.REALISTIC_AWS_KEY_ID),
        ):
            with self.subTest(line=line[:20]):
                self.assertIn("SEC022", rule_ids(secrets.scan_text("ci.env", line)))

    def test_the_entropy_rule_does_not_report_it_a_second_time(self):
        line = "api_token: " + self.encoded(fixtures.REALISTIC_AWS_KEY_ID)
        self.assertEqual(rule_ids(secrets.scan_text("config.yaml", line)), {"SEC022"})

    def test_ordinary_base64_is_not_a_finding(self):
        blob = self.encoded("the quick brown fox jumps over the lazy dog, twice over")
        self.assertEqual(secrets.scan_text("a.py", f'BLOB = "{blob}"'), [])

    def test_a_binary_blob_is_not_decoded_into_a_finding(self):
        blob = base64.b64encode(bytes(range(256))).decode()
        self.assertEqual(secrets.scan_text("a.py", f'BLOB = "{blob}"'), [])

    def test_the_raw_value_never_reaches_the_report(self):
        line = "token: " + self.encoded(fixtures.REALISTIC_AWS_KEY_ID)
        finding = secrets.scan_text("kubeconfig.yaml", line)[0]
        self.assertNotIn(fixtures.REALISTIC_AWS_KEY_ID, finding.evidence)


class TestServiceAccountFiles(unittest.TestCase):
    """A finding that only exists when the whole document is read at once."""

    def document(self, *fields):
        return "{\n" + ",\n".join(fields) + "\n}\n"

    def test_type_and_private_key_together_are_a_key_file(self):
        text = self.document(
            '  "type": "service_account"',
            '  "project_id": "x"',
            '  "private_key_id": "a3f5c9d1b7e204863f2a"',
        )
        findings = secrets.scan_text("sa.json", text)
        self.assertIn("SEC021", rule_ids(findings))
        self.assertEqual(next(f for f in findings if f.rule_id == "SEC021").line, 2)

    def test_the_type_alone_is_not_a_credential(self):
        text = self.document('  "type": "service_account"', '  "client_email": "a@b.com"')
        self.assertEqual(secrets.scan_text("sa.json", text), [])

    def test_a_template_service_account_is_not_a_leak(self):
        # Charts ship these to document the shape. The key field is there and
        # empty, or filled with zeroes, which is the opposite of a credential.
        for fields in (
            ('  "type": "service_account"', '  "private_key": ""'),
            ('  "type": "service_account"', '  "private_key_id": "' + "0" * 32 + '"'),
        ):
            with self.subTest(fields=fields):
                self.assertEqual(secrets.scan_text("values.yaml", self.document(*fields)), [])

    def test_a_private_key_field_alone_is_not_a_service_account(self):
        text = self.document('  "private_key_id": "abc"')
        self.assertNotIn("SEC021", rule_ids(secrets.scan_text("other.json", text)))


if __name__ == "__main__":
    unittest.main()
