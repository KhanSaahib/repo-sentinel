import unittest

import fixtures
from repo_sentinel.findings import Severity, redact
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


class TestEntropy(unittest.TestCase):
    def test_empty_string_has_no_entropy(self):
        self.assertEqual(secrets.shannon_entropy(""), 0.0)

    def test_repeated_character_has_no_entropy(self):
        self.assertEqual(secrets.shannon_entropy("aaaaaaaa"), 0.0)

    def test_random_string_scores_above_the_floor(self):
        value = "Xk92mQp7Lz4TvB8nRw1Y"
        self.assertGreater(
            secrets.shannon_entropy(value), secrets.entropy_floor(value)
        )

    def test_english_prose_scores_below_a_generated_token(self):
        prose = secrets.shannon_entropy("the quick brown fox")
        token = secrets.shannon_entropy("aG9sZFRoZUxpbmVYeVo5")
        self.assertLess(prose, token)


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

    def test_flags_a_short_hex_token_the_flat_floor_missed(self):
        # The regression the per-class floor exists for: hex cannot exceed 4
        # bits per character, so a flat 3.2-bit floor rejected around half of
        # all genuine hex tokens.
        token = fixtures.UNEVEN_HEX_TOKEN
        self.assertLess(secrets.shannon_entropy(token), 3.2)
        findings = secrets.scan_text("settings.py", f'API_KEY = "{token}"')
        self.assertIn("SEC100", rule_ids(findings))

    def test_ignores_structured_text_the_flat_floor_admitted(self):
        # The other half of the regression: these all score above 3.2, and a
        # base64-shaped alphabet is the only reason they ever looked random.
        for value in (
            "staging-deploy-token-value",
            "database_connection_password",
            "/var/run/secrets/app/token",
            "2026-09-12T14:32:07.512Z",
            "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
        ):
            with self.subTest(value=value):
                self.assertGreater(secrets.shannon_entropy(value), 3.2)
                findings = secrets.scan_text("cfg.yaml", f'secret_value = "{value}"')
                self.assertNotIn("SEC100", rule_ids(findings), value)

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


if __name__ == "__main__":
    unittest.main()
