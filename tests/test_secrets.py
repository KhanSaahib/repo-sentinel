import base64
import unittest

import fixtures
from bluerayscan.findings import Confidence, Severity, redact
from bluerayscan.scanners import secrets


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
        findings = secrets.scan_text("id_rsa", "-----BEGIN " + "OPENSSH PRIVATE KEY-----")
        self.assertIn("SEC004", rule_ids(findings))

    def test_live_and_test_stripe_keys_differ_in_severity(self):
        live = secrets.scan_text("a.py", 'k = "sk' + '_live_' + filler(20) + '"')[0]
        test = secrets.scan_text("a.py", 'k = "sk' + '_test_' + filler(20) + '"')[0]
        self.assertGreater(live.severity, test.severity)

    def test_reports_correct_line_number(self):
        text = "\n".join(
            ["import os", "", f'KEY = "{fixtures.REALISTIC_AWS_KEY_ID}"']
        )
        self.assertEqual(secrets.scan_text("a.py", text)[0].line, 3)


class TestInventedCredentials(unittest.TestCase):
    """A documented shape with made-up bytes in it is still made up."""

    def scan(self, value):
        return rule_ids(secrets.scan_text("app.py", f'k = "{value}"\n'))

    def test_a_repeated_character_is_nobody_key(self):
        self.assertEqual(self.scan("sk-" + "a" * 40), set())

    def test_a_counted_out_run_is_nobody_key(self):
        # Split, like every other well-formed shape in this suite: GitHub's
        # push protection reads a contiguous literal and is right to.
        self.assertEqual(self.scan("xox" + "b-8403192576-abcdefghijklmnop"), set())

    def test_a_word_somebody_typed_is_nobody_key(self):
        for value in (
            "sk-ant-api03-CHANGE_ME-0a1b0a1b0a1b",
            "sk-ant-api03-REPLACE_ME",
            "sk-proj-SET_ME-0a1b0a1b0a1b",
            "gh" + "p_PutYourTokenHere0a1b0a1b0a1b0a1b0a1b",
        ):
            with self.subTest(value=value):
                self.assertEqual(self.scan(value), set())

    def test_the_same_shape_with_generated_bytes_is_reported(self):
        self.assertIn("SEC001", self.scan("AKIA" + "ZZ7Q4TWFN2XKLM3D"))

    def test_opting_out_reports_the_invented_ones_too(self):
        # --no-example-allowlist is for auditing what the scanner chose not to
        # say, and this is one of the things it chose not to say.
        text = 'k = "' + "AKIA" + "AAAAAAAAAAAAAAAA" + '"\n'
        self.assertEqual(secrets.scan_text("app.py", text), [])
        loud = secrets.scan_text("app.py", text, allow_examples=False)
        self.assertIn("SEC001", rule_ids(loud))


class TestPrivateKeyBlocks(unittest.TestCase):
    """SEC004: a header is only a key when there is a key under it."""

    BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj" * 2

    def scan(self, line):
        return rule_ids(secrets.scan_text("a.ts", line + "\n"))

    def test_a_header_with_the_body_below_it_is_a_key(self):
        self.assertIn("SEC004", self.scan("-----BEGIN " + "PRIVATE KEY-----"))

    def test_a_one_line_block_with_real_material_is_a_key(self):
        line = f'key = "-----BEGIN PRIVATE KEY-----{self.BODY}-----END PRIVATE KEY-----"'
        self.assertIn("SEC004", self.scan(line))

    def test_a_one_line_block_with_a_placeholder_in_it_is_not(self):
        # What a test of a redactor looks like, and what a document explaining
        # the format looks like. n8n writes this forty-three times.
        line = "const pem = `-----BEGIN PRIVATE KEY-----\\n${FAKE}\\n-----END PRIVATE KEY-----`"
        self.assertNotIn("SEC004", self.scan(line))

    def test_a_block_built_by_concatenation_is_not_a_key_either(self):
        line = 'header + "-----BEGIN PRIVATE KEY-----" + key + "-----END PRIVATE KEY-----"'
        self.assertNotIn("SEC004", self.scan(line))


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
        text = 'api_key = "gh' + 'p_' + filler(36) + '"'
        self.assertEqual(rule_ids(secrets.scan_text("a.py", text)), {"SEC002"})


class TestIgnoreMarker(unittest.TestCase):
    def test_marker_suppresses_the_line(self):
        line = f'key = "{fixtures.REALISTIC_AWS_KEY_ID}"  # bluerayscan: ignore'
        self.assertEqual(secrets.scan_text("a.py", line), [])


class TestScanFiles(unittest.TestCase):
    def test_aggregates_across_files(self):
        findings = secrets.scan_files(
            [
                ("a.py", f'k = "{fixtures.REALISTIC_AWS_KEY_ID}"'),
                ("b.py", "nothing to see here"),
                ("c.py", "-----BEGIN " + "RSA PRIVATE KEY-----"),
            ]
        )
        self.assertEqual({finding.path for finding in findings}, {"a.py", "c.py"})


#: Filler that looks generated rather than typed. A repeated character or a
#: counted-out run ("aaaa...", "abcdefgh", "1234567890") is what somebody
#: invents, and the provider rules reject those on purpose -- so a fixture
#: written that way tests nothing.
_ALPHABET = "aB3dEf7hIj0kLm2nOp5qRs8tUv1wXy4z"


def filler(length):
    return (_ALPHABET * (length // len(_ALPHABET) + 1))[:length]


class TestAdditionalProviders(unittest.TestCase):
    """The rules added after the first ten, spot-checked one apiece."""

    def assert_rule(self, rule_id, line):
        self.assertIn(rule_id, rule_ids(secrets.scan_text("config.py", line)))

    def test_azure_storage_key(self):
        self.assert_rule("SEC011", "AccountKey=" + "aB3dEf7h" * 10 + "aB3dEf" + "==")

    def test_google_oauth_client_secret(self):
        self.assert_rule("SEC012", 'secret = "GOC' + "SPX-" + filler(28) + '"')

    def test_sendgrid_key(self):
        self.assert_rule("SEC013", 'k = "S' + "G." + filler(22) + "." + filler(43) + '"')

    def test_npm_token(self):
        self.assert_rule("SEC015", "//registry.npmjs.org/:_authToken=np" + "m_" + filler(36))

    def test_pypi_token(self):
        self.assert_rule("SEC016", "password = pyp" + "i-AgEIcHlwaS5vcmc" + filler(60))

    def test_docker_hub_token(self):
        self.assert_rule("SEC017", 'token = "dck' + "r_pat_" + filler(24) + '"')

    def test_slack_webhook_url(self):
        self.assert_rule("SEC018", "https://hooks.sl" + "ack.com/services/T" + filler(32))

    def test_huggingface_token(self):
        self.assert_rule("SEC019", 'HF = "h' + "f_" + filler(34) + '"')

    def test_the_provider_rules_added_for_the_tokens_people_actually_leak(self):
        # One apiece: the shapes are documented, so the test is that the
        # pattern was transcribed correctly rather than that it is clever.
        for rule_id, value in (
            ("SEC023", "glp" + "at-" + "a1B2c3D4e5F6g7H8i9J0"),
            ("SEC024", "glr" + "t-" + "a1B2c3D4e5F6g7H8i9J0"),
            ("SEC025", "dop" + "_v1_" + "0a1b" * 16),
            ("SEC026", "shp" + "at_" + "0a1b" * 8),
            ("SEC027", "dap" + "i" + "0a1b" * 8),
            ("SEC028", "dp" + ".pt." + "aB3dEf7hIj0kLm2nOp5qRs8tUv1wXy4zaB3dEf7h"),
            ("SEC029", "gls" + "a_" + "aB3dEf7hIj0kLm2nOp5qRs8tUv1wXy4z_1a2b3c4d"),
            ("SEC030", "8403192576" + ":AA" + "aB3dEf7hIj0kLm2nOp5qRs8tUv1wXy4zQ"),
            ("SEC031", "PMA" + "K-" + "0a1b" * 6 + "-" + "0a1b" * 8 + "aa"),
            ("SEC032", "lin" + "_api_" + "aB3dEf7hIj0kLm2nOp5qRs8tUv1wXy4zaB3dEf7h"),
            ("SEC033", "ATA" + "TT3x" + "aB3dEf7h" * 13),
            ("SEC034", "sq0" + "atp-" + "aB3dEf7hIj0kLm2nOp5qRs"),
        ):
            with self.subTest(rule=rule_id):
                self.assertIn(rule_id, rule_ids(secrets.scan_text("app.py", f'k = "{value}"')))

    def test_the_second_batch_of_provider_rules(self):
        for rule_id, value in (
            ("SEC035", "xap" + "p-1-A01B02C03-8403192576-" + "0a1b" * 8),
            ("SEC036", "M" + "TA1B2c3D4e5F6g7H8i9J0k1L" + ".Ab3dEf." + "aB3dEf7hIj0kLm2nOp5qRs8tUv1"),
            ("SEC037", "key" + "-" + "0a1b" * 8),
            ("SEC038", "0a1b" * 8 + "-us21"),
            ("SEC039", "NRA" + "K-" + "ZQMXDPLBKWRTFHNCVGJSYAE" + "3X70"),
            ("SEC040", "https://" + "0a1b" * 8 + "@o314.ingest.example.invalid/592"),
            ("SEC041", "1/" + "8403192576418302" + ":" + "0a1b" * 8),
            ("SEC042", "sl" + "." + "aB3dEf7h" * 17),
            ("SEC043", "fig" + "d_" + "aB3dEf7hIj0kLm2nOp5qRs8tUv1wXy4zaB3dEf7h"),
            ("SEC044", "pat" + "aB3dEf7hIj0kLm" + "." + "0a1b" * 16),
            ("SEC045", "AKC" + "p8" + "aB3dEf7h" * 8),
            ("SEC046", "aB3dEf7hIj0kLm" + ".atlasv1." + "aB3dEf7h" * 6),
            ("SEC047", "AAA" + "A" + "aB3dEf7" + ":APA91b" + "aB3dEf7h" * 17),
        ):
            with self.subTest(rule=rule_id):
                self.assertIn(rule_id, rule_ids(secrets.scan_text("app.py", f'k = "{value}"')))

    def test_the_tokens_a_repository_written_this_year_leaks(self):
        for rule_id, value in (
            ("SEC048", "hv" + "s." + filler(40)),
            ("SEC049", "sb" + "p_" + filler(40)),
            ("SEC050", "pscale" + "_tkn_" + filler(34)),
            ("SEC051", "tsk" + "ey-auth-" + filler(12) + "-" + filler(22)),
            ("SEC052", "sntry" + "s_" + filler(48)),
            ("SEC053", "gs" + "k_" + filler(52)),
            ("SEC054", "r" + "8_" + filler(40)),
        ):
            with self.subTest(rule=rule_id):
                self.assertIn(rule_id, rule_ids(secrets.scan_text("app.py", f'k = "{value}"')))

    def test_the_new_prefixes_alone_are_not_tokens(self):
        for prefix in ("hvs.", "sbp_", "pscale_tkn_", "tskey-auth-", "sntrys_", "gsk_", "r8_"):
            with self.subTest(prefix=prefix):
                self.assertEqual(secrets.scan_text("app.py", f'k = "{prefix}"'), [])

    def test_the_new_patterns_do_not_fire_on_their_own_prefixes(self):
        # "glpat-" and friends turn up in documentation about tokens far more
        # often than actual tokens do.
        for value in (
            "glpat-", "dop_v1_", "dapi", "PMAK-xxxx", "lin_api_short",
            "xapp-", "figd_", "key-", "AKCp8", "sl.",
        ):
            with self.subTest(value=value):
                self.assertEqual(secrets.scan_text("docs/tokens.md", f'k = "{value}"'), [])

    def test_a_loose_shape_is_reported_at_lower_confidence(self):
        findings = secrets.scan_text("t.py", 'sid = "S' + "K" + "0a1b" * 8 + '"')
        twilio = next(f for f in findings if f.rule_id == "SEC014")
        self.assertEqual(twilio.confidence, Confidence.MEDIUM)


class TestTemplateFiles(unittest.TestCase):
    """A file whose name says "template" is documentation with an extension."""

    LINE = "API_TOKEN=Qq7Zx9Lm2Pv4Rt8WcY6h"

    def test_an_example_file_is_weighed_like_prose(self):
        real = secrets.scan_text(".env", self.LINE)[0]
        template = secrets.scan_text(".env.example", self.LINE)[0]
        self.assertLess(template.confidence, real.confidence)

    def test_both_conventions_for_saying_so(self):
        for path in (
            ".env.example", "config.sample.yml", "values.template.yaml", "app.conf.dist",
        ):
            with self.subTest(path=path):
                findings = secrets.scan_text(path, self.LINE)
                self.assertEqual(findings[0].confidence, Confidence.LOW)

    def test_a_template_is_read_as_the_format_it_will_become(self):
        # "app.conf.dist" is a .conf file somebody is meant to copy, and the
        # value-position rules only apply to formats they know.
        from bluerayscan.scanners.secrets import has_value_positions

        for path in ("app.conf.dist", "settings.ini.template", ".env.example"):
            with self.subTest(path=path):
                self.assertTrue(has_value_positions(path))
        self.assertFalse(has_value_positions("notes.md"))

    def test_it_is_weakened_rather_than_silenced(self):
        # A real key does get left in the file people copy.
        self.assertIn("SEC101", rule_ids(secrets.scan_text(".env.example", self.LINE)))


class TestValuesWrittenBeneathTheirName(unittest.TestCase):
    """YAML puts a long value on the lines under its key. Both halves matter."""

    def scan(self, text, path="config.yaml"):
        return secrets.scan_text(path, text)

    def test_a_block_scalar_holds_its_value(self):
        for marker in ("|", ">", ""):
            with self.subTest(marker=marker):
                text = f"data:\n  api_key: {marker}\n    Xk92mQp7Lz4TvB8nRw1Y\n"
                findings = [f for f in self.scan(text) if f.rule_id == "SEC101"]
                self.assertEqual(len(findings), 1)
                self.assertIn("api_key", findings[0].title)

    def test_a_value_wrapped_over_several_lines_is_rejoined(self):
        text = (
            "client_secret: |\n"
            "  Xk92mQp7Lz4TvB8n\n"
            "  Rw1YQq7Zx9Lm2Pv4\n"
            "  Rt8WcY6hTv8nRw1Y\n"
        )
        findings = [f for f in self.scan(text) if f.rule_id == "SEC101"]
        self.assertEqual(len(findings), 1)

    def test_the_finding_sits_where_a_marker_can_go(self):
        # Inside a block scalar a "#" is part of the value, so the key's line
        # is the only line a suppression marker can live on.
        text = "api_key: |\n  Xk92mQp7Lz4TvB8nRw1Y\n"
        finding = next(f for f in self.scan(text) if f.rule_id == "SEC101")
        self.assertEqual(finding.line, 1)

    def test_a_name_that_promises_nothing_is_not_read(self):
        text = "description: |\n  Xk92mQp7Lz4TvB8nRw1Y\n"
        self.assertEqual(self.scan(text), [])

    def test_a_nested_mapping_is_not_a_value(self):
        # A CRD property: "automountServiceAccountToken:" with "type: boolean"
        # under it. The Grafana operator has hundreds.
        text = (
            "properties:\n"
            "  automountServiceAccountToken:\n"
            "    type: boolean\n"
            "    description: whether to mount it\n"
        )
        self.assertEqual(self.scan(text), [])

    def test_a_paragraph_under_a_credential_name_is_not_one(self):
        # Discourse's locale files: api_key followed by a translated sentence.
        text = "api_key: |\n  Revoke the key and issue another one from settings\n"
        self.assertEqual(self.scan(text), [])

    def test_a_list_of_names_and_paths_is_not_a_value(self):
        # The Grafana operator's release workflow hands vault paths this way.
        text = (
            "with:\n  repo_secrets: |\n"
            "    QUAY_USERNAME=quay-io:username\n"
            "    QUAY_PASSWORD=quay-io:token\n"
        )
        self.assertEqual(self.scan(text), [])

    def test_a_private_key_body_is_left_to_the_rule_that_has_the_header(self):
        text = (
            "private_key: |\n"
            "  -----BEGIN " + "PRIVATE KEY-----\n"
            "  MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n"
            "  -----END " + "PRIVATE KEY-----\n"
        )
        self.assertEqual({f.rule_id for f in self.scan(text)}, {"SEC004"})

    def test_a_block_too_long_to_be_one_value(self):
        body = "".join(f"  Xk92mQp7Lz4TvB8nRw1Y{index}\n" for index in range(20))
        self.assertEqual(self.scan("api_key: |\n" + body), [])

    def test_a_format_that_does_not_write_values_this_way(self):
        text = "api_key: |\n  Xk92mQp7Lz4TvB8nRw1Y\n"
        self.assertEqual(secrets.scan_text("notes.md", text), [])

    def test_a_marker_on_the_key_silences_it(self):
        text = "api_key: |  # repo-sentinel: ignore\n  Xk92mQp7Lz4TvB8nRw1Y\n"
        self.assertEqual(self.scan(text), [])


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


class TestDocumentation(unittest.TestCase):
    """Prose is where credentials are examples, because that is what it is for."""

    LINE = 'api_key = "Qq7Zx9Lm2Pv4Rt8WcY6h"'

    def test_a_guess_in_documentation_is_reported_at_lower_confidence(self):
        for path in ("README.md", "docs/install.md", "documentation/guide.rst"):
            with self.subTest(path=path):
                self.assertEqual(
                    secrets.scan_text(path, self.LINE)[0].confidence, Confidence.LOW
                )

    def test_source_keeps_its_confidence(self):
        self.assertEqual(
            secrets.scan_text("app/config.py", self.LINE)[0].confidence, Confidence.MEDIUM
        )

    def test_a_key_in_a_readme_is_reported_but_believed_less(self):
        # Grafana's manual contains two dozen service account tokens and none
        # of them is real. A live key does get pasted into a README, so the
        # finding stays and keeps its severity; it is --min-confidence high
        # that stops hearing about it.
        finding = secrets.scan_text("README.md", f'k = "{fixtures.REALISTIC_AWS_KEY_ID}"')[0]
        self.assertEqual(finding.confidence, Confidence.MEDIUM)
        self.assertEqual(finding.severity, Severity.CRITICAL)

    def test_a_documented_shape_in_a_fixture_tree_keeps_its_confidence(self):
        # Different mistake, different weighing: the classic way a real key
        # reaches a repository is a test that once talked to a real service.
        finding = secrets.scan_text(
            "tests/fixtures/creds.py", f'k = "{fixtures.REALISTIC_AWS_KEY_ID}"'
        )[0]
        self.assertEqual(finding.confidence, Confidence.HIGH)


class TestUrlCredentials(unittest.TestCase):
    def test_reports_a_password_in_a_connection_string(self):
        dsn = "postgres://svc:" + "Xk92mQp7" + "Lz4TvB8n" + "@db.internal:5432/app"
        findings = secrets.scan_text("db.py", f'DSN = "{dsn}"')
        self.assertIn("SEC020", rule_ids(findings))

    def test_keeps_the_host_but_redacts_the_password(self):
        dsn = "postgres://svc:" + "Xk92mQp7" + "Lz4TvB8n" + "@db.internal:5432/app"
        findings = secrets.scan_text("db.py", f'DSN = "{dsn}"')
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

    def test_a_fat_arrow_is_not_an_assignment_this_rule_reads(self):
        # From ansible/ansible: lib/ansible/plugins/filter/password_hash.yml
        # documents its own filter with "# pwdhash => \"$2b$12$...\"", and that
        # is a bcrypt hash -- filtered since the beginning. Reading "=>" as an
        # assignment did not merely add a finding: the ">" became the first
        # character of the value, so the modular-crypt pattern, which begins
        # "^\$", stopped matching. Every filter anchored at the start of a
        # value had the same hole.
        hash_line = '    # pwdhash => "$2b$12$' + "ujYVRD9v9z87lpvLqeWNuOFDI4QzSSYHoRyYydW6XK4.kgqfwOXzO" + '"'
        self.assertEqual(secrets.scan_text("filter.yml", hash_line), [])

    def test_a_credential_behind_a_fat_arrow_is_still_found(self):
        # Ruby and PHP write a hash literal this way, and a credential does
        # land there. It is the provider rules' to find, which read a shape
        # wherever it appears rather than an assignment.
        line = "  'api_key' => '" + fixtures.REALISTIC_AWS_KEY_ID + "',"
        self.assertIn("SEC001", rule_ids(secrets.scan_text("config.rb", line)))

    def test_a_value_may_not_begin_with_an_operator(self):
        for line in ("token == Tv8nRw1YXk92mQp7Lz4T", "token => Tv8nRw1YXk92mQp7Lz4T"):
            with self.subTest(line=line):
                self.assertEqual(secrets.scan_text(".env", line), [])

    def test_ignores_an_interpolated_reference(self):
        self.assertEqual(secrets.scan_text(".env", "API_TOKEN=${API_TOKEN}"), [])

    def test_a_line_with_no_credential_word_is_not_examined(self):
        # The gate in front of the assignment patterns. A line that mentions
        # none of the words the rules require cannot produce a finding, and
        # this is what makes a source tree finish.
        text = 'greeting = "Xk92mQp7Lz4TvB8nRw1Y"\n'
        self.assertEqual(secrets.scan_text("app.py", text), [])

    def test_the_gate_lets_through_every_word_the_rules_need(self):
        for name in (
            "passwd", "password", "secret", "token", "api_key", "apikey",
            "access_key", "private_key", "credential", "auth_token", "bearer",
        ):
            with self.subTest(name=name):
                text = f'{name} = "Xk92mQp7Lz4TvB8nRw1Y"\n'
                self.assertIn("SEC100", rule_ids(secrets.scan_text("app.py", text)))

    def test_an_escaped_quote_does_not_end_the_string(self):
        # Without this the sentence is cut at the backslash and the half that
        # survives is measured as a credential.
        text = 'password_too_long: "Devi disattivare \\"tokenize\\" prima di attivare."\n'
        self.assertEqual(secrets.scan_text("server.it.yml", text), [])

    def test_a_shell_continuation_is_not_part_of_the_value(self):
        # A run: block in a workflow is full of these, and the backslash
        # attached to the value defeats every filter that asks its shape.
        text = "jobs:\n  b:\n    steps:\n      - run: |\n          tool \\\n"
        text += "            --github-token=env:GITHUB_TOKEN \\\n"
        self.assertEqual(secrets.scan_text(".github/workflows/a.yml", text), [])

    def test_the_continuation_strip_does_not_lose_a_real_value(self):
        text = "DATABASE_PASSWORD=Tv8nRw1YXk92mQp7Lz4T \\\n"
        findings = secrets.scan_text(".env", text)
        self.assertIn("SEC101", rule_ids(findings))
        self.assertNotIn("\\", findings[0].evidence)

    def test_a_systemd_unit_is_a_value_position_format(self):
        unit = (
            "[Service]\nUser=app\n"
            "Environment=DB_PASSWORD=Tv8nRw1YXk92mQp7Lz4T\n"
            "ExecStart=/usr/bin/app\n"
        )
        findings = secrets.scan_text("deploy/app.service", unit)
        self.assertIn("SEC101", rule_ids(findings))
        self.assertIn("DB_PASSWORD", findings[0].title)

    def test_a_quoted_systemd_environment_line(self):
        unit = '[Service]\nEnvironment="API_TOKEN=Qq7Zx9Lm2Pv4Rt8WcY6h"\n'
        self.assertIn("SEC101", rule_ids(secrets.scan_text("app.service", unit)))

    def test_an_ordinary_unit_setting_says_nothing(self):
        unit = "[Service]\nUser=app\nExecStart=/usr/bin/app --port 8080\nRestart=always\n"
        self.assertEqual(secrets.scan_text("app.service", unit), [])

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
            '  "type": "service' + '_account"',
            '  "project_id": "x"',
            '  "private_key_id": "a3f5c9d1b7e204863f2a"',
        )
        findings = secrets.scan_text("sa.json", text)
        self.assertIn("SEC021", rule_ids(findings))
        self.assertEqual(next(f for f in findings if f.rule_id == "SEC021").line, 2)

    def test_the_type_alone_is_not_a_credential(self):
        text = self.document(
            '  "type": "service' + '_account"', '  "client_email": "a@b.com"'
        )
        self.assertEqual(secrets.scan_text("sa.json", text), [])

    def test_a_template_service_account_is_not_a_leak(self):
        # Charts ship these to document the shape. The key field is there and
        # empty, or filled with zeroes, which is the opposite of a credential.
        account = '  "type": "service' + '_account"'
        for fields in (
            (account, '  "private_key": ""'),
            (account, '  "private_key_id": "' + "0" * 32 + '"'),
        ):
            with self.subTest(fields=fields):
                self.assertEqual(secrets.scan_text("values.yaml", self.document(*fields)), [])

    def test_a_private_key_field_alone_is_not_a_service_account(self):
        text = self.document('  "private_key_id": "abc"')
        self.assertNotIn("SEC021", rule_ids(secrets.scan_text("other.json", text)))


if __name__ == "__main__":
    unittest.main()
