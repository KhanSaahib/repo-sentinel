import base64
import json
import unittest

import fixtures
from repo_sentinel.scanners import allowlist, secrets


def jwt(header, payload, signature="c2lnbmF0dXJl"):
    """Build a JWT with the given claim dicts. The signature is never checked."""

    def encode(obj):
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{encode(header)}.{encode(payload)}.{signature}"


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


class TestExactValues(unittest.TestCase):
    def test_documented_aws_key_id_is_an_example(self):
        self.assertTrue(allowlist.is_known_example("AKIAIOSFODNN7EXAMPLE"))

    def test_documented_aws_secret_is_an_example(self):
        self.assertTrue(
            allowlist.is_known_example("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        )

    def test_surrounding_whitespace_does_not_defeat_the_match(self):
        self.assertTrue(allowlist.is_known_example("  AKIAIOSFODNN7EXAMPLE\t"))

    def test_empty_value_is_not_an_example(self):
        self.assertFalse(allowlist.is_known_example(""))
        self.assertFalse(allowlist.is_known_example("   "))


class TestVendorConventions(unittest.TestCase):
    def test_any_aws_id_ending_in_example_is_documentation(self):
        # Not in the exact list; AWS reserves the suffix, so the shape suffices.
        self.assertTrue(allowlist.is_known_example("AKIAZZZZZZZZZEXAMPLE"))
        self.assertTrue(allowlist.is_known_example("ASIAQQQQQQQQQEXAMPLE"))

    def test_a_real_looking_aws_id_is_not_allowlisted(self):
        self.assertFalse(allowlist.is_known_example(fixtures.REALISTIC_AWS_KEY_ID))

    def test_example_suffix_alone_is_not_enough(self):
        # Right suffix, wrong length: this is not an AWS identifier at all.
        self.assertFalse(allowlist.is_known_example("AKIAEXAMPLE"))
        self.assertFalse(allowlist.is_known_example("TOTALLYNOTAKEYEXAMPLE"))


class TestReservedDomainJwts(unittest.TestCase):
    def test_claim_naming_a_reserved_domain_is_documentation(self):
        # The shape RFC 7519's own examples use.
        token = jwt(
            {"typ": "JWT", "alg": "HS256"},
            {"iss": "joe", "exp": 1300819380, "http://example.com/is_root": True},
        )
        self.assertTrue(allowlist.is_known_example(token))

    def test_reserved_domain_in_the_header_also_counts(self):
        token = jwt({"alg": "HS256", "jku": "https://example.org/keys"}, {"sub": "1"})
        self.assertTrue(allowlist.is_known_example(token))

    def test_the_actual_rfc_7519_sample_token(self):
        # Deliberately not in EXAMPLE_CREDENTIALS: this proves the
        # reserved-domain rule generalises to the RFC samples nobody has
        # enumerated by hand.
        token = fixtures.RFC_7519_SAMPLE_JWT
        self.assertTrue(allowlist.is_known_example(token))
        self.assertEqual(secrets.scan_text("docs/jwt.md", token), [])

    def test_a_real_issuer_is_not_allowlisted(self):
        token = jwt({"alg": "HS256", "typ": "JWT"}, {"iss": "https://auth.acme.io"})
        self.assertFalse(allowlist.is_known_example(token))

    def test_malformed_token_is_reported_rather_than_allowlisted(self):
        # Undecodable segments must not be read as "no evidence, so allow".
        self.assertFalse(allowlist.is_known_example("eyJ!!!.eyJ!!!.sig"))
        self.assertFalse(allowlist.is_known_example("eyJhbGciOiJIUzI1NiJ9.only-two"))

    def test_jwt_is_documentation_requires_three_segments(self):
        self.assertFalse(allowlist.jwt_is_documentation("eyJhbGciOiJIUzI1NiJ9"))


class TestScannerIntegration(unittest.TestCase):
    def test_documentation_aws_key_is_not_reported(self):
        findings = secrets.scan_text("README.md", 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"')
        self.assertEqual(findings, [])

    def test_suppressed_example_does_not_resurface_as_entropy(self):
        # Regression: the provider rule stays quiet, but SEC100 must not pick
        # the same string up again just because it looks random.
        findings = secrets.scan_text("docs.md", 'secret_key = "AKIAIOSFODNN7EXAMPLE"')
        self.assertNotIn("SEC100", rule_ids(findings))

    def test_documentation_aws_secret_is_not_reported(self):
        text = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        self.assertEqual(secrets.scan_text("README.md", text), [])

    def test_a_real_looking_key_beside_an_example_is_still_reported(self):
        text = f'a = "{fixtures.EXAMPLE_AWS_KEY_ID}"  b = "{fixtures.REALISTIC_AWS_KEY_ID}"'
        findings = secrets.scan_text("a.py", text)
        self.assertEqual(len(findings), 1)
        self.assertIn("SEC001", rule_ids(findings))

    def test_opting_out_reports_the_example_again(self):
        findings = secrets.scan_text(
            "README.md", 'key = "AKIAIOSFODNN7EXAMPLE"', allow_examples=False
        )
        self.assertIn("SEC001", rule_ids(findings))


if __name__ == "__main__":
    unittest.main()
