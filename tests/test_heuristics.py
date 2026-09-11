"""The judgement calls: entropy, placeholders, and secret-shaped names."""

import unittest

from repo_sentinel import heuristics


class TestEntropy(unittest.TestCase):
    def test_empty_string_has_no_entropy(self):
        self.assertEqual(heuristics.shannon_entropy(""), 0.0)

    def test_repeated_character_has_no_entropy(self):
        self.assertEqual(heuristics.shannon_entropy("aaaaaaaa"), 0.0)

    def test_english_prose_scores_below_a_generated_token(self):
        prose = heuristics.shannon_entropy("the quick brown fox")
        token = heuristics.shannon_entropy("aG9sZFRoZUxpbmVYeVo5")
        self.assertLess(prose, token)


class TestEntropyFloor(unittest.TestCase):
    """The floor has to move with the alphabet, or it is wrong twice over."""

    def test_alphabet_is_judged_nominally_not_by_observation(self):
        self.assertEqual(heuristics.alphabet_size("0123456789abcdef"), 16)
        self.assertEqual(heuristics.alphabet_size("Xk92mQp7Lz4TvB8n"), 62)
        self.assertEqual(heuristics.alphabet_size("0123456789"), 10)

    def test_hex_token_clears_its_own_floor(self):
        # A 16-character hex token cannot exceed 4.0 bits, so the old flat 3.2
        # bar left almost no room between a real token and a hand-typed one.
        token = "a3f5c9d1b7e20486"
        self.assertLess(heuristics.entropy_floor(token), 3.2)
        self.assertTrue(heuristics.looks_generated(token))

    def test_base64_blob_is_held_to_a_higher_floor_than_hex(self):
        self.assertGreater(
            heuristics.entropy_floor("aG9sZFRoZUxpbmVYeVo5cXc4bTJrN3A1" * 4),
            heuristics.entropy_floor("a3f5c9d1b7e20486"),
        )

    def test_floor_never_falls_below_the_absolute_minimum(self):
        self.assertGreaterEqual(heuristics.entropy_floor("abc"), heuristics.MIN_ENTROPY)


class TestLooksGenerated(unittest.TestCase):
    def test_accepts_a_random_token(self):
        self.assertTrue(heuristics.looks_generated("Xk92mQp7Lz4TvB8nRw1Y"))

    def test_rejects_a_short_value(self):
        self.assertFalse(heuristics.looks_generated("Xk92mQp7"))

    def test_rejects_placeholders(self):
        for value in (
            "your-password-here",
            "${DB_PASSWORD}",
            "$DATABASE_URL",
            "changeme-please",
            "xxxxxxxxxxxxxxxx",
            "<your-token-here>",
        ):
            with self.subTest(value=value):
                self.assertFalse(heuristics.looks_generated(value))

    def test_rejects_structure_that_is_not_a_credential(self):
        for value in (
            "/etc/ssl/private/server.pem",
            "https://api.internal.example/v1",
            "1.2.3-alpha.4",
            "2024-01-02T03:04:05Z",
            "com.example.service.auth",
            "[{ name = 'someone' }]",
            # Vocabulary, not entropy. Every one of these was a real false
            # positive from a run over the Python standard library, assigned
            # to a name like token_type or auth_header.
            "unstructured",
            "bare-quoted-string",
            "Proxy-Authorization",
            "obs-local-part",
            # A quoted type alias, which is what a module full of string
            # annotations assigns to names like Token and Block.
            "tuple[int, str, int]",
            "dict[str, Node]",
        ):
            with self.subTest(value=value):
                self.assertFalse(heuristics.looks_generated(value))

    def test_rejects_a_repeated_pair(self):
        self.assertFalse(heuristics.looks_generated("ababababababab"))


class TestSecretNames(unittest.TestCase):
    def test_recognises_credential_names(self):
        for name in ("api_key", "DB_PASSWORD", "clientSecret", "_authToken", "AUTHORIZATION"):
            with self.subTest(name=name):
                self.assertTrue(heuristics.is_secret_name(name))

    def test_does_not_read_authors_as_auth(self):
        # The bare substring "auth" appears in authors, authorized_keys and
        # authenticate, none of which hold a credential. This exact false
        # positive fired on this project's own pyproject.toml.
        for name in ("authors", "author", "authorized_keys", "authenticate"):
            with self.subTest(name=name):
                self.assertFalse(heuristics.is_secret_name(name))


if __name__ == "__main__":
    unittest.main()
