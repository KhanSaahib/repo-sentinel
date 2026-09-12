import math
import random
import unittest

from repo_sentinel import entropy

HEX_ALPHABET = "0123456789abcdef"
BASE64_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)


class TestShannonEntropy(unittest.TestCase):
    def test_empty_string_has_no_entropy(self):
        self.assertEqual(entropy.shannon_entropy(""), 0.0)

    def test_repeated_character_has_no_entropy(self):
        self.assertEqual(entropy.shannon_entropy("aaaaaaaa"), 0.0)

    def test_uniform_alphabet_reaches_its_ceiling(self):
        self.assertAlmostEqual(entropy.shannon_entropy("abcdefgh"), 3.0)


class TestClassify(unittest.TestCase):
    def test_single_case_hex_is_hex(self):
        self.assertIs(entropy.classify("d66dfa006466f04f"), entropy.HEX)
        self.assertIs(entropy.classify("D66DFA006466F04F"), entropy.HEX)

    def test_mixed_case_hex_is_not_hex(self):
        # Generators emit one case or the other. A value mixing them is drawing
        # from a wider alphabet than sixteen symbols and should be judged as one.
        self.assertIsNot(entropy.classify("d66DFa006466f04F"), entropy.HEX)

    def test_mixed_case_alphanumeric_is_base64(self):
        self.assertIs(entropy.classify("Xk92mQp7Lz4TvB8nRw1Y"), entropy.BASE64)

    def test_single_class_word_is_not_base64(self):
        # Uses nothing outside the base64url alphabet, but it is a phrase.
        self.assertIs(entropy.classify("staging-deploy-token"), entropy.MIXED)

    def test_punctuation_falls_through_to_mixed(self):
        self.assertIs(entropy.classify("/var/run/secrets/app"), entropy.MIXED)


class TestEntropyFloor(unittest.TestCase):
    def test_too_short_to_judge_is_unreachable(self):
        self.assertEqual(entropy.entropy_floor("abc"), math.inf)
        self.assertFalse(entropy.is_high_entropy("abc"))

    def test_hex_floor_sits_below_the_old_flat_floor(self):
        self.assertLess(entropy.entropy_floor("d" * 8 + "e" * 8), 3.2)

    def test_base64_floor_sits_above_the_old_flat_floor(self):
        self.assertGreater(entropy.entropy_floor("Xk92mQp7Lz4TvB8nRw1Y"), 3.2)

    def test_floor_never_exceeds_what_the_length_allows(self):
        # A value of length L cannot score above log2(L) however random it is,
        # so a floor above that ceiling would reject every possible value.
        for length in range(entropy.MIN_JUDGEABLE_LENGTH, 80):
            for alphabet in (HEX_ALPHABET, BASE64_ALPHABET, "aB3/+_=-."):
                value = (alphabet * length)[:length]
                with self.subTest(length=length, alphabet=alphabet[:4]):
                    self.assertLess(
                        entropy.entropy_floor(value), math.log2(length)
                    )

    def test_floor_rises_with_length_within_a_profile(self):
        short = entropy.entropy_floor("Xk92mQp7Lz4T")
        long = entropy.entropy_floor("Xk92mQp7Lz4TvB8nRw1YcE5jH6kD2fA3")
        self.assertGreater(long, short)


class TestCalibration(unittest.TestCase):
    """The ratios are only defensible if random draws actually clear them."""

    def _pass_rate(self, alphabet, length, trials=2000):
        rng = random.Random(20260912)
        passed = 0
        for _ in range(trials):
            value = "".join(rng.choice(alphabet) for _ in range(length))
            if entropy.is_high_entropy(value):
                passed += 1
        return passed / trials

    def test_random_hex_tokens_almost_always_clear_their_floor(self):
        for length in (12, 16, 32, 64):
            with self.subTest(length=length):
                self.assertGreater(self._pass_rate(HEX_ALPHABET, length), 0.95)

    def test_random_base64_tokens_almost_always_clear_their_floor(self):
        for length in (12, 16, 32, 64):
            with self.subTest(length=length):
                self.assertGreater(self._pass_rate(BASE64_ALPHABET, length), 0.95)

    def test_english_prose_does_not_clear_its_floor(self):
        for text in (
            "the quick brown fox jumps over the lazy dog",
            "correct horse battery staple",
            "please remember to rotate this before release",
        ):
            with self.subTest(text=text):
                self.assertFalse(entropy.is_high_entropy(text))


if __name__ == "__main__":
    unittest.main()
