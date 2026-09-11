"""The YAML subset reader: structure, line numbers, and honest gaps."""

import unittest

from repo_sentinel import yamlish


def parse(text):
    return yamlish.parse_one(text)


class TestMappings(unittest.TestCase):
    def test_reads_nested_keys_with_their_lines(self):
        document = parse("apiVersion: v1\nmetadata:\n  name: web\n")
        self.assertEqual(document.get("apiVersion").text, "v1")
        self.assertEqual(document.get("metadata", "name").text, "web")
        self.assertEqual(document.get("metadata", "name").line, 3)

    def test_a_broken_path_is_none_rather_than_an_error(self):
        document = parse("a:\n  b: 1\n")
        self.assertIsNone(document.get("a", "missing"))
        self.assertIsNone(document.get("a", "b", "deeper"))

    def test_quoted_keys_keep_their_colons(self):
        document = parse('data:\n  "a.b:c": value\n')
        self.assertEqual(document.get("data", "a.b:c").text, "value")

    def test_comments_and_blank_lines_are_not_structure(self):
        document = parse("# header\n\na: 1  # trailing\n")
        self.assertEqual(list(document.items())[0][0], "a")


class TestSequences(unittest.TestCase):
    def test_items_under_a_key(self):
        document = parse("spec:\n  containers:\n    - name: a\n    - name: b\n")
        names = [entry.get("name").text for entry in document.get("spec", "containers").entries()]
        self.assertEqual(names, ["a", "b"])

    def test_items_at_the_same_indent_as_their_key(self):
        # Both styles are idiomatic YAML and both appear in real manifests.
        document = parse("volumes:\n- name: a\n- name: b\n")
        self.assertEqual(len(list(document.get("volumes").entries())), 2)

    def test_a_mapping_started_on_the_dash_line_keeps_its_siblings(self):
        document = parse("items:\n  - name: a\n    image: nginx\n")
        first = next(document.get("items").entries())
        self.assertEqual(first.get("image").text, "nginx")

    def test_scalar_items(self):
        document = parse("args:\n  - --verbose\n  - --quiet\n")
        self.assertEqual([item.text for item in document.get("args").entries()], ["--verbose", "--quiet"])


class TestScalarsAndGaps(unittest.TestCase):
    def test_block_scalars_do_not_leak_structure(self):
        document = parse('script: |\n  a: not a key\n  - not an item\nnext: 2\n')
        self.assertEqual(document.get("next").text, "2")
        self.assertEqual(sorted(dict(document.items())), ["next", "script"])

    def test_flow_collections_stay_as_text(self):
        # Unknown structure becomes a scalar, so a rule looking for nesting
        # finds none rather than finding something wrong.
        document = parse("args: [--a, --b]\n")
        self.assertFalse(document.get("args").is_list)
        self.assertEqual(document.get("args").text, "[--a, --b]")

    def test_booleans_in_their_several_spellings(self):
        document = parse("a: true\nb: 'yes'\nc: False\nd: off\ne: maybe\n")
        self.assertTrue(document.get("a").truthy())
        self.assertTrue(document.get("b").truthy())
        self.assertTrue(document.get("c").falsy())
        self.assertTrue(document.get("d").falsy())
        self.assertFalse(document.get("e").truthy())
        self.assertFalse(document.get("e").falsy())


class TestDocuments(unittest.TestCase):
    def test_a_stream_splits_into_documents(self):
        documents = yamlish.parse("kind: A\n---\nkind: B\n")
        self.assertEqual([document.get("kind").text for document in documents], ["A", "B"])

    def test_a_leading_break_does_not_create_an_empty_document(self):
        documents = yamlish.parse("---\nkind: A\n")
        self.assertEqual(len(documents), 1)

    def test_an_empty_stream_has_no_documents(self):
        self.assertEqual(yamlish.parse("\n# nothing\n"), [])


class TestWalk(unittest.TestCase):
    def test_reaches_every_node_with_the_key_it_sat_under(self):
        document = parse("spec:\n  containers:\n    - name: a\n      ports:\n        - 80\n")
        keys = [key for key, _ in document.walk()]
        self.assertIn("containers", keys)
        self.assertIn("ports", keys)
        self.assertIn("", keys)  # sequence elements


if __name__ == "__main__":
    unittest.main()
