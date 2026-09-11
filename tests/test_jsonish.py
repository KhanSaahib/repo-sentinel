"""The JSON reader: the same nodes as YAML, with the line numbers kept."""

import unittest

from repo_sentinel import jsonish


class TestParsing(unittest.TestCase):
    def test_objects_and_arrays_become_the_same_nodes_as_yaml(self):
        document = jsonish.parse('{"a": {"b": [1, 2]}}')
        self.assertTrue(document.is_map)
        self.assertTrue(document.get("a", "b").is_list)
        self.assertEqual([entry.text for entry in document.get("a", "b").entries()], ["1", "2"])

    def test_every_value_keeps_the_line_it_was_on(self):
        document = jsonish.parse('{\n  "a": 1,\n  "b": {\n    "c": 2\n  }\n}')
        self.assertEqual(document.get("a").line, 2)
        self.assertEqual(document.get("b").line, 3)
        self.assertEqual(document.get("b", "c").line, 4)

    def test_scalars_keep_their_source_text(self):
        # "true" stays a string so that Node.truthy() means the same thing in
        # both readers, and a rule comparing ports does not care which produced
        # the number it is looking at.
        document = jsonish.parse('{"yes": true, "no": false, "n": 22, "nothing": null}')
        self.assertTrue(document.get("yes").truthy())
        self.assertTrue(document.get("no").falsy())
        self.assertEqual(document.get("n").text, "22")
        self.assertEqual(document.get("nothing").text, "null")

    def test_strings_are_decoded(self):
        document = jsonish.parse(r'{"a": "line\nbreak \"quoted\" é"}')
        self.assertEqual(document.get("a").text, 'line\nbreak "quoted" é')

    def test_an_escaped_quote_does_not_end_the_string(self):
        document = jsonish.parse(r'{"a": "ends with a backslash \\", "b": 2}')
        self.assertEqual(document.get("b").text, "2")

    def test_empty_containers(self):
        document = jsonish.parse('{"a": {}, "b": []}')
        self.assertEqual(dict(document.get("a").items()), {})
        self.assertEqual(list(document.get("b").entries()), [])

    def test_a_top_level_array(self):
        document = jsonish.parse('[\n  {"a": 1},\n  {"a": 2}\n]')
        self.assertEqual([entry.get("a").line for entry in document.entries()], [2, 3])


class TestRefusals(unittest.TestCase):
    """A partial parse is how a scanner reports findings that are not there."""

    def test_malformed_documents_return_nothing(self):
        for text in (
            '{"a": 1,}',            # a trailing comma
            '{"a": 1',              # unterminated
            '{"a": "unterminated}',
            "{'a': 1}",             # single quotes
            '{"a": 1} and then some',
            "",
            "not json at all",
        ):
            with self.subTest(text=text[:20]):
                self.assertIsNone(jsonish.parse(text))

    def test_comments_are_not_json(self):
        self.assertIsNone(jsonish.parse('{\n  // a comment\n  "a": 1\n}'))

    def test_looks_like_json_is_about_the_first_character(self):
        self.assertTrue(jsonish.looks_like_json('  {"a": 1}'))
        self.assertTrue(jsonish.looks_like_json("[1]"))
        self.assertFalse(jsonish.looks_like_json("a: 1\n"))
        self.assertFalse(jsonish.looks_like_json(""))

    def test_deeply_nested_documents_are_refused_by_a_rule(self):
        # Not by a RecursionError: that is raised wherever the stack happens to
        # be deep, including inside a tracer, where it does damage out of all
        # proportion to the malformed file that caused it. It cost this
        # project's coverage measurement fifteen points before it was noticed.
        self.assertIsNone(jsonish.parse("[" * 5000 + "]" * 5000))
        self.assertIsNone(jsonish.parse("[" * (jsonish.MAX_DEPTH + 2)))

    def test_ordinary_nesting_is_well_within_the_limit(self):
        document = jsonish.parse("[" * 50 + "1" + "]" * 50)
        self.assertIsNotNone(document)


class TestDocuments(unittest.TestCase):
    def test_a_document_comes_back_as_a_tuple_for_callers_that_loop(self):
        self.assertEqual(len(jsonish.parse_documents('{"a": 1}')), 1)
        self.assertEqual(jsonish.parse_documents("nonsense"), ())


if __name__ == "__main__":
    unittest.main()
