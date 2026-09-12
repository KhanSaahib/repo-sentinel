"""The YAML subset reader: structure, line numbers, and honest gaps."""

import unittest

from bluerayscan import yamlish


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


class TestComments(unittest.TestCase):
    def test_a_trailing_comment_is_not_part_of_the_value(self):
        self.assertEqual(parse("a: true  # repo-sentinel: ignore\n").get("a").text, "true")
        self.assertEqual(parse("a: nginx # pin me\n").get("a").text, "nginx")

    def test_a_hash_inside_quotes_stays(self):
        self.assertEqual(parse('a: "x # y"\n').get("a").text, '"x # y"')

    def test_a_hash_with_no_space_before_it_is_not_a_comment(self):
        # YAML starts a comment at a "#" that follows whitespace, and nowhere
        # else, which is what keeps a URL fragment intact.
        self.assertEqual(parse("a: http://h/#frag\n").get("a").text, "http://h/#frag")

    def test_sequence_items_are_stripped_too(self):
        document = parse("args:\n  - --verbose  # why\n")
        self.assertEqual(next(document.get("args").entries()).text, "--verbose")


class TestColonRule(unittest.TestCase):
    """A colon only opens a mapping when whitespace follows it."""

    def test_a_port_mapping_stays_a_scalar(self):
        document = parse('ports:\n  - "5432:5432"\n')
        entries = list(document.get("ports").entries())
        self.assertEqual(entries[0].text, '"5432:5432"')

    def test_a_bind_mount_stays_a_scalar(self):
        document = parse("volumes:\n  - /var/run/docker.sock:/srv\n")
        entries = list(document.get("volumes").entries())
        self.assertEqual(entries[0].text, "/var/run/docker.sock:/srv")

    def test_an_image_reference_keeps_its_tag(self):
        self.assertEqual(parse("image: nginx:1.25\n").get("image").text, "nginx:1.25")

    def test_a_real_key_still_opens_a_mapping(self):
        document = parse("items:\n  - name: a\n")
        self.assertEqual(next(document.get("items").entries()).get("name").text, "a")


class TestDocuments(unittest.TestCase):
    def test_a_stream_splits_into_documents(self):
        documents = yamlish.parse("kind: A\n---\nkind: B\n")
        self.assertEqual([document.get("kind").text for document in documents], ["A", "B"])

    def test_a_leading_break_does_not_create_an_empty_document(self):
        documents = yamlish.parse("---\nkind: A\n")
        self.assertEqual(len(documents), 1)

    def test_an_empty_stream_has_no_documents(self):
        self.assertEqual(yamlish.parse("\n# nothing\n"), [])


class TestTemplates(unittest.TestCase):
    def test_expressions_become_a_placeholder(self):
        stripped = yamlish.strip_templates("image: {{ .Values.image }}\n")
        self.assertEqual(stripped.strip(), f"image: {yamlish.TEMPLATE_PLACEHOLDER}")

    def test_control_lines_become_blank_and_keep_their_place(self):
        text = "a: 1\n{{- if .Values.x }}\nb: 2\n{{- end }}\nc: 3\n"
        stripped = yamlish.strip_templates(text)
        self.assertEqual(len(stripped.splitlines()), 5)
        document = yamlish.parse_one(stripped)
        self.assertEqual(document.get("c").line, 5)

    def test_an_untemplated_document_is_recognised_as_such(self):
        self.assertFalse(yamlish.is_templated("a: 1\n"))
        self.assertTrue(yamlish.is_templated("a: {{ .x }}\n"))


class TestWalk(unittest.TestCase):
    def test_reaches_every_node_with_the_key_it_sat_under(self):
        document = parse("spec:\n  containers:\n    - name: a\n      ports:\n        - 80\n")
        keys = [key for key, _ in document.walk()]
        self.assertIn("containers", keys)
        self.assertIn("ports", keys)
        self.assertIn("", keys)  # sequence elements


if __name__ == "__main__":
    unittest.main()
