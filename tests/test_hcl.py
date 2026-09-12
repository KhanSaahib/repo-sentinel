"""The block reader: structure without a grammar."""

import unittest

from repo_sentinel import hcl


class TestStripping(unittest.TestCase):
    def test_comments_go_but_strings_stay(self):
        self.assertEqual(hcl.strip_comments('name = "web" # a comment'), 'name = "web" ')
        self.assertEqual(hcl.strip_comments('name = "a # b"'), 'name = "a # b"')

    def test_masking_keeps_the_quotes_and_drops_the_contents(self):
        self.assertEqual(hcl.mask_strings('a = "x{y}"'), 'a = "    "')

    def test_a_brace_in_a_string_is_not_structure(self):
        self.assertEqual(hcl.strip_noise('policy = "${var.x}"').count("{"), 0)


class TestParsing(unittest.TestCase):
    def test_reads_labels_and_nesting(self):
        blocks = hcl.parse(
            'resource "aws_security_group" "web" {\n'
            "  ingress {\n"
            "    from_port = 22\n"
            "  }\n"
            "}\n"
        )
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].kind, "resource")
        self.assertEqual(blocks[0].type, "aws_security_group")
        self.assertEqual(blocks[0].name, "web")
        self.assertEqual([child.kind for child in blocks[0].children], ["ingress"])

    def test_unlabelled_and_assigned_blocks_both_parse(self):
        blocks = hcl.parse("resource \"a\" \"b\" {\n  tags = {\n    Name = \"x\"\n  }\n}\n")
        self.assertEqual([child.kind for child in blocks[0].children], ["tags"])

    def test_a_heredoc_body_is_not_parsed_as_structure(self):
        blocks = hcl.parse(
            'resource "a" "b" {\n'
            "  policy = <<EOF\n"
            '{ "Statement": [{ "Effect": "Allow" }] }\n'
            "EOF\n"
            "}\n"
        )
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].children, ())

    def test_sibling_blocks_are_not_nested(self):
        blocks = hcl.parse('resource "a" "b" {\n}\n\nresource "c" "d" {\n}\n')
        self.assertEqual(len(blocks), 2)
        self.assertEqual(blocks[1].line, 4)


class TestAttributes(unittest.TestCase):
    def block(self, text):
        return hcl.parse(text)[0]

    def test_finds_a_scalar(self):
        block = self.block('resource "a" "b" {\n  acl = "public-read"\n}\n')
        self.assertEqual(block.attribute("acl"), (2, '"public-read"'))

    def test_joins_a_list_written_across_lines(self):
        block = self.block(
            'resource "a" "b" {\n  cidr_blocks = [\n    "10.0.0.0/8",\n    "0.0.0.0/0",\n  ]\n}\n'
        )
        line, value = block.attribute("cidr_blocks")
        self.assertEqual(line, 2)
        self.assertIn("0.0.0.0/0", value)

    def test_a_nested_attribute_does_not_answer_for_the_parent(self):
        # encrypted = false inside root_block_device is a different finding
        # from the same words at the top of the resource.
        block = self.block(
            'resource "a" "b" {\n  root_block_device {\n    encrypted = false\n  }\n}\n'
        )
        self.assertIsNone(block.attribute("encrypted"))
        self.assertEqual(block.children[0].attribute("encrypted"), (3, "false"))

    def test_walk_reaches_every_depth(self):
        block = self.block(
            'resource "a" "b" {\n  x {\n    y {\n      z = 1\n    }\n  }\n}\n'
        )
        self.assertEqual([scope.kind for scope in block.walk()], ["resource", "x", "y"])

    def test_a_missing_attribute_is_none_not_an_error(self):
        self.assertIsNone(self.block('resource "a" "b" {\n}\n').attribute("acl"))


if __name__ == "__main__":
    unittest.main()
