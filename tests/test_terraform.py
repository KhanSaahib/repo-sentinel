"""Terraform rules: what is open, what is unencrypted, what is unlimited."""

import unittest

from repo_sentinel.findings import Severity
from repo_sentinel.scanners import terraform


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


def scan(text, path="main.tf"):
    return terraform.scan_terraform(path, text)


def security_group(body):
    return 'resource "aws_security_group" "web" {\n' + body + "}\n"


class TestPathRecognition(unittest.TestCase):
    def test_recognises_terraform_files(self):
        for path in ("main.tf", "infra/modules/vpc/variables.tf", "out.tf.json"):
            with self.subTest(path=path):
                self.assertTrue(terraform.is_terraform_path(path))

    def test_ignores_everything_else(self):
        for path in ("terraform.md", "src/tf.py", "tfvars"):
            with self.subTest(path=path):
                self.assertFalse(terraform.is_terraform_path(path))


class TestIngress(unittest.TestCase):
    def test_open_admin_port_is_critical(self):
        findings = scan(
            security_group(
                "  ingress {\n    from_port = 22\n    to_port = 22\n"
                '    cidr_blocks = ["0.0.0.0/0"]\n  }\n'
            )
        )
        self.assertEqual(findings[0].rule_id, "TF001")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertIn("SSH", findings[0].title)

    def test_open_web_port_is_high_not_critical(self):
        findings = scan(
            security_group(
                "  ingress {\n    from_port = 443\n    to_port = 443\n"
                '    cidr_blocks = ["0.0.0.0/0"]\n  }\n'
            )
        )
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_all_protocols_counts_as_every_port(self):
        findings = scan(
            security_group(
                '  ingress {\n    protocol = "-1"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n'
            )
        )
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertIn("every port", findings[0].title)

    def test_egress_to_the_world_is_not_a_finding(self):
        # Letting a host reach the internet is normal. Letting the internet
        # reach a host is not.
        findings = scan(
            security_group(
                "  egress {\n    from_port = 0\n    to_port = 0\n"
                '    protocol = "-1"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n'
            )
        )
        self.assertEqual(findings, [])

    def test_a_narrow_source_is_not_a_finding(self):
        findings = scan(
            security_group(
                "  ingress {\n    from_port = 22\n    to_port = 22\n"
                '    cidr_blocks = ["10.0.0.0/8"]\n  }\n'
            )
        )
        self.assertEqual(findings, [])

    def test_ipv6_counts_too(self):
        findings = scan(
            security_group(
                "  ingress {\n    from_port = 22\n    to_port = 22\n"
                '    ipv6_cidr_blocks = ["::/0"]\n  }\n'
            )
        )
        self.assertIn("TF001", rule_ids(findings))

    def test_standalone_rule_resources_are_read_too(self):
        text = (
            'resource "aws_security_group_rule" "ssh" {\n'
            '  type = "ingress"\n  from_port = 22\n  to_port = 22\n'
            '  cidr_blocks = ["0.0.0.0/0"]\n}\n'
        )
        self.assertIn("TF001", rule_ids(scan(text)))

    def test_the_newer_ingress_resource_type(self):
        # AWS adds one of these roughly every time somebody decides the
        # previous spelling was awkward.
        text = (
            'resource "aws_vpc_security_group_ingress_rule" "ssh" {\n'
            '  from_port = 22\n  to_port = 22\n  cidr_ipv4 = "0.0.0.0/0"\n}\n'
        )
        self.assertIn("TF001", rule_ids(scan(text)))

    def test_network_acl_entries_use_the_singular_attribute(self):
        text = (
            'resource "aws_network_acl_rule" "ssh" {\n  rule_number = 120\n'
            '  egress = false\n  protocol = "tcp"\n  from_port = 22\n'
            '  to_port = 22\n  cidr_block = "0.0.0.0/0"\n}\n'
        )
        findings = scan(text)
        self.assertIn("TF001", rule_ids(findings))
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_an_outbound_acl_entry_is_not_ingress(self):
        text = (
            'resource "aws_network_acl_rule" "out" {\n  egress = true\n'
            '  from_port = 0\n  to_port = 0\n  cidr_block = "0.0.0.0/0"\n}\n'
        )
        self.assertEqual(scan(text), [])

    def test_a_standalone_egress_rule_is_not_a_finding(self):
        text = (
            'resource "aws_security_group_rule" "out" {\n'
            '  type = "egress"\n  from_port = 0\n  to_port = 0\n'
            '  cidr_blocks = ["0.0.0.0/0"]\n}\n'
        )
        self.assertEqual(scan(text), [])


class TestPublicStorage(unittest.TestCase):
    def test_public_acl(self):
        self.assertIn(
            "TF002", rule_ids(scan('resource "aws_s3_bucket" "a" {\n  acl = "public-read"\n}\n'))
        )

    def test_private_acl_is_fine(self):
        self.assertEqual(scan('resource "aws_s3_bucket" "a" {\n  acl = "private"\n}\n'), [])

    def test_disabled_public_access_block(self):
        text = (
            'resource "aws_s3_bucket_public_access_block" "a" {\n'
            "  block_public_acls = false\n  block_public_policy = true\n}\n"
        )
        findings = scan(text)
        self.assertEqual(len(findings), 1)
        self.assertIn("block_public_acls", findings[0].title)

    def test_all_users_member(self):
        text = (
            'resource "google_storage_bucket_iam_member" "a" {\n  member = "allUsers"\n}\n'
        )
        self.assertIn("TF002", rule_ids(scan(text)))

    def test_a_named_principal_is_fine(self):
        text = (
            'resource "google_storage_bucket_iam_member" "a" {\n'
            '  member = "serviceAccount:app@example.iam.gserviceaccount.com"\n}\n'
        )
        self.assertEqual(scan(text), [])


class TestEncryption(unittest.TestCase):
    def test_explicitly_disabled_encryption(self):
        self.assertIn(
            "TF003",
            rule_ids(scan('resource "aws_db_instance" "a" {\n  storage_encrypted = false\n}\n')),
        )

    def test_nested_block_is_reported_where_it_sits(self):
        text = (
            'resource "aws_instance" "a" {\n  root_block_device {\n'
            "    encrypted = false\n  }\n}\n"
        )
        findings = scan(text)
        self.assertEqual(findings[0].line, 3)
        self.assertIn("root_block_device", findings[0].title)

    def test_encryption_left_at_the_default_is_not_reported(self):
        # Absence is not the same as refusal, and reporting every resource that
        # does not mention encryption would bury the ones that switched it off.
        self.assertEqual(scan('resource "aws_db_instance" "a" {\n  name = "x"\n}\n'), [])


class TestPolicies(unittest.TestCase):
    def test_wildcard_policy_document(self):
        text = (
            'data "aws_iam_policy_document" "a" {\n  statement {\n'
            '    actions = ["*"]\n    resources = ["*"]\n  }\n}\n'
        )
        self.assertIn("TF004", rule_ids(scan(text)))

    def test_a_deny_statement_is_not_a_grant(self):
        text = (
            'data "aws_iam_policy_document" "a" {\n  statement {\n'
            '    effect = "Deny"\n    actions = ["*"]\n    resources = ["*"]\n  }\n}\n'
        )
        self.assertEqual(scan(text), [])

    def test_scoped_actions_are_fine(self):
        text = (
            'data "aws_iam_policy_document" "a" {\n  statement {\n'
            '    actions = ["s3:GetObject"]\n    resources = ["*"]\n  }\n}\n'
        )
        self.assertEqual(scan(text), [])

    def test_json_policy_in_a_heredoc(self):
        text = (
            'resource "aws_iam_policy" "a" {\n  policy = <<EOF\n{\n'
            '  "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]\n'
            "}\nEOF\n}\n"
        )
        findings = scan(text)
        self.assertIn("TF004", rule_ids(findings))
        self.assertEqual(findings[0].line, 4)


class TestDatabasesAndState(unittest.TestCase):
    def test_public_database(self):
        self.assertIn(
            "TF005",
            rule_ids(scan('resource "aws_db_instance" "a" {\n  publicly_accessible = true\n}\n')),
        )

    def test_unencrypted_state_backend(self):
        text = 'terraform {\n  backend "s3" {\n    bucket = "state"\n  }\n}\n'
        self.assertIn("TF006", rule_ids(scan(text)))

    def test_encrypted_state_backend_is_fine(self):
        text = 'terraform {\n  backend "s3" {\n    bucket = "state"\n    encrypt = true\n  }\n}\n'
        self.assertEqual(scan(text), [])

    def test_other_backends_are_not_judged_on_an_s3_attribute(self):
        text = 'terraform {\n  backend "remote" {\n    organization = "acme"\n  }\n}\n'
        self.assertEqual(scan(text), [])


class TestSuppression(unittest.TestCase):
    def test_line_marker_silences_one_attribute(self):
        text = (
            'resource "aws_s3_bucket" "a" {\n'
            '  acl = "public-read"  # repo-sentinel: ignore\n}\n'
        )
        self.assertEqual(scan(text), [])

    def test_file_marker_silences_the_file(self):
        text = '# repo-sentinel: ignore-file\nresource "aws_s3_bucket" "a" {\n  acl = "public-read"\n}\n'
        self.assertEqual(scan(text), [])


class TestScanFiles(unittest.TestCase):
    def test_only_terraform_files_are_scanned(self):
        self.assertEqual(
            terraform.scan_files([("notes.md", 'resource "aws_s3_bucket" "a" {\n  acl = "public-read"\n}\n')]),
            [],
        )


if __name__ == "__main__":
    unittest.main()
