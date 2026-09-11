"""CloudFormation rules: the Terraform mistakes, in AWS's other vocabulary."""

import unittest

from repo_sentinel.findings import Severity
from repo_sentinel.scanners import cloudformation


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


def scan(text, path="infra/stack.yaml"):
    return cloudformation.scan_template(path, text)


def template(resources):
    return 'AWSTemplateFormatVersion: "2010-09-09"\nResources:\n' + resources


class TestRecognition(unittest.TestCase):
    def test_a_template_declares_itself(self):
        text = template("  Bucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      AccessControl: PublicRead\n")
        self.assertIn("CF002", rule_ids(scan(text)))

    def test_resources_with_aws_types_are_enough(self):
        # Generated templates often omit the format version.
        text = "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      AccessControl: PublicRead\n"
        self.assertIn("CF002", rule_ids(scan(text)))

    def test_a_document_that_merely_has_resources_is_not_a_template(self):
        # A Helm values file can have anything in it, including "Resources".
        text = "Resources:\n  limits:\n    cpu: 1\n"
        self.assertEqual(scan(text), [])

    def test_a_kubernetes_manifest_is_not_a_template(self):
        text = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: w\nspec:\n  containers: []\n"
        self.assertEqual(scan(text, "deploy/pod.yaml"), [])


class TestIngress(unittest.TestCase):
    def group(self, rule):
        return template(
            "  Web:\n    Type: AWS::EC2::SecurityGroup\n    Properties:\n"
            "      SecurityGroupIngress:\n" + rule
        )

    def test_an_admin_port_open_to_the_world_is_critical(self):
        findings = scan(
            self.group("        - IpProtocol: tcp\n          FromPort: 22\n"
                       "          ToPort: 22\n          CidrIp: 0.0.0.0/0\n")
        )
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertIn("SSH", findings[0].title)

    def test_a_web_port_is_high(self):
        findings = scan(
            self.group("        - IpProtocol: tcp\n          FromPort: 443\n"
                       "          ToPort: 443\n          CidrIp: 0.0.0.0/0\n")
        )
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_a_narrow_range_is_not_a_finding(self):
        self.assertEqual(
            scan(self.group("        - IpProtocol: tcp\n          FromPort: 22\n"
                            "          ToPort: 22\n          CidrIp: 10.0.0.0/8\n")),
            [],
        )

    def test_an_intrinsic_function_is_decided_at_deploy_time(self):
        self.assertEqual(
            scan(self.group("        - IpProtocol: tcp\n          FromPort: 22\n"
                            "          ToPort: 22\n          CidrIp: !Ref AllowedRange\n")),
            [],
        )

    def test_the_standalone_ingress_resource(self):
        text = template(
            "  Rule:\n    Type: AWS::EC2::SecurityGroupIngress\n    Properties:\n"
            "      IpProtocol: tcp\n      FromPort: 3389\n      ToPort: 3389\n"
            "      CidrIp: 0.0.0.0/0\n"
        )
        self.assertIn("CF001", rule_ids(scan(text)))

    def test_ipv6_counts(self):
        self.assertIn(
            "CF001",
            rule_ids(scan(self.group("        - IpProtocol: tcp\n          FromPort: 22\n"
                                     "          ToPort: 22\n          CidrIpv6: ::/0\n"))),
        )


class TestStorageAndDatabases(unittest.TestCase):
    def test_a_public_acl(self):
        for acl in ("PublicRead", "PublicReadWrite", "AuthenticatedRead"):
            with self.subTest(acl=acl):
                text = template(f"  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      AccessControl: {acl}\n")
                self.assertIn("CF002", rule_ids(scan(text)))

    def test_a_private_acl_is_fine(self):
        text = template("  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      AccessControl: Private\n")
        self.assertEqual(scan(text), [])

    def test_a_disabled_public_access_block(self):
        text = template(
            "  B:\n    Type: AWS::S3::Bucket\n    Properties:\n"
            "      PublicAccessBlockConfiguration:\n        BlockPublicAcls: false\n"
            "        BlockPublicPolicy: true\n"
        )
        findings = scan(text)
        self.assertEqual(len(findings), 1)
        self.assertIn("BlockPublicAcls", findings[0].title)

    def test_a_public_database(self):
        text = template("  D:\n    Type: AWS::RDS::DBInstance\n    Properties:\n      PubliclyAccessible: true\n")
        self.assertIn("CF005", rule_ids(scan(text)))

    def test_encryption_switched_off(self):
        text = template("  D:\n    Type: AWS::RDS::DBInstance\n    Properties:\n      StorageEncrypted: false\n")
        self.assertIn("CF003", rule_ids(scan(text)))

    def test_encryption_left_at_the_default_is_not_reported(self):
        text = template("  D:\n    Type: AWS::RDS::DBInstance\n    Properties:\n      DBName: app\n")
        self.assertEqual(scan(text), [])


class TestPolicies(unittest.TestCase):
    def statement(self, body):
        return template(
            "  Role:\n    Type: AWS::IAM::Role\n    Properties:\n      Policies:\n"
            "        - PolicyDocument:\n            Statement:\n" + body
        )

    def test_a_wildcard_statement(self):
        text = self.statement('              - Effect: Allow\n                Action: "*"\n                Resource: "*"\n')
        self.assertIn("CF004", rule_ids(scan(text)))

    def test_a_wildcard_written_as_a_list(self):
        text = self.statement(
            "              - Effect: Allow\n                Action:\n                  - '*'\n"
            "                Resource:\n                  - '*'\n"
        )
        self.assertIn("CF004", rule_ids(scan(text)))

    def test_a_deny_statement_is_not_a_grant(self):
        text = self.statement('              - Effect: Deny\n                Action: "*"\n                Resource: "*"\n')
        self.assertEqual(scan(text), [])

    def test_scoped_actions_are_fine(self):
        text = self.statement('              - Effect: Allow\n                Action: "s3:GetObject"\n                Resource: "*"\n')
        self.assertEqual(scan(text), [])


class TestSuppression(unittest.TestCase):
    def test_line_marker(self):
        text = template(
            "  B:\n    Type: AWS::S3::Bucket\n    Properties:\n"
            "      AccessControl: PublicRead  # repo-sentinel: ignore\n"
        )
        self.assertEqual(scan(text), [])


if __name__ == "__main__":
    unittest.main()
