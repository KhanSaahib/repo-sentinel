"""Compose rules: isolation negotiated away one line at a time."""

import unittest

from bluerayscan.findings import Severity
from bluerayscan.scanners import compose


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


def scan(text, path="docker-compose.yml"):
    return compose.scan_compose(path, text)


def stack(body):
    return "services:\n  app:\n    image: app:1.0\n" + body


class TestRecognition(unittest.TestCase):
    def test_a_document_with_services_is_a_stack(self):
        self.assertIn("DC001", rule_ids(scan(stack("    privileged: true\n"))))

    def test_a_kubernetes_service_is_not_a_compose_service(self):
        # Both have "services"; only one has an apiVersion.
        text = (
            "apiVersion: v1\nkind: Service\nmetadata:\n  name: web\n"
            "spec:\n  services:\n    app:\n      privileged: true\n"
        )
        self.assertEqual(scan(text, "k8s/svc.yaml"), [])

    def test_an_unrelated_yaml_file_is_left_alone(self):
        self.assertEqual(scan("on:\n  push:\njobs:\n  build: {}\n", "ci.yml"), [])


class TestPrivilegeAndConfinement(unittest.TestCase):
    def test_privileged(self):
        findings = scan(stack("    privileged: true\n"))
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_privileged_false_is_not_a_finding(self):
        self.assertEqual(scan(stack("    privileged: false\n")), [])

    def test_dangerous_capability(self):
        self.assertIn("DC004", rule_ids(scan(stack("    cap_add:\n      - SYS_ADMIN\n"))))

    def test_inline_capability_list(self):
        self.assertIn("DC004", rule_ids(scan(stack("    cap_add: [NET_ADMIN]\n"))))

    def test_harmless_capability(self):
        self.assertEqual(scan(stack("    cap_add:\n      - CHOWN\n")), [])

    def test_unconfined_profile(self):
        findings = scan(stack("    security_opt:\n      - seccomp:unconfined\n"))
        self.assertIn("DC004", rule_ids(findings))

    def test_a_custom_profile_is_fine(self):
        self.assertEqual(scan(stack("    security_opt:\n      - seccomp:./profile.json\n")), [])


class TestHostAccess(unittest.TestCase):
    def test_host_namespaces(self):
        for line in ("network_mode: host", "pid: host", "ipc: host", "userns_mode: host"):
            with self.subTest(line=line):
                self.assertIn("DC003", rule_ids(scan(stack(f"    {line}\n"))))

    def test_bridge_networking_is_fine(self):
        self.assertEqual(scan(stack("    network_mode: bridge\n")), [])

    def test_the_runtime_socket(self):
        findings = scan(stack("    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"))
        self.assertEqual(findings[0].rule_id, "DC002")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_the_host_root(self):
        self.assertIn("DC002", rule_ids(scan(stack("    volumes:\n      - /:/host\n"))))

    def test_a_named_volume_is_not_a_host_mount(self):
        self.assertEqual(scan(stack("    volumes:\n      - data:/var/lib/app\n")), [])

    def test_an_ordinary_bind_mount_is_not_reported(self):
        # Mounting the project directory is how everyone develops; reporting it
        # would drown the socket mount that actually matters.
        self.assertEqual(scan(stack("    volumes:\n      - ./src:/app/src\n")), [])


class TestPorts(unittest.TestCase):
    def test_a_database_on_every_interface(self):
        findings = scan(stack('    ports:\n      - "5432:5432"\n'))
        self.assertEqual(findings[0].rule_id, "DC005")
        self.assertIn("PostgreSQL", findings[0].title)

    def test_bound_to_loopback_is_fine(self):
        self.assertEqual(scan(stack('    ports:\n      - "127.0.0.1:5432:5432"\n')), [])

    def test_web_ports_are_not_a_finding(self):
        # A server on 443 open to the world is the point of it.
        self.assertEqual(scan(stack('    ports:\n      - "80:80"\n      - "443:443"\n')), [])

    def test_a_range_covering_a_sensitive_port(self):
        self.assertIn("DC005", rule_ids(scan(stack('    ports:\n      - "6370-6390:6379"\n'))))

    def test_container_only_ports_are_not_published(self):
        self.assertEqual(scan(stack('    expose:\n      - "5432"\n')), [])


class TestImages(unittest.TestCase):
    def test_floating_tags(self):
        for reference in ("postgres", "postgres:latest"):
            with self.subTest(reference=reference):
                text = f"services:\n  db:\n    image: {reference}\n"
                self.assertIn("DC006", rule_ids(scan(text)))

    def test_a_pinned_tag_is_accepted(self):
        self.assertEqual(scan("services:\n  db:\n    image: postgres:16.2\n"), [])

    def test_an_interpolated_tag_is_decided_elsewhere(self):
        self.assertEqual(scan("services:\n  db:\n    image: postgres:${TAG}\n"), [])

    def test_a_built_service_has_no_image_to_judge(self):
        self.assertEqual(scan("services:\n  app:\n    build: .\n"), [])


class TestSuppression(unittest.TestCase):
    def test_line_marker(self):
        self.assertEqual(scan(stack("    privileged: true  # repo-sentinel: ignore\n")), [])


if __name__ == "__main__":
    unittest.main()
