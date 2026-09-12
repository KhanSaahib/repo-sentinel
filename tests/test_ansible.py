"""Ansible rules: decisions applied to every host at once."""

import unittest

from bluerayscan.findings import Severity
from bluerayscan.scanners import ansible


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


def scan(text, path="playbooks/web.yml"):
    return ansible.scan_playbook(path, text)


def play(tasks):
    return "---\n- name: Configure\n  hosts: web\n  tasks:\n" + tasks


class TestRecognition(unittest.TestCase):
    def test_a_play_is_recognised_by_its_vocabulary(self):
        text = play("    - name: Ping\n      command: /bin/true\n      validate_certs: no\n")
        self.assertIn("AN001", rule_ids(scan(text)))

    def test_a_task_file_with_no_play_around_it(self):
        text = "- name: Fetch\n  uri:\n    url: https://x.invalid\n    validate_certs: false\n"
        self.assertIn("AN001", rule_ids(scan(text, "roles/web/tasks/main.yml")))

    def test_a_compose_file_is_not_a_playbook(self):
        self.assertEqual(scan("services:\n  db:\n    image: postgres\n", "compose.yml"), [])

    def test_a_bare_list_of_mappings_is_not_a_playbook(self):
        # Kustomize patches, CI matrices and half of everything else look like
        # this. The vocabulary check is what keeps them out.
        self.assertEqual(scan("- name: a\n  image: nginx\n", "k.yaml"), [])


class TestVerification(unittest.TestCase):
    def test_the_several_spellings(self):
        for key in ("validate_certs", "verify_ssl", "allow_insecure"):
            with self.subTest(key=key):
                text = play(f"    - name: Fetch\n      get_url:\n        url: https://x.invalid\n        {key}: no\n")
                findings = scan(text)
                self.assertIn("AN001", rule_ids(findings))
                self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_verification_left_on_is_not_a_finding(self):
        text = play("    - name: Fetch\n      get_url:\n        url: https://x.invalid\n        validate_certs: yes\n")
        self.assertEqual(scan(text), [])

    def test_the_finding_names_the_task(self):
        text = play("    - name: Install the agent\n      get_url:\n        url: https://x.invalid\n        validate_certs: no\n")
        self.assertIn("'Install the agent'", scan(text)[0].title)


class TestModes(unittest.TestCase):
    def test_world_writable_modes(self):
        for mode in ('"0777"', '"0666"', "0757", '"0662"'):
            with self.subTest(mode=mode):
                text = play(f"    - name: Write\n      copy:\n        dest: /tmp/x\n        mode: {mode}\n")
                self.assertIn("AN002", rule_ids(scan(text)))

    def test_ordinary_modes_are_fine(self):
        for mode in ('"0644"', '"0755"', '"0600"', "0640"):
            with self.subTest(mode=mode):
                text = play(f"    - name: Write\n      copy:\n        dest: /tmp/x\n        mode: {mode}\n")
                self.assertEqual(scan(text), [])


class TestPlaintextFetch(unittest.TestCase):
    def test_fetching_over_http(self):
        text = play("    - name: Fetch\n      get_url:\n        url: http://downloads.invalid/a.tgz\n")
        findings = scan(text)
        self.assertIn("AN003", rule_ids(findings))
        self.assertIn("downloads.invalid", findings[0].title)

    def test_a_templated_host_is_not_named_back_at_the_reader(self):
        # "http://{{ hue_ip }}/api" is still a plaintext fetch; the host is a
        # variable, and quoting the placeholder says nothing.
        text = play("    - name: Fetch\n      uri:\n        url: http://{{ hue_ip }}/api\n")
        findings = scan(text)
        self.assertIn("AN003", rule_ids(findings))
        self.assertNotIn("__TEMPLATED__", findings[0].title)

    def test_https_is_the_point(self):
        text = play("    - name: Fetch\n      get_url:\n        url: https://downloads.invalid/a.tgz\n")
        self.assertEqual(scan(text), [])

    def test_a_local_url_is_a_development_detail(self):
        text = play("    - name: Fetch\n      uri:\n        url: http://localhost:8080/health\n")
        self.assertEqual(scan(text), [])


class TestBlocks(unittest.TestCase):
    def test_a_task_inside_a_block_is_found_and_named(self):
        text = play(
            "    - name: Guarded\n      block:\n        - name: Inner\n"
            "          copy:\n            dest: /tmp/x\n            mode: \"0777\"\n"
        )
        findings = scan(text)
        self.assertEqual(len(findings), 1)
        self.assertIn("'Inner'", findings[0].title)

    def test_rescue_and_always_are_tasks_too(self):
        text = play(
            "    - name: Guarded\n      block:\n        - name: Try\n          command: /bin/true\n"
            "      rescue:\n        - name: Recover\n          copy:\n            dest: /tmp/x\n"
            "            mode: \"0777\"\n"
        )
        self.assertIn("'Recover'", scan(text)[0].title)


class TestSuppression(unittest.TestCase):
    def test_line_marker(self):
        text = play(
            "    - name: Fetch\n      get_url:\n        url: https://x.invalid\n"
            "        validate_certs: no  # repo-sentinel: ignore\n"
        )
        self.assertEqual(scan(text), [])


if __name__ == "__main__":
    unittest.main()
