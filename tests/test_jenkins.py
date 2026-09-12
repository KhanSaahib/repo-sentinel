"""Jenkinsfile rules, and the quoting that decides whether they apply."""

import unittest

from bluerayscan.findings import Severity
from bluerayscan.scanners import jenkins


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


def scan(text, path="Jenkinsfile"):
    return jenkins.scan_jenkinsfile(path, text)


def pipeline(steps, agent=""):
    return (
        "pipeline {\n" + agent + "  stages {\n    stage('Build') {\n      steps {\n"
        + steps + "      }\n    }\n  }\n}\n"
    )


class TestRecognition(unittest.TestCase):
    def test_the_usual_names(self):
        for path in ("Jenkinsfile", "ci/Jenkinsfile.release", "build.jenkinsfile"):
            with self.subTest(path=path):
                self.assertTrue(jenkins.is_jenkinsfile(path))

    def test_a_groovy_file_has_to_look_like_a_pipeline(self):
        # Most Groovy in a repository is not a Jenkinsfile.
        self.assertTrue(jenkins.is_jenkinsfile("ci/build.groovy", "pipeline {\n}\n"))
        self.assertFalse(jenkins.is_jenkinsfile("src/Main.groovy", "class Main {}\n"))


class TestGroovyQuoting(unittest.TestCase):
    """The difference between the two lines is the whole rule."""

    def test_a_double_quoted_step_is_interpolated_by_groovy(self):
        findings = scan(pipeline('        sh "echo ${env.BRANCH_NAME}"\n'))
        self.assertEqual(findings[0].rule_id, "JK001")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_a_single_quoted_step_is_left_to_the_shell(self):
        # sh 'echo $BRANCH_NAME' expands in the shell, which never parses the
        # value as code. Reporting it would be reporting the fix.
        self.assertEqual(scan(pipeline("        sh 'echo $BRANCH_NAME'\n")), [])

    def test_a_triple_double_quoted_block_still_interpolates(self):
        text = pipeline('        sh """\n          echo ${env.CHANGE_TITLE}\n        """\n')
        self.assertIn("JK001", rule_ids(scan(text)))

    def test_a_triple_single_quoted_block_does_not(self):
        text = pipeline("        sh '''\n          echo $CHANGE_TITLE\n        '''\n")
        self.assertEqual(scan(text), [])

    def test_the_untrusted_variables(self):
        for name in ("BRANCH_NAME", "CHANGE_TITLE", "CHANGE_AUTHOR", "TAG_NAME"):
            with self.subTest(name=name):
                self.assertIn("JK001", rule_ids(scan(pipeline(f'        sh "echo ${{env.{name}}}"\n'))))

    def test_a_trusted_variable_is_not_a_finding(self):
        self.assertEqual(scan(pipeline('        sh "echo ${env.BUILD_NUMBER}"\n')), [])

    def test_bat_and_powershell_count_too(self):
        for step in ("bat", "powershell"):
            with self.subTest(step=step):
                self.assertIn("JK001", rule_ids(scan(pipeline(f'        {step} "echo ${{env.BRANCH_NAME}}"\n'))))


class TestAgentsAndDownloads(unittest.TestCase):
    def test_a_floating_agent_image(self):
        text = pipeline("        sh 'make'\n", agent="  agent { docker { image 'node:latest' } }\n")
        self.assertIn("JK002", rule_ids(scan(text)))

    def test_a_pinned_agent_image(self):
        text = pipeline("        sh 'make'\n", agent="  agent { docker { image 'node:20.11' } }\n")
        self.assertEqual(scan(text), [])

    def test_pipe_to_shell_in_either_quoting(self):
        for step in (
            "        sh 'curl -sSL https://x.invalid/i.sh | sh'\n",
            '        sh "curl -sSL https://x.invalid/i.sh | bash"\n',
        ):
            with self.subTest(step=step.strip()):
                self.assertIn("JK003", rule_ids(scan(pipeline(step))))

    def test_a_verified_download_is_fine(self):
        text = pipeline("        sh 'curl -sSLo i.sh https://x.invalid/i.sh && sha256sum -c i.sha'\n")
        self.assertEqual(scan(text), [])


class TestSuppression(unittest.TestCase):
    def test_line_marker(self):
        text = pipeline('        sh "echo ${env.BRANCH_NAME}"  // bluerayscan: ignore\n')
        self.assertEqual(scan(text), [])


if __name__ == "__main__":
    unittest.main()
