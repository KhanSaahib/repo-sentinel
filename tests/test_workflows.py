import textwrap
import unittest

from repo_sentinel.findings import Severity
from repo_sentinel.scanners import workflows

SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


def workflow(body: str) -> str:
    return textwrap.dedent(body).lstrip("\n")


class TestWorkflowPathMatching(unittest.TestCase):
    def test_accepts_workflow_files(self):
        self.assertTrue(workflows.is_workflow_path(".github/workflows/ci.yml"))
        self.assertTrue(workflows.is_workflow_path(".github/workflows/release.yaml"))

    def test_accepts_windows_separators(self):
        self.assertTrue(workflows.is_workflow_path(".github\\workflows\\ci.yml"))

    def test_rejects_other_yaml(self):
        self.assertFalse(workflows.is_workflow_path("docker-compose.yml"))
        self.assertFalse(workflows.is_workflow_path(".github/dependabot.yml"))

    def test_rejects_non_yaml_in_the_workflow_directory(self):
        self.assertFalse(workflows.is_workflow_path(".github/workflows/README.md"))


class TestActionPinning(unittest.TestCase):
    def test_flags_a_mutable_tag(self):
        findings = workflows.scan_workflow(
            ".github/workflows/ci.yml",
            workflow(
                """
                permissions:
                  contents: read
                jobs:
                  build:
                    steps:
                      - uses: actions/checkout@v4
                """
            ),
        )
        self.assertIn("WF001", rule_ids(findings))

    def test_accepts_a_sha_pin(self):
        findings = workflows.scan_workflow(
            ".github/workflows/ci.yml",
            workflow(
                f"""
                permissions:
                  contents: read
                jobs:
                  build:
                    steps:
                      - uses: actions/checkout@{SHA}
                """
            ),
        )
        self.assertNotIn("WF001", rule_ids(findings))

    def test_ignores_local_and_docker_actions(self):
        findings = workflows.scan_workflow(
            ".github/workflows/ci.yml",
            workflow(
                """
                permissions:
                  contents: read
                jobs:
                  build:
                    steps:
                      - uses: ./.github/actions/setup
                      - uses: docker://alpine:3.20
                """
            ),
        )
        self.assertNotIn("WF001", rule_ids(findings))


class TestPermissions(unittest.TestCase):
    def test_flags_missing_permissions_block(self):
        findings = workflows.scan_workflow(
            ".github/workflows/ci.yml", workflow("jobs:\n  build:\n    steps: []\n")
        )
        self.assertIn("WF002", rule_ids(findings))

    def test_accepts_a_top_level_permissions_block(self):
        findings = workflows.scan_workflow(
            ".github/workflows/ci.yml",
            workflow("permissions:\n  contents: read\njobs:\n  build:\n    steps: []\n"),
        )
        self.assertNotIn("WF002", rule_ids(findings))


class TestScriptInjection(unittest.TestCase):
    def test_flags_untrusted_input_in_a_block_scalar(self):
        findings = workflows.scan_workflow(
            ".github/workflows/ci.yml",
            workflow(
                """
                permissions:
                  contents: read
                jobs:
                  greet:
                    steps:
                      - run: |
                          echo "title: ${{ github.event.issue.title }}"
                """
            ),
        )
        self.assertIn("WF003", rule_ids(findings))
        injection = [f for f in findings if f.rule_id == "WF003"][0]
        self.assertEqual(injection.severity, Severity.CRITICAL)

    def test_flags_untrusted_input_in_an_inline_run(self):
        findings = workflows.scan_workflow(
            ".github/workflows/ci.yml",
            workflow(
                """
                permissions:
                  contents: read
                jobs:
                  greet:
                    steps:
                      - run: echo ${{ github.head_ref }}
                """
            ),
        )
        self.assertIn("WF003", rule_ids(findings))

    def test_ignores_trusted_contexts(self):
        findings = workflows.scan_workflow(
            ".github/workflows/ci.yml",
            workflow(
                """
                permissions:
                  contents: read
                jobs:
                  greet:
                    steps:
                      - run: echo ${{ github.repository }} ${{ github.sha }}
                """
            ),
        )
        self.assertNotIn("WF003", rule_ids(findings))

    def test_ignores_untrusted_input_outside_a_run_block(self):
        findings = workflows.scan_workflow(
            ".github/workflows/ci.yml",
            workflow(
                """
                permissions:
                  contents: read
                jobs:
                  greet:
                    steps:
                      - env:
                          TITLE: ${{ github.event.issue.title }}
                        run: echo "$TITLE"
                """
            ),
        )
        self.assertNotIn("WF003", rule_ids(findings))


class TestPullRequestTarget(unittest.TestCase):
    def test_flags_checkout_of_untrusted_ref(self):
        findings = workflows.scan_workflow(
            ".github/workflows/pr.yml",
            workflow(
                f"""
                on:
                  pull_request_target:
                permissions:
                  contents: read
                jobs:
                  build:
                    steps:
                      - uses: actions/checkout@{SHA}
                        with:
                          ref: ${{{{ github.event.pull_request.head.sha }}}}
                """
            ),
        )
        self.assertIn("WF004", rule_ids(findings))

    def test_plain_pull_request_is_fine(self):
        findings = workflows.scan_workflow(
            ".github/workflows/pr.yml",
            workflow(
                f"""
                on:
                  pull_request:
                permissions:
                  contents: read
                jobs:
                  build:
                    steps:
                      - uses: actions/checkout@{SHA}
                        with:
                          ref: main
                """
            ),
        )
        self.assertNotIn("WF004", rule_ids(findings))


class TestScanFiles(unittest.TestCase):
    def test_only_workflow_files_are_scanned(self):
        findings = workflows.scan_files(
            [("docker-compose.yml", "services:\n  web:\n    image: nginx\n")]
        )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
