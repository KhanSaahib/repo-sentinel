"""Azure Pipelines rules: the same injection, a third time."""

import unittest

from bluerayscan.findings import Severity
from bluerayscan.scanners import azure


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


def scan(text, path="azure-pipelines.yml"):
    return azure.scan_pipeline(path, text)


def pipeline(steps, extra=""):
    return "trigger:\n  - main\n" + extra + "\nsteps:\n" + steps


class TestRecognition(unittest.TestCase):
    def test_recognised_by_name(self):
        for path in ("azure-pipelines.yml", "ci/azure-pipelines-release.yml", "vsts-ci.yml"):
            with self.subTest(path=path):
                self.assertTrue(azure.is_named_pipeline(path))

    def test_recognised_by_shape_when_the_name_says_nothing(self):
        text = pipeline('  - script: echo "$(Build.SourceVersionMessage)"\n')
        self.assertIn("AZ001", rule_ids(scan(text, "ci/templates/build.yml")))

    def test_a_kubernetes_manifest_is_not_a_pipeline(self):
        text = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: w\nspec:\n  containers: []\n"
        self.assertEqual(scan(text, "deploy/pod.yaml"), [])

    def test_an_unrelated_yaml_file_is_left_alone(self):
        self.assertEqual(scan("services:\n  db:\n    image: postgres\n", "compose.yml"), [])


class TestInjection(unittest.TestCase):
    def test_untrusted_variables(self):
        for variable in (
            "Build.SourceVersionMessage",
            "Build.SourceBranchName",
            "System.PullRequest.SourceBranch",
            "Build.RequestedFor",
        ):
            with self.subTest(variable=variable):
                findings = scan(pipeline(f'  - script: echo "$({variable})"\n'))
                self.assertIn("AZ001", rule_ids(findings))
                self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_fields_that_cannot_carry_an_injection(self):
        # A pull request id is a number and a commit id is hex; Azure picks
        # both. Reporting them is how a rule that matters gets ignored.
        for variable in ("System.PullRequest.PullRequestId", "System.PullRequest.SourceCommitId"):
            with self.subTest(variable=variable):
                self.assertEqual(scan(pipeline(f"  - script: echo $({variable})\n")), [])

    def test_bash_and_powershell_steps_count_too(self):
        for key in ("bash", "pwsh", "powershell"):
            with self.subTest(key=key):
                text = pipeline(f'  - {key}: echo "$(Build.SourceVersionMessage)"\n')
                self.assertIn("AZ001", rule_ids(scan(text)))

    def test_a_trusted_variable_is_not_a_finding(self):
        self.assertEqual(scan(pipeline("  - script: echo $(Build.BuildId)\n")), [])

    def test_the_finding_names_the_step(self):
        text = pipeline('  - script: echo "$(Build.SourceVersionMessage)"\n    displayName: Greet\n')
        self.assertIn("'Greet'", scan(text)[0].title)


class TestPools(unittest.TestCase):
    def test_a_self_hosted_pool(self):
        text = pipeline("  - script: make\n", extra="\npool:\n  name: our-build-servers\n")
        self.assertIn("AZ002", rule_ids(scan(text)))

    def test_microsoft_hosted_images_are_not_self_hosted(self):
        for image in ("ubuntu-latest", "windows-2022", "macos-13"):
            with self.subTest(image=image):
                text = pipeline("  - script: make\n", extra=f"\npool:\n  vmImage: {image}\n")
                self.assertEqual(scan(text), [])

    def test_a_pool_named_like_a_hosted_image_is_not_reported(self):
        text = pipeline("  - script: make\n", extra="\npool:\n  name: ubuntu-latest\n")
        self.assertEqual(scan(text), [])

    def test_the_pool_microsoft_runs_is_called_azure_pipelines(self):
        # The name every tutorial writes, and the one the rule used to report
        # as self-hosted -- loudest exactly where it was most wrong.
        for name in ("Azure Pipelines", "azure pipelines", "Hosted Ubuntu 1604"):
            with self.subTest(name=name):
                text = pipeline("  - script: make\n", extra=f"\npool:\n  name: {name}\n")
                self.assertEqual(scan(text), [])

    def test_a_named_pool_with_a_vm_image_is_still_microsoft_hosted(self):
        text = pipeline(
            "  - script: make\n",
            extra="\npool:\n  name: Azure Pipelines\n  vmImage: ubuntu-latest\n",
        )
        self.assertEqual(scan(text), [])

    def test_the_bare_form_still_finds_a_private_pool(self):
        text = pipeline("  - script: make\n", extra="\npool: our-build-servers\n")
        self.assertIn("AZ002", rule_ids(scan(text)))


class TestContainersAndDebug(unittest.TestCase):
    def test_a_floating_container(self):
        text = pipeline("  - script: make\n", extra="\ncontainer: node\n")
        self.assertIn("AZ003", rule_ids(scan(text)))

    def test_a_pinned_container(self):
        text = pipeline("  - script: make\n", extra="\ncontainer: node:20.11\n")
        self.assertEqual(scan(text), [])

    def test_debug_logging(self):
        text = pipeline("  - script: make\n", extra="\nvariables:\n  system.debug: true\n")
        findings = scan(text)
        self.assertIn("AZ004", rule_ids(findings))
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_debug_switched_off_is_fine(self):
        text = pipeline("  - script: make\n", extra="\nvariables:\n  system.debug: false\n")
        self.assertEqual(scan(text), [])


class TestSuppression(unittest.TestCase):
    def test_line_marker(self):
        text = pipeline('  - script: echo "$(Build.SourceVersionMessage)"  # bluerayscan: ignore\n')
        self.assertEqual(scan(text), [])


if __name__ == "__main__":
    unittest.main()
