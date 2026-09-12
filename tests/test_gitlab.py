"""GitLab pipeline rules: the same injection, a different CI system."""

import unittest

from repo_sentinel.findings import Severity
from repo_sentinel.scanners import gitlab


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


def scan(text, path=".gitlab-ci.yml"):
    return gitlab.scan_pipeline(path, text)


def job(body, name="build"):
    return f"{name}:\n{body}"


class TestRecognition(unittest.TestCase):
    def test_recognised_by_name(self):
        self.assertTrue(gitlab.is_named_pipeline(".gitlab-ci.yml"))
        self.assertTrue(gitlab.is_named_pipeline("ci/templates/.gitlab-ci.yaml"))
        self.assertFalse(gitlab.is_named_pipeline("docker-compose.yml"))

    def test_recognised_by_shape_when_the_name_says_nothing(self):
        # include: lets a pipeline fragment live anywhere, under any name.
        text = job("  script:\n    - echo $CI_COMMIT_TITLE\n")
        self.assertIn("GL002", rule_ids(scan(text, "ci/jobs/build.yml")))

    def test_a_kubernetes_manifest_is_not_a_pipeline(self):
        text = (
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: w\nspec:\n"
            "  containers:\n    - name: app\n      image: nginx\n"
        )
        self.assertEqual(scan(text, "deploy/pod.yaml"), [])

    def test_an_unrelated_yaml_file_is_left_alone(self):
        self.assertEqual(scan("stages: [build]\n", "config.yml"), [])


class TestInjection(unittest.TestCase):
    def test_untrusted_variables_in_a_script(self):
        for variable in (
            "CI_COMMIT_TITLE",
            "CI_COMMIT_MESSAGE",
            "CI_MERGE_REQUEST_TITLE",
            "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
            "GITLAB_USER_LOGIN",
        ):
            with self.subTest(variable=variable):
                text = job(f'  script:\n    - echo "hello ${variable}"\n')
                findings = scan(text)
                self.assertIn("GL002", rule_ids(findings))
                self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_the_braced_form_counts_too(self):
        self.assertIn(
            "GL002", rule_ids(scan(job('  script:\n    - echo "${CI_COMMIT_TITLE}"\n')))
        )

    def test_a_trusted_variable_is_not_a_finding(self):
        for variable in ("CI_COMMIT_SHA", "CI_PROJECT_NAME", "CI_PIPELINE_ID"):
            with self.subTest(variable=variable):
                self.assertEqual(scan(job(f"  script:\n    - echo ${variable}\n")), [])

    def test_before_and_after_scripts_are_scripts(self):
        for key in ("before_script", "after_script"):
            with self.subTest(key=key):
                text = job(f"  {key}:\n    - echo $CI_COMMIT_TITLE\n  script:\n    - make\n")
                self.assertIn("GL002", rule_ids(scan(text)))

    def test_a_hidden_template_is_scanned(self):
        # GitLab does not run it directly, but everything that extends it does.
        text = job("  script:\n    - echo $CI_COMMIT_TITLE\n", name=".build_template")
        self.assertIn("GL002", rule_ids(scan(text)))


class TestNetworkTrust(unittest.TestCase):
    def test_pipe_to_shell(self):
        text = job("  script:\n    - curl -sSL https://x/i.sh | bash\n")
        self.assertIn("GL003", rule_ids(scan(text)))

    def test_a_verified_download_is_fine(self):
        text = job("  script:\n    - curl -sSLo i.sh https://x/i.sh\n    - sha256sum -c i.sha\n")
        self.assertEqual(scan(text), [])


class TestImages(unittest.TestCase):
    def test_a_floating_job_image(self):
        text = job("  image: python\n  script:\n    - make\n")
        self.assertIn("GL001", rule_ids(scan(text)))

    def test_a_pinned_image_is_accepted(self):
        text = job("  image: python:3.13\n  script:\n    - make\n")
        self.assertEqual(scan(text), [])

    def test_the_mapping_form_is_read(self):
        text = job("  image:\n    name: python:latest\n    entrypoint: [\"\"]\n  script:\n    - make\n")
        self.assertIn("GL001", rule_ids(scan(text)))

    def test_a_global_default_image_is_judged_once(self):
        text = "default:\n  image: python\n\n" + job("  script:\n    - make\n")
        findings = [f for f in scan(text) if f.rule_id == "GL001"]
        self.assertEqual(len(findings), 1)
        self.assertIn("default image", findings[0].title)

    def test_an_interpolated_image_is_decided_elsewhere(self):
        text = job("  image: $CI_REGISTRY_IMAGE\n  script:\n    - make\n")
        self.assertEqual(scan(text), [])


class TestDebugTrace(unittest.TestCase):
    def test_debug_trace_anywhere_is_a_finding(self):
        for text in (
            'variables:\n  CI_DEBUG_TRACE: "true"\n' + job("  script:\n    - make\n"),
            job('  variables:\n    CI_DEBUG_TRACE: "true"\n  script:\n    - make\n'),
        ):
            with self.subTest(text=text[:20]):
                self.assertIn("GL004", rule_ids(scan(text)))

    def test_switched_off_is_not_a_finding(self):
        text = 'variables:\n  CI_DEBUG_TRACE: "false"\n' + job("  script:\n    - make\n")
        self.assertEqual(scan(text), [])


class TestSuppression(unittest.TestCase):
    def test_line_marker(self):
        text = job('  script:\n    - echo $CI_COMMIT_TITLE  # repo-sentinel: ignore\n')
        self.assertEqual(scan(text), [])


if __name__ == "__main__":
    unittest.main()
