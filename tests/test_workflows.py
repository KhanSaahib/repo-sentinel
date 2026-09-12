import textwrap
import unittest

from bluerayscan.findings import Severity
from bluerayscan.scanners import workflows

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

    def test_a_third_party_tag_outweighs_a_first_party_one(self):
        def severity(ref):
            findings = workflows.scan_workflow(
                ".github/workflows/ci.yml",
                workflow(
                    "permissions:\n  contents: read\njobs:\n  build:\n    steps:\n"
                    f"      - uses: {ref}\n"
                ),
            )
            return next(f for f in findings if f.rule_id == "WF001").severity

        # Somebody else's action moving under you is the rule; GitHub moving
        # GitHub, on a runner GitHub gave you, is the smaller half of it.
        self.assertGreater(severity("vendor/deploy@v2"), severity("actions/checkout@v4"))
        self.assertEqual(severity("actions/checkout@v4"), Severity.LOW)

    def test_an_action_with_no_version_at_all_is_still_reported(self):
        findings = workflows.scan_workflow(
            ".github/workflows/ci.yml",
            workflow(
                "permissions:\n  contents: read\njobs:\n  build:\n    steps:\n"
                "      - uses: vendor/deploy\n"
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


def workflow_with_jobs(body):
    return "name: ci\non:\n  push:\njobs:\n" + body


class TestJobStructure(unittest.TestCase):
    """Jobs and steps have to be split apart before most rules can be asked."""

    def test_splits_jobs_at_their_own_indent(self):
        text = workflow_with_jobs(
            "  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"
            "  deploy:\n    needs: build\n    steps:\n      - run: make deploy\n"
        )
        jobs = list(workflows.iter_jobs(text.splitlines()))
        self.assertEqual([job.name for job in jobs], ["build", "deploy"])
        self.assertEqual(len(jobs[0].body), 3)

    def test_a_workflow_without_jobs_has_none(self):
        self.assertEqual(list(workflows.iter_jobs(["name: ci", "on:", "  push:"])), [])

    def test_stops_at_the_next_top_level_key(self):
        text = workflow_with_jobs("  build:\n    steps: []\n") + "env:\n  A: 1\n"
        self.assertEqual([job.name for job in workflows.iter_jobs(text.splitlines())], ["build"])


class TestPerJobPermissions(unittest.TestCase):
    def test_a_job_declaring_its_own_permissions_is_not_reported(self):
        text = workflow_with_jobs(
            "  build:\n    permissions:\n      contents: read\n    steps:\n      - run: make\n"
        )
        self.assertNotIn("WF002", rule_ids(workflows.scan_workflow(".github/workflows/a.yml", text)))

    def test_each_job_without_permissions_is_reported_where_it_starts(self):
        text = workflow_with_jobs(
            "  build:\n    steps:\n      - run: make\n"
            "  deploy:\n    permissions:\n      contents: read\n    steps:\n      - run: make deploy\n"
        )
        findings = [f for f in workflows.scan_workflow(".github/workflows/a.yml", text) if f.rule_id == "WF002"]
        self.assertEqual(len(findings), 1)
        self.assertIn("build", findings[0].evidence)

    def test_a_file_where_no_job_declares_permissions_is_one_finding(self):
        # The fix is one top-level block, however many jobs there are.
        text = workflow_with_jobs(
            "  build:\n    steps:\n      - run: make\n"
            "  test:\n    steps:\n      - run: make test\n"
            "  deploy:\n    steps:\n      - run: make deploy\n"
        )
        findings = [
            f
            for f in workflows.scan_workflow(".github/workflows/a.yml", text)
            if f.rule_id == "WF002"
        ]
        self.assertEqual(len(findings), 1)
        self.assertIn("3 jobs", findings[0].evidence)

    def test_a_single_job_is_still_named(self):
        text = workflow_with_jobs("  build:\n    steps:\n      - run: make\n")
        findings = [
            f
            for f in workflows.scan_workflow(".github/workflows/a.yml", text)
            if f.rule_id == "WF002"
        ]
        self.assertEqual(len(findings), 1)
        self.assertIn("'build'", findings[0].evidence)

    def test_write_all_is_its_own_finding(self):
        text = workflow_with_jobs("  build:\n    permissions: write-all\n    steps: []\n")
        findings = workflows.scan_workflow(".github/workflows/a.yml", text)
        self.assertIn("WF005", rule_ids(findings))
        self.assertEqual(next(f for f in findings if f.rule_id == "WF005").severity, Severity.HIGH)


class TestRunners(unittest.TestCase):
    def test_flags_a_self_hosted_runner(self):
        text = workflow_with_jobs("  build:\n    runs-on: self-hosted\n    steps: []\n")
        self.assertIn("WF006", rule_ids(workflows.scan_workflow(".github/workflows/a.yml", text)))

    def test_flags_a_self_hosted_label_list(self):
        text = workflow_with_jobs("  build:\n    runs-on: [self-hosted, linux, x64]\n    steps: []\n")
        self.assertIn("WF006", rule_ids(workflows.scan_workflow(".github/workflows/a.yml", text)))

    def test_hosted_runners_are_fine(self):
        text = workflow_with_jobs("  build:\n    runs-on: ubuntu-latest\n    steps: []\n")
        self.assertNotIn("WF006", rule_ids(workflows.scan_workflow(".github/workflows/a.yml", text)))


class TestSecretHandoff(unittest.TestCase):
    def test_flags_a_secret_given_to_a_third_party_action(self):
        text = workflow_with_jobs(
            "  build:\n    steps:\n"
            "      - uses: some-vendor/deploy@v2\n"
            "        with:\n          token: ${{ secrets.DEPLOY_TOKEN }}\n"
        )
        findings = workflows.scan_workflow(".github/workflows/a.yml", text)
        handoff = next(f for f in findings if f.rule_id == "WF007")
        self.assertIn("DEPLOY_TOKEN", handoff.title)

    def test_a_pinned_action_is_code_somebody_chose(self):
        # The pin is the review. An action at a commit SHA cannot become
        # something else tomorrow, which is the risk this rule is about.
        text = workflow_with_jobs(
            "  build:\n    steps:\n"
            f"      - uses: some-vendor/deploy@{SHA}\n"
            "        with:\n          token: ${{ secrets.DEPLOY_TOKEN }}\n"
        )
        self.assertNotIn("WF007", rule_ids(workflows.scan_workflow(".github/workflows/a.yml", text)))

    def test_first_party_actions_are_not_third_parties(self):
        text = workflow_with_jobs(
            "  build:\n    steps:\n"
            "      - uses: actions/github-script@v7\n"
            "        with:\n          github-token: ${{ secrets.GITHUB_TOKEN }}\n"
        )
        self.assertNotIn("WF007", rule_ids(workflows.scan_workflow(".github/workflows/a.yml", text)))

    def test_a_secret_in_a_step_with_no_action_is_not_a_handoff(self):
        text = workflow_with_jobs(
            "  build:\n    steps:\n      - run: deploy.sh\n        env:\n          T: ${{ secrets.TOKEN }}\n"
        )
        self.assertNotIn("WF007", rule_ids(workflows.scan_workflow(".github/workflows/a.yml", text)))


class TestWorkflowRunCheckout(unittest.TestCase):
    def test_flags_checking_out_the_triggering_run(self):
        text = (
            "name: publish\non:\n  workflow_run:\n    workflows: [CI]\njobs:\n"
            "  publish:\n    permissions:\n      contents: read\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n          ref: ${{ github.event.workflow_run.head_sha }}\n"
        )
        self.assertIn("WF008", rule_ids(workflows.scan_workflow(".github/workflows/a.yml", text)))

    def test_a_plain_workflow_run_listener_is_fine(self):
        text = (
            "name: publish\non:\n  workflow_run:\n    workflows: [CI]\njobs:\n"
            "  publish:\n    permissions:\n      contents: read\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
        )
        self.assertNotIn("WF008", rule_ids(workflows.scan_workflow(".github/workflows/a.yml", text)))


def privileged(steps):
    return (
        "name: risky\non:\n  pull_request_target:\njobs:\n  build:\n"
        "    permissions:\n      contents: read\n    steps:\n" + steps
    )


class TestPersistedCredentials(unittest.TestCase):
    def test_checkout_under_a_privileged_trigger(self):
        findings = workflows.scan_workflow(
            ".github/workflows/a.yml", privileged("      - uses: actions/checkout@" + SHA + "\n")
        )
        self.assertIn("WF009", rule_ids(findings))

    def test_disabling_it_settles_the_matter(self):
        text = privileged(
            "      - uses: actions/checkout@" + SHA + "\n"
            "        with:\n          persist-credentials: false\n"
        )
        self.assertNotIn("WF009", rule_ids(workflows.scan_workflow(".github/workflows/a.yml", text)))

    def test_an_ordinary_trigger_is_not_in_scope(self):
        # The default is tolerable when the job only runs the repository's own
        # code; scoping the rule is what keeps it from being ignored.
        text = (
            "name: ci\non:\n  push:\njobs:\n  build:\n    permissions:\n"
            "      contents: read\n    steps:\n      - uses: actions/checkout@" + SHA + "\n"
        )
        self.assertNotIn("WF009", rule_ids(workflows.scan_workflow(".github/workflows/a.yml", text)))

    def test_other_actions_are_not_checkouts(self):
        text = privileged("      - uses: actions/setup-node@" + SHA + "\n")
        self.assertNotIn("WF009", rule_ids(workflows.scan_workflow(".github/workflows/a.yml", text)))


class TestExportedSecrets(unittest.TestCase):
    def test_secret_written_to_a_job_output(self):
        text = workflow(
            "jobs:\n  build:\n    permissions:\n      contents: read\n    steps:\n"
            '      - run: echo "token=${{ secrets.API_TOKEN }}" >> $GITHUB_OUTPUT\n'
        )
        findings = workflows.scan_workflow(".github/workflows/a.yml", text)
        self.assertIn("WF010", rule_ids(findings))
        self.assertIn("API_TOKEN", next(f for f in findings if f.rule_id == "WF010").title)

    def test_secret_written_to_the_job_environment(self):
        text = workflow(
            "jobs:\n  build:\n    permissions:\n      contents: read\n    steps:\n"
            '      - run: echo "T=${{ secrets.API_TOKEN }}" >> $GITHUB_ENV\n'
        )
        self.assertIn("WF010", rule_ids(workflows.scan_workflow(".github/workflows/a.yml", text)))

    def test_using_a_secret_within_the_step_is_fine(self):
        text = workflow(
            "jobs:\n  build:\n    permissions:\n      contents: read\n    steps:\n"
            "      - run: deploy.sh\n        env:\n          T: ${{ secrets.API_TOKEN }}\n"
        )
        self.assertNotIn("WF010", rule_ids(workflows.scan_workflow(".github/workflows/a.yml", text)))

    def test_writing_something_that_is_not_a_secret_is_fine(self):
        text = workflow(
            "jobs:\n  build:\n    permissions:\n      contents: read\n    steps:\n"
            '      - run: echo "version=1.2.3" >> $GITHUB_OUTPUT\n'
        )
        self.assertEqual(rule_ids(workflows.scan_workflow(".github/workflows/a.yml", text)), set())


class TestUnusedWritePermission(unittest.TestCase):
    """WF013: a grant nothing in the job uses."""

    def scan(self, body):
        return workflows.scan_workflow(".github/workflows/a.yml", workflow(body))

    def test_a_job_that_writes_nothing(self):
        findings = self.scan(
            "jobs:\n  build:\n    permissions:\n      contents: write\n"
            "    steps:\n      - run: make test\n"
        )
        finding = next(f for f in findings if f.rule_id == "WF013")
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertIn("'build'", finding.title)

    def test_a_job_that_does_write_is_not_reported(self):
        for step in (
            "      - run: git push origin main\n",
            "      - run: gh release create v1.0.0\n",
            "      - uses: peter-evans/create-pull-request@v6\n",
            "      - run: npx semantic-release\n",
        ):
            with self.subTest(step=step.strip()):
                body = (
                    "jobs:\n  publish:\n    permissions:\n      contents: write\n"
                    "    steps:\n" + step
                )
                self.assertNotIn("WF013", rule_ids(self.scan(body)))

    def test_a_top_level_grant_is_judged_against_the_whole_file(self):
        unused = self.scan(
            "permissions:\n  contents: write\njobs:\n  build:\n    steps:\n"
            "      - run: make test\n"
        )
        used = self.scan(
            "permissions:\n  contents: write\njobs:\n  build:\n    steps:\n"
            "      - run: git push origin main\n"
        )
        self.assertIn("WF013", rule_ids(unused))
        self.assertNotIn("WF013", rule_ids(used))

    def test_read_access_is_not_the_rule_s_business(self):
        body = (
            "jobs:\n  build:\n    permissions:\n      contents: read\n"
            "    steps:\n      - run: make test\n"
        )
        self.assertNotIn("WF013", rule_ids(self.scan(body)))

    def test_one_job_writing_does_not_excuse_another(self):
        body = (
            "jobs:\n"
            "  publish:\n    permissions:\n      contents: write\n"
            "    steps:\n      - run: gh release create v1\n"
            "  build:\n    permissions:\n      contents: write\n"
            "    steps:\n      - run: make test\n"
        )
        findings = [f for f in self.scan(body) if f.rule_id == "WF013"]
        self.assertEqual(len(findings), 1)
        self.assertIn("'build'", findings[0].title)


class TestInheritedSecrets(unittest.TestCase):
    """WF011: secrets: inherit on a call to somebody else's workflow."""

    def scan(self, body):
        return workflows.scan_workflow(".github/workflows/a.yml", workflow(body))

    def call(self, ref, secrets="    secrets: inherit\n"):
        return (
            "jobs:\n"
            "  release:\n"
            "    permissions:\n      contents: read\n"
            f"    uses: {ref}\n" + secrets
        )

    def test_a_call_to_another_repository_hands_over_everything(self):
        findings = self.scan(self.call("vendor/pipe/.github/workflows/r.yml@main"))
        finding = next(f for f in findings if f.rule_id == "WF011")
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertIn("vendor/pipe", finding.title)

    def test_a_call_within_this_repository_is_not_a_finding(self):
        self.assertNotIn("WF011", rule_ids(self.scan(self.call("./.github/workflows/r.yml"))))

    def test_naming_the_secrets_is_the_fix_and_is_not_reported(self):
        body = self.call(
            "vendor/pipe/.github/workflows/r.yml@main",
            secrets="    secrets:\n      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n",
        )
        self.assertNotIn("WF011", rule_ids(self.scan(body)))

    def test_a_pinned_call_is_still_reported_but_less_certainly(self):
        pinned = self.scan(self.call(f"vendor/pipe/.github/workflows/r.yml@{SHA}"))
        mutable = self.scan(self.call("vendor/pipe/.github/workflows/r.yml@main"))
        pinned_finding = next(f for f in pinned if f.rule_id == "WF011")
        mutable_finding = next(f for f in mutable if f.rule_id == "WF011")
        self.assertLess(pinned_finding.confidence, mutable_finding.confidence)

    def test_a_step_that_inherits_nothing_is_not_confused_for_a_call(self):
        body = (
            "jobs:\n"
            "  build:\n"
            "    permissions:\n      contents: read\n"
            "    steps:\n"
            f"      - uses: vendor/action@{SHA}\n"
            "      - run: echo secrets: inherit\n"
        )
        self.assertNotIn("WF011", rule_ids(self.scan(body)))


class TestCompositeActions(unittest.TestCase):
    """The family also reads action.yml, which is a workflow fragment."""

    ACTION = (
        "name: deploy\n"
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
    )

    def scan(self, steps):
        return workflows.scan_action("action.yml", workflow(self.ACTION + steps))

    def test_an_action_file_is_recognised_wherever_it_lives(self):
        self.assertTrue(workflows.is_action_path(".github/actions/deploy/action.yml"))
        self.assertTrue(workflows.is_action_path("action.yaml"))
        self.assertFalse(workflows.is_action_path("actions.yml"))

    def test_an_input_reaching_a_shell_is_reported(self):
        findings = self.scan('    - run: echo "${{ inputs.tag }}"\n      shell: bash\n')
        finding = next(f for f in findings if f.rule_id == "WF012")
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertIn("tag", finding.title)

    def test_one_input_mentioned_five_times_is_one_finding(self):
        findings = self.scan(
            "    - run: |\n"
            '        if [ -n "${{ inputs.tag }}" ]; then\n'
            '          echo "${{ inputs.tag }}"\n'
            "        fi\n"
            "      shell: bash\n"
        )
        self.assertEqual([f.rule_id for f in findings].count("WF012"), 1)

    def test_two_inputs_on_one_line_are_two_findings(self):
        findings = self.scan(
            '    - run: echo "${{ inputs.tag }} ${{ inputs.env }}"\n      shell: bash\n'
        )
        self.assertEqual([f.rule_id for f in findings].count("WF012"), 2)

    def test_an_input_passed_through_the_environment_is_the_fix(self):
        findings = self.scan(
            "    - env:\n        TAG: ${{ inputs.tag }}\n"
            '      run: echo "$TAG"\n      shell: bash\n'
        )
        self.assertNotIn("WF012", rule_ids(findings))

    def test_an_action_called_by_a_mutable_tag_is_still_reported(self):
        findings = self.scan("    - uses: vendor/setup@v1\n")
        self.assertIn("WF001", rule_ids(findings))

    def test_an_untrusted_context_inside_an_action_is_the_injection_rule(self):
        findings = self.scan(
            '    - run: echo "${{ github.event.issue.title }}"\n      shell: bash\n'
        )
        self.assertIn("WF003", rule_ids(findings))

    def test_a_javascript_action_has_no_steps_to_read(self):
        text = workflow(
            "name: deploy\nruns:\n  using: node20\n  main: dist/index.js\n"
        )
        self.assertEqual(workflows.scan_action("action.yml", text), [])

    def test_a_whole_file_marker_silences_an_action(self):
        text = workflow("# bluerayscan: ignore-file\n" + self.ACTION + "    - uses: v/a@v1\n")
        self.assertEqual(workflows.scan_action("action.yml", text), [])

    def test_scan_files_picks_up_actions_as_well_as_workflows(self):
        findings = workflows.scan_files(
            [("action.yml", workflow(self.ACTION + "    - uses: vendor/setup@v1\n"))]
        )
        self.assertIn("WF001", rule_ids(findings))


if __name__ == "__main__":
    unittest.main()
