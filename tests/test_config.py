"""Project defaults: what a config file may say, and what it may not override."""

import json
import os
import tempfile
import unittest

from repo_sentinel import cli, config


def write(root, payload):
    path = os.path.join(root, config.DEFAULT_PATH)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(payload))
    return path


def dockerfile(root):
    with open(os.path.join(root, "Dockerfile"), "w", encoding="utf-8") as handle:
        handle.write("FROM debian:latest\nRUN echo hi\n")


def run(argv):
    import contextlib
    import io

    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = cli.main(argv)
    return code, stdout.getvalue()


class TestLoading(unittest.TestCase):
    def test_reads_known_settings(self):
        with tempfile.TemporaryDirectory() as root:
            path = write(root, {"fail_on": "critical", "disable": ["DK002"]})
            self.assertEqual(config.load(path), {"fail_on": "critical", "disable": ["DK002"]})

    def test_an_unknown_setting_is_an_error_not_a_shrug(self):
        # A typo in a security tool's configuration should be loud. Ignoring it
        # means a project believes it configured something it did not.
        with tempfile.TemporaryDirectory() as root:
            path = write(root, {"fail-on": "critical"})
            with self.assertRaises(config.ConfigError) as caught:
                config.load(path)
            self.assertIn("unknown setting", str(caught.exception))

    def test_wrong_types_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            for payload in ({"exclude": "tests"}, {"gitignore": "no"}, {"fail_on": 3}):
                with self.subTest(payload=payload):
                    with self.assertRaises(config.ConfigError):
                        config.load(write(root, payload))

    def test_broken_json_is_an_error(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "broken.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("{not json")
            with self.assertRaises(config.ConfigError):
                config.load(path)

    def test_found_beside_the_scanned_tree(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertIsNone(config.find(root, None))
            path = write(root, {})
            self.assertEqual(config.find(root, None), path)


class TestDisabledMatcher(unittest.TestCase):
    def test_exact_and_family_patterns(self):
        disabled = config.disabled_matcher(["K8S004", "dc*"])
        self.assertTrue(disabled("K8S004"))
        self.assertTrue(disabled("DC001"))
        self.assertFalse(disabled("K8S001"))
        self.assertFalse(disabled("SEC001"))

    def test_nothing_disabled_disables_nothing(self):
        disabled = config.disabled_matcher([])
        self.assertFalse(disabled("SEC001"))


class TestPrecedence(unittest.TestCase):
    def test_config_supplies_defaults(self):
        with tempfile.TemporaryDirectory() as root:
            dockerfile(root)
            write(root, {"fail_on": "critical"})
            code, _ = run(["scan", root])
        self.assertEqual(code, cli.EXIT_OK)

    def test_the_command_line_wins(self):
        # A config file must never stop someone auditing their own repository
        # more strictly than the project usually does.
        with tempfile.TemporaryDirectory() as root:
            dockerfile(root)
            write(root, {"fail_on": "critical"})
            code, _ = run(["scan", root, "--fail-on", "medium"])
        self.assertEqual(code, cli.EXIT_FINDINGS)

    def test_a_bad_config_stops_the_run(self):
        with tempfile.TemporaryDirectory() as root:
            dockerfile(root)
            write(root, {"nonsense": True})
            code, _ = run(["scan", root])
        self.assertEqual(code, cli.EXIT_ERROR)


class TestRelativePaths(unittest.TestCase):
    def test_a_baseline_path_is_relative_to_the_config_file(self):
        # Not to whatever directory the command was run from: "scan some/repo"
        # has to find the baseline that repo's own config points at.
        with tempfile.TemporaryDirectory() as root:
            dockerfile(root)
            write(root, {"baseline": "accepted.json"})
            run(["scan", root, "--write-baseline", os.path.join(root, "accepted.json")])
            code, output = run(["scan", root])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("accepted by", output)


class TestDisabledRules(unittest.TestCase):
    def test_a_disabled_rule_is_dropped_and_counted(self):
        with tempfile.TemporaryDirectory() as root:
            dockerfile(root)
            _, output = run(["scan", root, "--disable", "DK002"])
        # The note names what was switched off, so the rule id is still in the
        # output; what must be gone is the finding itself.
        self.assertNotIn("Final image runs as root", output)
        self.assertIn("1 finding(s) hidden by disabled rules", output)

    def test_a_family_can_be_switched_off(self):
        with tempfile.TemporaryDirectory() as root:
            dockerfile(root)
            code, output = run(["scan", root, "--disable", "DK*"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("No findings", output)

    def test_an_unknown_rule_id_is_called_out(self):
        with tempfile.TemporaryDirectory() as root:
            dockerfile(root)
            _, output = run(["scan", root, "--disable", "DK999"])
        self.assertIn("No such rule: DK999", output)


class TestPathScopes(unittest.TestCase):
    """Rules switched off for one subtree rather than everywhere."""

    def scope(self, pattern, disable=("K8S*",)):
        return config.PathScope.build(pattern, list(disable))

    def test_a_directory_pattern_covers_what_is_under_it(self):
        # The walk gets this free by never descending; matching after the fact
        # has to do the same work by hand.
        scope = self.scope("examples/")
        self.assertTrue(scope.covers("examples/pod.yaml"))
        self.assertTrue(scope.covers("examples/nested/pod.yaml"))
        self.assertFalse(scope.covers("deploy/pod.yaml"))

    def test_the_glob_dialect_is_the_gitignore_one(self):
        self.assertTrue(self.scope("charts/vendor/**").covers("charts/vendor/a/b.yaml"))
        self.assertTrue(self.scope("**/fixtures/**").covers("tests/fixtures/key.pem"))
        self.assertTrue(self.scope("*.tf").covers("infra/main.tf"))
        self.assertFalse(self.scope("*.tf").covers("infra/main.tfvars"))

    def test_scopes_are_read_from_the_config(self):
        settings = {"paths": {"examples/**": {"disable": ["K8S004"]}}}
        scopes = config.path_scopes(settings)
        self.assertEqual([scope.pattern for scope in scopes], ["examples/**"])
        self.assertEqual(scopes[0].disable, ("K8S004",))

    def test_a_malformed_paths_table_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            for payload in (
                {"paths": ["examples/**"]},
                {"paths": {"examples/**": ["K8S004"]}},
                {"paths": {"examples/**": {"disabled": ["K8S004"]}}},
                {"paths": {"examples/**": {"disable": "K8S004"}}},
            ):
                with self.subTest(payload=payload):
                    with self.assertRaises(config.ConfigError):
                        config.load(write(root, payload))


class TestPathScopedDisabling(unittest.TestCase):
    def repository(self, root):
        manifest = (
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: w\nspec:\n"
            "  containers:\n    - name: a\n      image: nginx\n"
        )
        for directory in ("examples", "deploy"):
            os.makedirs(os.path.join(root, directory), exist_ok=True)
            with open(os.path.join(root, directory, "pod.yaml"), "w", encoding="utf-8") as handle:
                handle.write(manifest)

    def test_a_rule_can_be_off_in_one_subtree_and_on_in_another(self):
        with tempfile.TemporaryDirectory() as root:
            self.repository(root)
            write(root, {"paths": {"examples/**": {"disable": ["K8S*"]}}})
            _, output = run(["scan", root, "--format", "json"])
            paths = {finding["path"] for finding in json.loads(output)["findings"]}
        self.assertEqual(paths, {"deploy/pod.yaml"})

    def test_what_it_hid_is_still_counted(self):
        with tempfile.TemporaryDirectory() as root:
            self.repository(root)
            write(root, {"paths": {"examples/**": {"disable": ["K8S*"]}}})
            _, output = run(["scan", root])
        self.assertIn("hidden by disabled rules", output)


if __name__ == "__main__":
    unittest.main()
