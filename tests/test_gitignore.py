import contextlib
import json
import io
import os
import tempfile
import unittest

import fixtures
from bluerayscan import cli
from bluerayscan.discovery import iter_files
from bluerayscan.gitignore import GitIgnoreFile, GitIgnoreStack


def stack_for(*lines, base=""):
    return GitIgnoreStack().push(GitIgnoreFile.from_lines(lines, base))


def write(root, relative, text=""):
    path = os.path.join(root, *relative.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


def run(argv):
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        code = cli.main(argv)
    return code, stdout.getvalue()


class TestPatternMatching(unittest.TestCase):
    def assertIgnored(self, rules, path, is_dir=False):
        self.assertTrue(rules.is_ignored(path, is_dir), f"expected {path!r} to be ignored")

    def assertKept(self, rules, path, is_dir=False):
        self.assertFalse(rules.is_ignored(path, is_dir), f"expected {path!r} to be kept")

    def test_bare_name_matches_at_any_depth(self):
        rules = stack_for("secrets.txt")
        self.assertIgnored(rules, "secrets.txt")
        self.assertIgnored(rules, "a/b/secrets.txt")
        self.assertKept(rules, "a/secrets.txt.bak")

    def test_leading_slash_anchors_to_the_ignore_file(self):
        rules = stack_for("/build")
        self.assertIgnored(rules, "build", is_dir=True)
        self.assertKept(rules, "src/build", is_dir=True)

    def test_embedded_slash_also_anchors(self):
        rules = stack_for("doc/notes.md")
        self.assertIgnored(rules, "doc/notes.md")
        self.assertKept(rules, "src/doc/notes.md")

    def test_trailing_slash_matches_directories_only(self):
        rules = stack_for("cache/")
        self.assertIgnored(rules, "cache", is_dir=True)
        self.assertKept(rules, "cache")

    def test_star_does_not_cross_a_separator(self):
        rules = stack_for("logs/*.log")
        self.assertIgnored(rules, "logs/today.log")
        self.assertKept(rules, "logs/2026/today.log")

    def test_double_star_crosses_separators(self):
        rules = stack_for("logs/**/*.log")
        self.assertIgnored(rules, "logs/today.log")
        self.assertIgnored(rules, "logs/2026/09/today.log")

    def test_trailing_double_star_takes_the_whole_subtree(self):
        rules = stack_for("vendor/**")
        self.assertIgnored(rules, "vendor/lib/a.py")
        self.assertKept(rules, "vendor")

    def test_leading_double_star_matches_any_prefix(self):
        rules = stack_for("**/tmp")
        self.assertIgnored(rules, "tmp", is_dir=True)
        self.assertIgnored(rules, "a/b/tmp", is_dir=True)

    def test_question_mark_and_character_class(self):
        rules = stack_for("file?.txt", "part[0-9].bin")
        self.assertIgnored(rules, "fileA.txt")
        self.assertKept(rules, "file.txt")
        self.assertIgnored(rules, "part7.bin")
        self.assertKept(rules, "partX.bin")

    def test_negated_class_uses_gitignore_spelling(self):
        rules = stack_for("x[!0-9].log")
        self.assertIgnored(rules, "xa.log")
        self.assertKept(rules, "x1.log")

    def test_last_matching_pattern_wins(self):
        rules = stack_for("*.log", "!keep.log")
        self.assertIgnored(rules, "debug.log")
        self.assertKept(rules, "keep.log")

    def test_reinclusion_order_matters(self):
        rules = stack_for("!keep.log", "*.log")
        self.assertIgnored(rules, "keep.log")

    def test_comments_and_blank_lines_carry_no_rule(self):
        rules = stack_for("", "   ", "# *.py", "*.log")
        self.assertKept(rules, "app.py")
        self.assertIgnored(rules, "app.log")

    def test_escaped_hash_is_a_literal_name(self):
        rules = stack_for("\\#notes.md")
        self.assertIgnored(rules, "#notes.md")

    def test_trailing_space_is_dropped_unless_escaped(self):
        self.assertIgnored(stack_for("build   "), "build")
        self.assertIgnored(stack_for("odd\\ "), "odd ")

    def test_malformed_class_falls_back_to_a_literal(self):
        rules = stack_for("weird[abc.txt")
        self.assertIgnored(rules, "weird[abc.txt")

    def test_nested_ignore_file_is_relative_to_its_directory(self):
        rules = GitIgnoreStack().push(GitIgnoreFile.from_lines(["/local.txt"], "pkg/"))
        self.assertIgnored(rules, "pkg/local.txt")
        self.assertKept(rules, "local.txt")

    def test_inner_file_can_re_include_what_the_outer_hid(self):
        rules = GitIgnoreStack()
        rules = rules.push(GitIgnoreFile.from_lines(["*.log"], ""))
        rules = rules.push(GitIgnoreFile.from_lines(["!wanted.log"], "pkg/"))
        self.assertIgnored(rules, "pkg/other.log")
        self.assertKept(rules, "pkg/wanted.log")

    def test_empty_stack_ignores_nothing(self):
        self.assertKept(GitIgnoreStack(), "anything")


class TestGitIgnoreFile(unittest.TestCase):
    def test_load_returns_none_when_the_file_has_no_rules(self):
        with tempfile.TemporaryDirectory() as root:
            path = write(root, ".gitignore", "# only a comment\n\n")
            self.assertIsNone(GitIgnoreFile.load(path))

    def test_load_returns_none_when_the_file_is_unreadable(self):
        with tempfile.TemporaryDirectory() as root:
            missing = os.path.join(root, "nope", ".gitignore")
            self.assertIsNone(GitIgnoreFile.load(missing))

    def test_load_reads_patterns_from_disk(self):
        with tempfile.TemporaryDirectory() as root:
            path = write(root, ".gitignore", "*.log\n!keep.log\n")
            rules = GitIgnoreFile.load(path)
            self.assertIsNotNone(rules)
            self.assertEqual(len(rules.patterns), 2)


class TestWalkerIntegration(unittest.TestCase):
    def test_ignored_files_and_directories_are_skipped(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, ".gitignore", "*.log\nbuild/\n!important.log\n")
            write(root, "app.py", "x = 1\n")
            write(root, "debug.log", "noise\n")
            write(root, "important.log", "signal\n")
            write(root, "build/generated.py", "y = 2\n")
            paths = {path for path, _ in iter_files(root)}
        self.assertIn("app.py", paths)
        self.assertIn("important.log", paths)
        self.assertNotIn("debug.log", paths)
        self.assertNotIn("build/generated.py", paths)

    def test_nested_ignore_file_only_governs_its_own_subtree(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, "pkg/.gitignore", "notes.md\n")
            write(root, "pkg/notes.md", "hidden\n")
            write(root, "notes.md", "visible\n")
            paths = {path for path, _ in iter_files(root)}
        self.assertIn("notes.md", paths)
        self.assertNotIn("pkg/notes.md", paths)

    def test_no_gitignore_flag_restores_the_full_walk(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, ".gitignore", "*.log\n")
            write(root, "debug.log", "noise\n")
            paths = {path for path, _ in iter_files(root, use_gitignore=False)}
        self.assertIn("debug.log", paths)

    def test_the_ignore_file_itself_is_still_scanned(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, ".gitignore", "*.log\n")
            paths = {path for path, _ in iter_files(root)}
        self.assertIn(".gitignore", paths)


class TestCliIntegration(unittest.TestCase):
    def test_a_secret_in_an_ignored_file_is_not_reported(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, ".gitignore", ".env\n")
            write(root, ".env", f'AWS_KEY="{fixtures.REALISTIC_AWS_KEY_ID}"\n')
            code, output = run(["scan", root])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("No findings", output)

    def test_no_gitignore_surfaces_it_again(self):
        with tempfile.TemporaryDirectory() as root:
            write(root, ".gitignore", ".env\n")
            write(root, ".env", f'AWS_KEY="{fixtures.REALISTIC_AWS_KEY_ID}"\n')
            code, output = run(["scan", root, "--format", "json", "--no-gitignore"])
        self.assertEqual(code, cli.EXIT_FINDINGS)
        paths = {finding["path"] for finding in json.loads(output)["findings"]}
        self.assertIn(".env", paths)


if __name__ == "__main__":
    unittest.main()
