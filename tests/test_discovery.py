"""The walk: what it reaches, what it reads, and what it only names."""

import os
import tempfile
import unittest

from bluerayscan import discovery


def tree(files):
    root = tempfile.mkdtemp()
    for relative, content in files.items():
        path = os.path.join(root, relative.replace("/", os.sep))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(path, mode) as handle:
            handle.write(content)
    return root


class TestWalk(unittest.TestCase):
    def test_unreadable_files_are_named_but_not_read(self):
        root = tree({"app.py": "x = 1\n", "logo.png": b"\x89PNG\x00binary"})
        entries = {entry.path: entry for entry in discovery.walk(root)}
        self.assertTrue(entries["app.py"].readable)
        self.assertFalse(entries["logo.png"].readable)

    def test_a_binary_file_without_a_known_suffix_is_still_caught(self):
        root = tree({"blob.dat": b"\x00\x01\x02"})
        entry = next(iter(discovery.walk(root)))
        self.assertFalse(entry.readable)

    def test_an_oversized_file_is_named_only(self):
        root = tree({"big.txt": "x" * 100})
        entry = next(iter(discovery.walk(root, max_bytes=10)))
        self.assertFalse(entry.readable)

    def test_a_single_file_can_be_the_root(self):
        root = tree({"app.py": "x = 1\n"})
        entries = list(discovery.walk(os.path.join(root, "app.py")))
        self.assertEqual([entry.path for entry in entries], ["app.py"])

    def test_iter_files_yields_only_what_it_could_read(self):
        root = tree({"app.py": "x = 1\n", "logo.png": b"\x89PNG\x00"})
        self.assertEqual([path for path, _ in discovery.iter_files(root)], ["app.py"])


class TestUnreadablePaths(unittest.TestCase):
    """Skipped either way; the question is whether anybody is told."""

    @unittest.skipIf(
        os.name == "nt",
        "Windows ignores a directory mode of 0, so there is nothing to be denied",
    )
    def test_a_directory_that_cannot_be_opened_is_reported(self):
        import stat

        root = tree({"locked/secret.py": "x = 1\n", "ok.py": "y = 2\n"})
        locked = os.path.join(root, "locked")
        os.chmod(locked, 0)
        try:
            problems = []
            entries = list(discovery.walk(root, unreadable=problems))
        finally:
            os.chmod(locked, stat.S_IRWXU)
        self.assertEqual([entry.path for entry in entries], ["ok.py"])
        self.assertEqual(problems, ["locked"])

    def test_a_file_that_cannot_be_read_is_named_as_the_report_shows_it(self):
        # A dangling symlink is the common case, and a scan that names it
        # /tmp/xyz/repo/a/b among a list of relative paths reads as a bug.
        root = tree({"ok.py": "y = 2\n"})
        os.symlink(os.path.join(root, "gone.py"), os.path.join(root, "link.py"))
        problems = []
        list(discovery.walk(root, unreadable=problems))
        self.assertEqual(problems, ["link.py"])

    def test_a_readable_tree_reports_nothing(self):
        problems = []
        list(discovery.walk(tree({"a.py": "1\n"}), unreadable=problems))
        self.assertEqual(problems, [])

    def test_a_deliberate_skip_is_not_a_problem(self):
        # A binary and an oversized file are decisions, not gaps.
        problems = []
        root = tree({"logo.png": b"\x89PNG\x00", "big.txt": "x" * 100})
        list(discovery.walk(root, max_bytes=10, unreadable=problems))
        self.assertEqual(problems, [])


class TestEncodings(unittest.TestCase):
    def test_a_byte_order_mark_is_not_part_of_the_first_line(self):
        # An editor on Windows writes one, and a leading \ufeff makes the
        # first key of a YAML document something no rule is looking for --
        # which is a file silently unscanned rather than a file reported clean.
        root = tree({"pod.yaml": "\ufeffapiVersion: v1\n".encode("utf-8")})
        entry = next(iter(discovery.walk(root)))
        self.assertTrue(entry.text.startswith("apiVersion"))

    def test_undecodable_bytes_do_not_stop_a_scan(self):
        root = tree({"mixed.txt": b"caf\xe9 latte\n"})
        entry = next(iter(discovery.walk(root)))
        self.assertTrue(entry.readable)
        self.assertIn("caf", entry.text)


class TestReadListed(unittest.TestCase):
    def paths(self, root, listing, **kwargs):
        return [path for path, _ in discovery.read_listed(root, listing, **kwargs)]

    def test_relative_and_absolute_paths_both_work(self):
        root = tree({"a.py": "1\n", "pkg/b.py": "2\n"})
        listing = ["a.py", os.path.join(root, "pkg", "b.py")]
        self.assertEqual(sorted(self.paths(root, listing)), ["a.py", "pkg/b.py"])

    def test_blanks_comments_and_quotes_are_tolerated(self):
        root = tree({"a.py": "1\n"})
        self.assertEqual(self.paths(root, ["", "  ", "# a comment", '"a.py"']), ["a.py"])

    def test_a_path_listed_twice_is_read_once(self):
        root = tree({"a.py": "1\n"})
        self.assertEqual(self.paths(root, ["a.py", "a.py", "./a.py"]), ["a.py"])

    def test_binaries_and_excludes_are_still_honoured(self):
        root = tree({"logo.png": b"\x89PNG", "vendor/x.py": "1\n", "a.py": "1\n"})
        listed = self.paths(root, ["logo.png", "vendor/x.py", "a.py"], excludes=("vendor",))
        self.assertEqual(listed, ["a.py"])

    def test_a_missing_path_is_skipped(self):
        root = tree({"a.py": "1\n"})
        self.assertEqual(self.paths(root, ["a.py", "deleted.py"]), ["a.py"])


class TestBinaryDetection(unittest.TestCase):
    def test_a_nul_byte_is_the_tell(self):
        self.assertTrue(discovery.is_probably_binary(b"text\x00more"))
        self.assertFalse(discovery.is_probably_binary(b"just text"))


if __name__ == "__main__":
    unittest.main()
