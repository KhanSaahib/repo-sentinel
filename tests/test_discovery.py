"""The walk: what it reaches, what it reads, and what it only names."""

import os
import tempfile
import unittest

from repo_sentinel import discovery


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
