"""Decide which files are worth scanning."""

from __future__ import annotations

import dataclasses
import fnmatch
import os
from collections.abc import Iterable, Iterator

from .gitignore import GitIgnoreFile, GitIgnoreStack

#: Directories that hold generated or third-party code. Scanning them produces
#: noise nobody will act on, and vendored trees can be enormous.
DEFAULT_EXCLUDES: tuple[str, ...] = (
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    "dist",
    "build",
    "target",
    "vendor",
    "site-packages",
    ".terraform",
)

#: Files above this size are almost certainly data, not source.
MAX_FILE_BYTES = 2 * 1024 * 1024

#: Extensions that never contain reviewable text.
BINARY_SUFFIXES: frozenset[str] = frozenset(
    """
    .png .jpg .jpeg .gif .bmp .ico .webp .tif .tiff .svgz
    .pdf .zip .gz .bz2 .xz .7z .tar .rar .jar .war
    .exe .dll .so .dylib .bin .o .a .class .pyc .pyo .wasm
    .mp3 .mp4 .avi .mov .mkv .wav .flac .ogg
    .ttf .otf .woff .woff2 .eot
    .db .sqlite .sqlite3 .parquet .pkl .npy .npz
    """.split()
)


def is_probably_binary(chunk: bytes) -> bool:
    """A NUL byte in the first block is the classic binary tell."""
    return b"\x00" in chunk


@dataclasses.dataclass(frozen=True)
class Entry:
    """One file the walk reached, whether or not its contents were read.

    ``text`` is None for a file that was skipped -- a binary, something over
    the size limit, something unreadable. The path is still reported, because
    a name can be a finding on its own: nothing inside ``id_rsa`` or a
    ``.p12`` keystore is text, and a scanner that only ever sees text would
    never mention either of them.
    """

    path: str
    text: "str | None" = None

    @property
    def readable(self) -> bool:
        return self.text is not None


def iter_files(
    root: str,
    excludes: tuple[str, ...] = DEFAULT_EXCLUDES,
    max_bytes: int = MAX_FILE_BYTES,
    *,
    use_gitignore: bool = True,
) -> Iterator[tuple[str, str]]:
    """Yield ``(relative_path, text)`` for every scannable file under ``root``."""
    for entry in walk(root, excludes, max_bytes, use_gitignore=use_gitignore):
        if entry.text is not None:
            yield entry.path, entry.text


def walk(
    root: str,
    excludes: tuple[str, ...] = DEFAULT_EXCLUDES,
    max_bytes: int = MAX_FILE_BYTES,
    *,
    use_gitignore: bool = True,
    unreadable: "list[str] | None" = None,
) -> "Iterator[Entry]":
    """Yield an :class:`Entry` for every file under ``root`` worth considering.

    Paths are yielded with forward slashes so reports read the same on every
    platform. A file that cannot be read as text -- a binary, something over
    the size limit, something the process has no permission for -- is yielded
    with no text rather than raising or vanishing: a scanner that dies on one
    permission error is useless in CI, and a file that silently disappears from
    the walk is one the name rules never get to see.

    Pass ``unreadable`` to learn what the walk could not open -- a directory
    without permission, a file that vanished mid-scan. Those are skipped
    either way, because a scanner that dies on one permission error is useless
    in CI, but skipping them silently means a tree can be reported clean when
    most of it was never read.

    With ``use_gitignore`` the walk honours every ``.gitignore`` in the tree,
    each governing its own subtree. Set it to ``False`` to audit what git was
    told to hide - useful when you suspect an ignore rule was added to silence
    this scanner rather than to keep a build artifact out of history.
    """
    root = os.path.abspath(root)

    if os.path.isfile(root):
        yield Entry(os.path.basename(root), _read_text(root, max_bytes, unreadable))
        return

    # Each directory inherits the stack of its parent, so rules are consulted
    # outermost first and an entry is dropped as soon as its parent is visited.
    stacks: dict[str, GitIgnoreStack] = {root: GitIgnoreStack()}

    def note(error: OSError) -> None:
        if unreadable is not None:
            unreadable.append(_relative_dir(str(error.filename or root), root).rstrip("/"))

    for dirpath, dirnames, filenames in os.walk(root, onerror=note):
        stack = stacks.pop(dirpath, GitIgnoreStack())
        prefix = _relative_dir(dirpath, root)

        if use_gitignore and ".gitignore" in filenames:
            rules = GitIgnoreFile.load(os.path.join(dirpath, ".gitignore"), prefix)
            if rules is not None:
                stack = stack.push(rules)

        kept: list[str] = []
        for name in sorted(dirnames):
            if any(fnmatch.fnmatch(name, pattern) for pattern in excludes):
                continue
            # An empty stack short-circuits, which also covers use_gitignore=False:
            # nothing is ever pushed in that case, so no path is ever tested.
            if stack and stack.is_ignored(f"{prefix}{name}", True):
                continue
            kept.append(name)
            stacks[os.path.join(dirpath, name)] = stack
        dirnames[:] = kept

        for filename in sorted(filenames):
            absolute = os.path.join(dirpath, filename)
            if any(fnmatch.fnmatch(filename, pattern) for pattern in excludes):
                continue
            relative = f"{prefix}{filename}"
            if stack and stack.is_ignored(relative, False):
                continue
            if os.path.splitext(filename)[1].lower() in BINARY_SUFFIXES:
                yield Entry(relative)
                continue
            yield Entry(relative, _read_text(absolute, max_bytes, unreadable))


def read_listed(
    root: str,
    paths: "Iterable[str]",
    excludes: "tuple[str, ...]" = (),
    max_bytes: int = MAX_FILE_BYTES,
) -> Iterator[tuple[str, str]]:
    """Yield ``(relative_path, text)`` for an explicit list of files.

    This is the walk's opposite number, for the case where something else has
    already decided what to look at -- typically the files a pull request
    touched, fed in from ``git diff --name-only``. A path that no longer exists
    is skipped rather than reported: a diff lists deletions too, and a scanner
    that fails on one is a scanner nobody puts in a pipeline.

    ``.gitignore`` is deliberately not consulted here. The caller named these
    files, and second-guessing an explicit list is how a tool acquires a
    reputation for missing things.
    """
    root = os.path.abspath(root)
    seen: set = set()
    for raw in paths:
        candidate = raw.strip().strip('"')
        if not candidate or candidate.startswith("#"):
            continue
        absolute = candidate if os.path.isabs(candidate) else os.path.join(root, candidate)
        # Normalised before the duplicate check: "a.py" and "./a.py" are the
        # same file, and a diff list produced by two tools can contain both.
        absolute = os.path.normpath(absolute)
        if absolute in seen or not os.path.isfile(absolute):
            continue
        seen.add(absolute)
        relative = os.path.relpath(absolute, root).replace(os.sep, "/")
        name = os.path.basename(absolute)
        if os.path.splitext(name)[1].lower() in BINARY_SUFFIXES:
            continue
        if any(fnmatch.fnmatch(part, pattern) for part in relative.split("/") for pattern in excludes):
            continue
        text = _read_text(absolute, max_bytes)
        if text is not None:
            yield relative, text


def _relative_dir(dirpath: str, root: str) -> str:
    """Slash-separated path of ``dirpath`` under ``root``, with a trailing slash.

    Empty for the root itself, so callers can build a child path by concatenation.
    """
    if os.path.normpath(dirpath) == os.path.normpath(root):
        return ""
    return os.path.relpath(dirpath, root).replace(os.sep, "/") + "/"


def _read_text(
    path: str, max_bytes: int, unreadable: "list[str] | None" = None
) -> "str | None":
    """The file's text, or None when it is too large, binary, or unopenable.

    Only the last of those is worth telling anyone about, which is what
    ``unreadable`` collects: a file over the size limit and a file full of NUL
    bytes are both deliberate skips, and a file the process cannot open is a
    gap in the scan.
    """
    try:
        if os.path.getsize(path) > max_bytes:
            return None
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError:
        if unreadable is not None:
            unreadable.append(path)
        return None
    if is_probably_binary(raw[:8192]):
        return None
    # utf-8-sig rather than utf-8: an editor on Windows writes a byte-order
    # mark, and a leading \ufeff makes the first key of a YAML document
    # something no rule is looking for -- which is a file silently unscanned
    # rather than a file reported clean.
    return raw.decode("utf-8-sig", errors="replace")
