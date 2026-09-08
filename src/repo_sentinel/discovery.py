"""Decide which files are worth scanning."""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Iterator

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


def iter_files(
    root: str,
    excludes: tuple[str, ...] = DEFAULT_EXCLUDES,
    max_bytes: int = MAX_FILE_BYTES,
) -> Iterator[tuple[str, str]]:
    """Yield ``(relative_path, text)`` for every scannable file under ``root``.

    Paths are yielded with forward slashes so reports read the same on every
    platform. Unreadable files are skipped rather than raising: a scanner that
    dies on one permission error is useless in CI.
    """
    root = os.path.abspath(root)

    if os.path.isfile(root):
        text = _read_text(root, max_bytes)
        if text is not None:
            yield os.path.basename(root), text
        return

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            name
            for name in dirnames
            if not any(fnmatch.fnmatch(name, pattern) for pattern in excludes)
        )
        for filename in sorted(filenames):
            absolute = os.path.join(dirpath, filename)
            if os.path.splitext(filename)[1].lower() in BINARY_SUFFIXES:
                continue
            if any(fnmatch.fnmatch(filename, pattern) for pattern in excludes):
                continue
            text = _read_text(absolute, max_bytes)
            if text is None:
                continue
            relative = os.path.relpath(absolute, root).replace(os.sep, "/")
            yield relative, text


def _read_text(path: str, max_bytes: int) -> str | None:
    try:
        if os.path.getsize(path) > max_bytes:
            return None
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError:
        return None
    if is_probably_binary(raw[:8192]):
        return None
    return raw.decode("utf-8", errors="replace")
