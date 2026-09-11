"""Individual scanners.

Most expose ``scan_files(files) -> list[Finding]`` over ``(path, text)`` pairs.
:mod:`.filenames` is the exception: it works from paths alone, because the files
it is about have no text to read.
"""

from . import (
    allowlist,
    compose,
    dockerfiles,
    filenames,
    gitlab,
    kubernetes,
    secrets,
    terraform,
    workflows,
)

__all__ = [
    "allowlist",
    "compose",
    "dockerfiles",
    "filenames",
    "gitlab",
    "kubernetes",
    "secrets",
    "terraform",
    "workflows",
]
