"""Individual scanners.

Most expose ``scan_files(files) -> list[Finding]`` over ``(path, text)`` pairs.
:mod:`.filenames` is the exception: it works from paths alone, because the files
it is about have no text to read.
"""

from . import (
    allowlist,
    ansible,
    azure,
    ci,
    circleci,
    cloudformation,
    compose,
    dependencies,
    dockerfiles,
    filenames,
    gitlab,
    jenkins,
    kubernetes,
    secrets,
    shell,
    terraform,
    workflows,
)

__all__ = [
    "allowlist",
    "ansible",
    "azure",
    "circleci",
    "cloudformation",
    "compose",
    "dependencies",
    "dockerfiles",
    "filenames",
    "gitlab",
    "jenkins",
    "kubernetes",
    "secrets",
    "shell",
    "terraform",
    "workflows",
]
