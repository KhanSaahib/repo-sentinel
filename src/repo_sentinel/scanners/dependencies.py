"""Audit dependency manifests for how code gets into the build.

Everything else in this tool asks what a repository contains. This asks where
the rest of it comes from, which is the question a dependency manifest answers
and nobody reads: a registry fetched over plain HTTP, certificate verification
switched off to make an install work, a dependency pulled from a branch that
somebody can move, and an install-time script that downloads code and runs it.

All four are ordinary-looking lines in files that get skimmed. All four mean
that what ends up in the build is decided by something other than the
repository -- by whoever controls that host, that branch, or that URL today.

The formats covered are the ones almost every repository has one of: npm's
``package.json`` and ``.npmrc``, pip's ``requirements.txt`` and ``pip.conf``,
Bundler's ``Gemfile``, and Maven's ``pom.xml``. The checks are deliberately
shallow -- this is not a resolver, and it does not know what a version means --
because the mistakes worth reporting are visible in the text.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Iterator

from .. import jsonish, suppression, wellknown
from ..findings import Confidence, Finding, Severity

#: Hosts reached over plain HTTP. Localhost is excluded: a registry on the
#: loopback interface is a development detail, not a supply chain.
_HTTP_URL = re.compile(r"http://(?P<host>[\w.-]+(?::\d+)?)", re.IGNORECASE)
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]", "0.0.0.0")

#: Switches that turn off certificate verification, across package managers.
_VERIFICATION_OFF = re.compile(
    r"strict-ssl\s*=\s*false"
    # pip spells it "--trusted-host" on a command line and "trusted-host ="
    # in pip.conf, and the config form is the one that outlives the problem.
    r"|--trusted-host\b|^\s*trusted-host\s*="
    r"|--no-check-certificate\b"
    r"|(?:^|\s)(?:curl\b[^|;]*\s)(?:-k|--insecure)\b"
    r"|verify\s*=\s*(?:false|no|off)"
    r"|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0",
    re.IGNORECASE | re.MULTILINE,
)

#: The lifecycle scripts a package manager runs without being asked, which is
#: what makes a download inside one different from a download inside "build".
#: npm's are first; Composer's are the ones after the blank line.
_INSTALL_SCRIPTS = frozenset(
    {
        "preinstall", "install", "postinstall", "prepare", "prepublish", "prepack",
        "pre-install-cmd", "post-install-cmd", "pre-update-cmd", "post-update-cmd",
        "post-autoload-dump",
    }
)

#: A dependency that is a place rather than a version.
_VCS_DEPENDENCY = re.compile(r"^(?:git\+|git:|https?:|github:|gitlab:|bitbucket:)", re.IGNORECASE)
#: What a pin looks like: a commit or a version, after a "#" as npm writes it
#: or after an "@" as pip does. pip puts its "#egg=" fragment after the ref, so
#: the "@" form cannot be anchored to the end of the line.
_PINNED_REF = re.compile(r"#(?:[0-9a-f]{7,40}|v?\d+\.\d+[\w.-]*)$", re.IGNORECASE)
_PINNED_AT = re.compile(r"@(?:[0-9a-f]{7,40}|v?\d+\.\d+[\w.-]*)(?:#|$)", re.IGNORECASE)

_MANIFESTS = {
    "package.json": "npm",
    "pyproject.toml": "pip",
    "cargo.toml": "cargo",
    ".npmrc": "npm",
    "requirements.txt": "pip",
    "pip.conf": "pip",
    "pip.ini": "pip",
    "gemfile": "bundler",
    "pom.xml": "maven",
    "composer.json": "composer",
}


def manifest_kind(path: str) -> "str | None":
    """Which package manager a file belongs to, or None."""
    name = posixpath.basename(path.replace("\\", "/")).lower()
    if name in _MANIFESTS:
        return _MANIFESTS[name]
    if name.startswith("requirements") and name.endswith(".txt"):
        return "pip"
    return None


def _line_of(document: "jsonish.Node | None", *path: str) -> int:
    """The line a key sits on, or 1 when the document could not be read.

    Searching the raw text for a quoted key finds the wrong one whenever the
    same name appears twice -- "install" in both scripts and dependencies, say
    -- so the reader that knows the structure answers this instead.
    """
    if document is None:
        return 1
    node = document.get(*path)
    return node.line if node is not None else 1


def _check_plaintext_sources(path: str, kind: str, text: str) -> "Iterator[Finding]":
    """SC001: a package source fetched over a channel anyone can rewrite."""
    seen: "set[str]" = set()
    for number, line in enumerate(text.splitlines(), start=1):
        if suppression.marker_scope(line) is not None:
            continue
        for match in _HTTP_URL.finditer(line):
            host = match.group("host").split(":")[0].lower()
            if host in _LOCAL_HOSTS or host in seen:
                continue
            if not _looks_like_a_source(kind, line):
                continue
            seen.add(host)
            yield Finding(
                rule_id="SC001",
                severity=Severity.HIGH,
                title=f"{kind} fetches packages from {host} over plain HTTP",
                path=path,
                line=number,
                evidence=line.strip()[:120],
                remediation=(
                    "Anything on the path can replace what this downloads, and "
                    "a package manager runs what it downloads. Use https, and "
                    "if the host has no certificate, that is the finding."
                ),
            )


#: Fields of a JSON manifest that name somewhere packages are fetched from.
#: Everything else that holds a URL -- repository, bugs, homepage, funding --
#: is metadata about the project, and npm has never downloaded anything from
#: it. Reporting "repository": "http://github.com/..." as a supply chain is a
#: false positive fourteen times over in one repository, which is how it was
#: found.
_JSON_SOURCES = (
    ("publishConfig", "registry"),
    ("config", "registry"),
)


def _check_json_sources(path: str, kind: str, text: str) -> "Iterator[Finding]":
    """SC001 for the manifests that are JSON, where the field can be checked."""
    document = jsonish.parse(text)
    if document is None or not document.is_map:
        return

    candidates = [document.get(*keys) for keys in _JSON_SOURCES]
    repositories = document.get("repositories")
    if repositories is not None and repositories.is_list:
        candidates.extend(entry.get("url") for entry in repositories.entries())

    for node in candidates:
        if node is None or not node.text:
            continue
        match = _HTTP_URL.match(node.text.strip())
        if match is None or match.group("host").split(":")[0].lower() in _LOCAL_HOSTS:
            continue
        yield Finding(
            rule_id="SC001",
            severity=Severity.HIGH,
            title=f"{kind} fetches packages from {match.group('host')} over plain HTTP",
            path=path,
            line=node.line,
            evidence=node.text.strip()[:120],
            remediation=(
                "Anything on the path can replace what this downloads, and a "
                "package manager runs what it downloads. Use https."
            ),
        )


def _looks_like_a_source(kind: str, line: str) -> bool:
    """True when an http:// URL on this line is somewhere packages come from.

    A link in a description or a licence URL is not a supply chain; a registry,
    an index, a repository or a dependency is. The distinction is the whole
    difference between a rule people keep and one they switch off.
    """
    lowered = line.lower()
    markers = (
        "registry", "index-url", "extra-index", "repository", "source", "mirror",
        "resolved", "url", "dist", "@", "gem ", "find-links",
    )
    if kind == "maven":
        return "<url>" in lowered or "<repository" in lowered
    return any(marker in lowered for marker in markers)


_TOML_SECTION = re.compile(r"^\s*\[\[?(?P<name>[^\]\[]+)\]\]?\s*$")
_TOML_KEY = re.compile(r"^\s*(?P<key>[\w.\"'-]+)\s*=\s*(?P<value>.+?)\s*$")

#: TOML tables that name somewhere packages are fetched from. A URL anywhere
#: else in a pyproject is metadata -- the homepage, the issue tracker, the
#: documentation -- and reporting those is the mistake this scanner already
#: made once, in npm's manifest, fourteen times in one repository.
_TOML_SOURCE_SECTIONS = (
    "tool.poetry.source",
    "tool.poetry.repositories",
    "tool.uv.index",
    "tool.pdm.source",
    "source",       # Cargo: [source.crates-io], [source.mirror]
    "registries",   # Cargo: [registries.internal]
)
#: Keys that name a source wherever they appear, because nothing else is
#: called this.
_TOML_SOURCE_KEYS = ("index-url", "extra-index-url", "registry", "index")
#: ...and keys that only mean a source inside one of the tables above.
_TOML_SCOPED_KEYS = ("url",)

#: A reference that stays where it is. A branch does not.
_TOML_PINNED = ("rev", "tag")


def _toml_value(raw: str) -> str:
    return raw.split("#")[0].strip().strip("\"'")


def _check_toml(path: str, kind: str, text: str) -> "Iterator[Finding]":
    """SC001 and SC003 for the two TOML manifests people actually have.

    TOML is read by section rather than by line, because both questions are
    about a table: which one a URL sits in decides whether it is a package
    source, and a git dependency spread over three lines is one dependency.
    There is no TOML parser here -- ``tomllib`` arrived in 3.11 and this runs
    on 3.9 -- so the reader knows headers, keys and nothing else, and a value
    it cannot make sense of produces no finding rather than a wrong one.
    """
    section = ""
    pending: "dict[str, tuple[int, str]]" = {}
    seen_hosts: "set[str]" = set()

    def flush() -> "Iterator[Finding]":
        finding = _toml_git_dependency(path, section, pending)
        if finding is not None:
            yield finding

    for number, line in enumerate(text.splitlines(), start=1):
        if suppression.marker_scope(line) is not None:
            continue
        header = _TOML_SECTION.match(line)
        if header is not None:
            yield from flush()
            section, pending = header.group("name").strip(), {}
            continue

        entry = _TOML_KEY.match(line)
        if entry is None:
            continue
        key = entry.group("key").strip().strip("\"'").lower()
        raw = entry.group("value")

        if key in _TOML_PINNED or key == "git":
            pending[key] = (number, _toml_value(raw))

        source = key in _TOML_SOURCE_KEYS or (
            key in _TOML_SCOPED_KEYS and section.startswith(_TOML_SOURCE_SECTIONS)
        )
        if source:
            match = _HTTP_URL.search(raw)
            host = match.group("host").split(":")[0].lower() if match else ""
            if host and host not in _LOCAL_HOSTS and host not in seen_hosts:
                seen_hosts.add(host)
                yield Finding(
                    rule_id="SC001",
                    severity=Severity.HIGH,
                    title=f"{kind} fetches packages from {host} over plain HTTP",
                    path=path,
                    line=number,
                    evidence=line.strip()[:120],
                    remediation=(
                        "Anything on the path can replace what this downloads, "
                        "and a package manager runs what it downloads. Use "
                        "https, and if the host has no certificate, that is "
                        "the finding."
                    ),
                )

        inline = _inline_git_dependency(path, kind, number, key, raw)
        if inline is not None:
            yield inline

    yield from flush()


def _inline_git_dependency(
    path: str, kind: str, number: int, key: str, raw: str
) -> "Finding | None":
    """``foo = { git = "...", branch = "main" }``, all on one line."""
    value = raw.strip()
    if not value.startswith("{") or "git" not in value:
        return None
    if re.search(r"\b(?:rev|tag)\s*=", value):
        return None
    if not re.search(r"\bgit\s*=", value):
        return None
    return _moving_source(path, key, number, value)


def _toml_git_dependency(
    path: str, section: str, pending: "dict[str, tuple[int, str]]"
) -> "Finding | None":
    """``[dependencies.foo]`` with ``git`` and no ``rev`` or ``tag``."""
    if "git" not in pending or any(key in pending for key in _TOML_PINNED):
        return None
    line, url = pending["git"]
    name = section.rsplit(".", 1)[-1] if section else "dependency"
    return _moving_source(path, name, line, f"git = {url}")


def _moving_source(path: str, name: str, line: int, evidence: str) -> Finding:
    return Finding(
        rule_id="SC003",
        severity=Severity.MEDIUM,
        title=f"Dependency {name!r} comes from a source that can move",
        path=path,
        line=line,
        evidence=evidence[:100],
        remediation=(
            "A git dependency with no rev or tag installs whatever the "
            "default branch holds at build time. Pin it to a commit, or "
            "publish it to a registry."
        ),
        confidence=Confidence.MEDIUM,
    )


_GEM_LINE = re.compile(r"""^\s*gem\s+['"](?P<name>[^'"]+)['"](?P<rest>.*)$""")
_GEM_SOURCE = re.compile(r"\b(?:git|github|gist|bitbucket)\s*:\s*['\"]")
_GEM_PINNED = re.compile(r"\b(?:ref|tag)\s*:\s*['\"]")


def _check_gemfile_dependencies(path: str, text: str) -> "Iterator[Finding]":
    """SC003 for Bundler: a gem from a repository with nothing pinning it.

    ``gem "x", github: "acme/x"`` installs whatever the default branch holds
    the next time the lockfile is regenerated. ``ref:`` and ``tag:`` are the
    two spellings that stop that, and ``branch:`` is not one of them.
    """
    for number, line in enumerate(text.splitlines(), start=1):
        if suppression.marker_scope(line) is not None:
            continue
        entry = _GEM_LINE.match(line)
        if entry is None:
            continue
        rest = entry.group("rest")
        if not _GEM_SOURCE.search(rest) or _GEM_PINNED.search(rest):
            continue
        yield _moving_source(path, entry.group("name"), number, line.strip())


def _check_verification(path: str, kind: str, text: str) -> "Iterator[Finding]":
    """SC004: certificate verification switched off to make an install work."""
    for number, line in enumerate(text.splitlines(), start=1):
        if suppression.marker_scope(line) is not None:
            continue
        if not _VERIFICATION_OFF.search(line):
            continue
        yield Finding(
            rule_id="SC004",
            severity=Severity.HIGH,
            title=f"{kind} is configured to skip certificate verification",
            path=path,
            line=number,
            evidence=line.strip()[:120],
            remediation=(
                "This is usually added to get past one broken certificate and "
                "then never removed, and it disables the only check that a "
                "download came from where it claims. Fix the certificate, or "
                "vendor the artifact."
            ),
        )


def _check_npm_scripts(path: str, text: str) -> "Iterator[Finding]":
    """SC002: an install-time script that downloads code and runs it.

    npm and Composer run these without being asked -- ``npm install`` or
    ``composer install`` is enough -- so a download inside ``postinstall``
    executes on every machine and every CI runner that installs the package,
    which is a different proposition from the same line inside ``build``.

    Composer writes a script as either a string or a list of them, so both
    shapes are read.
    """
    document = jsonish.parse(text)
    if document is None or not document.is_map:
        return
    scripts = document.get("scripts")
    if scripts is None or not scripts.is_map:
        return
    for name, node in scripts.items():
        if name not in _INSTALL_SCRIPTS:
            continue
        for step in node.entries() if node.is_list else (node,):
            command = step.text
            if not command or not wellknown.downloads_and_runs(command):
                continue
            yield Finding(
                rule_id="SC002",
                severity=Severity.HIGH,
                title=f"The {name!r} script downloads a script and runs it",
                path=path,
                line=step.line,
                evidence=command[:120],
                remediation=(
                    "This runs on every install, on every machine, without "
                    "being asked. Whoever controls that URL runs code on all "
                    "of them. Vendor the artifact, or verify a checksum "
                    "before executing it."
                ),
            )


def _check_npm_dependencies(path: str, text: str) -> "Iterator[Finding]":
    """SC003: a dependency that is a place rather than a version."""
    document = jsonish.parse(text)
    if document is None or not document.is_map:
        return
    for section in ("dependencies", "devDependencies", "optionalDependencies", "require", "require-dev"):
        block = document.get(section)
        if block is None or not block.is_map:
            continue
        for name, node in block.items():
            specifier = node.text
            if not specifier or not _VCS_DEPENDENCY.match(specifier):
                continue
            if _PINNED_REF.search(specifier):
                continue
            yield Finding(
                rule_id="SC003",
                severity=Severity.MEDIUM,
                title=f"Dependency {name!r} comes from a source that can move",
                path=path,
                line=node.line,
                evidence=f"{name}: {specifier[:100]}",
                remediation=(
                    "A dependency on a branch or a bare URL installs whatever "
                    "is there at install time. Pin it to a commit or a tag "
                    "(name#<sha>), or publish it to a registry."
                ),
                confidence=Confidence.MEDIUM,
            )


def _check_requirement_urls(path: str, text: str) -> "Iterator[Finding]":
    """SC003 for pip: a requirement fetched from a URL with no hash."""
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if suppression.marker_scope(line) is not None:
            continue
        if not re.search(r"(?:^|@\s*|\s)(?:git\+|https?://)", stripped):
            continue
        if "#sha256=" in stripped or "--hash=" in stripped:
            continue
        if _PINNED_REF.search(stripped) or _PINNED_AT.search(stripped):
            continue
        if wellknown.is_interpolated(stripped):
            continue
        yield Finding(
            rule_id="SC003",
            severity=Severity.MEDIUM,
            title="Requirement is fetched from a URL with nothing pinning it",
            path=path,
            line=number,
            evidence=stripped[:120],
            remediation=(
                "Whatever is at that URL when the build runs is what gets "
                "installed. Add a commit for a VCS requirement, or a "
                "--hash= for an archive, so the build can tell if it changes."
            ),
            confidence=Confidence.MEDIUM,
        )


def scan_manifest(
    path: str, text: str, marks: "suppression.Suppressions | None" = None
) -> "list[Finding]":
    """Run the rules for whichever package manager this file belongs to."""
    kind = manifest_kind(path)
    if kind is None:
        return []

    marks = suppression.parse(text) if marks is None else marks
    if marks.whole_file:
        return []

    name = posixpath.basename(path.replace("\\", "/")).lower()
    if name in ("package.json", "composer.json"):
        # Structure is available here, so use it: a URL in a JSON manifest is
        # only a supply chain when it sits in a field packages come from.
        findings = list(_check_json_sources(path, kind, text))
        findings += _check_npm_scripts(path, text)
        findings += _check_npm_dependencies(path, text)
    elif name.endswith(".toml"):
        findings = list(_check_toml(path, kind, text))
    else:
        findings = list(_check_plaintext_sources(path, kind, text))
        if kind == "pip" and name.startswith("requirement"):
            findings += _check_requirement_urls(path, text)
        if kind == "bundler":
            findings += _check_gemfile_dependencies(path, text)
    findings += _check_verification(path, kind, text)
    return marks.filter_findings(findings)


def scan_files(
    files: "Iterable[tuple[str, str]]", *, honour_markers: bool = True
) -> "list[Finding]":
    """Scan ``(path, text)`` pairs, ignoring anything that is not a manifest."""
    markers = None if honour_markers else suppression.NONE
    return [finding for path, text in files for finding in scan_manifest(path, text, markers)]
