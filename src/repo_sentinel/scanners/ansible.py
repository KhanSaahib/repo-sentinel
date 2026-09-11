"""Audit Ansible playbooks and task files.

Ansible is where a decision made once gets applied to every host, which cuts
both ways: a task that skips certificate verification skips it fleet-wide, and
a file mode written as 0777 is world-writable on every machine the play
touches.

Three rules, all narrow on purpose. Ansible's own idioms make most "insecure"
patterns ambiguous -- ``become: yes`` is how the tool works, and templating a
variable into a shell command is usually fine because the variable came from
the inventory rather than from a stranger. What is left is the small set of
things that are wrong wherever they appear.

Playbooks are recognised by shape, since Ansible imposes no naming convention
worth trusting: a document that is a list of mappings carrying plays or tasks.
The vocabulary check matters -- a list of mappings is also what a Compose
override, a Kustomize patch and half of CI configuration look like.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Iterator

from .. import suppression, yamlish
from ..findings import Confidence, Finding, Severity

_YAML_SUFFIXES = (".yaml", ".yml")

#: Keys that only appear in a play.
_PLAY_KEYS = frozenset({"hosts", "tasks", "roles", "pre_tasks", "post_tasks", "handlers"})

#: Modules common enough that seeing one means this is a task file. Short list
#: on purpose: a wrong guess here scans a file with the wrong vocabulary, and
#: the cost of missing an unusual playbook is one unscanned file.
_MODULES = frozenset(
    {
        "command", "shell", "copy", "file", "template", "get_url", "uri", "script",
        "package", "apt", "yum", "dnf", "service", "systemd", "user", "group",
        "lineinfile", "blockinfile", "unarchive", "git", "pip", "docker_container",
        "include_tasks", "import_tasks", "set_fact", "debug", "stat", "mount",
    }
)

#: Task keywords that are not modules, so their presence does not identify a
#: task on its own but their absence does not disqualify one either.
_TASK_KEYWORDS = frozenset(
    {"name", "become", "when", "with_items", "loop", "register", "tags", "notify", "vars"}
)

_VERIFY_KEYS = ("validate_certs", "validate_certificate", "verify_ssl", "allow_insecure")
_MODE_KEYS = ("mode",)
#: A file mode that gives every account on the machine write access.
_WORLD_WRITABLE = re.compile(r"^0?[0-7][0-7][2367]$")
_HTTP_URL = re.compile(r"^http://(?P<host>[\w.-]+)", re.IGNORECASE)
#: Left by template flattening; see :func:`yamlish.strip_templates`.
_LOCAL_HOSTS = ("localhost", "127.0.0.1")


def is_yaml_path(path: str) -> bool:
    return posixpath.basename(path.replace("\\", "/")).lower().endswith(_YAML_SUFFIXES)


def is_ansible(document: "yamlish.Node") -> bool:
    """True for a document that is a list of plays or of tasks."""
    if not document.is_list:
        return False
    entries = [entry for entry in document.entries() if entry.is_map]
    if not entries:
        return False
    vocabulary = {key for entry in entries for key, _ in entry.items()}
    if vocabulary & _PLAY_KEYS:
        return True
    modules = {key.split(".")[-1] for key in vocabulary}
    return bool(modules & _MODULES) and bool(vocabulary & _TASK_KEYWORDS)


#: Where a play keeps its tasks, and where a block keeps more of them.
_TASK_SECTIONS = ("tasks", "pre_tasks", "post_tasks", "handlers", "block", "rescue", "always")


def _tasks(document: "yamlish.Node") -> "Iterator[yamlish.Node]":
    """Every task in a document, whether it is a play's or a task file's.

    Returned as the *task* mapping rather than the module's argument mapping,
    so that a finding can say which task it is about. The settings a rule
    reads may sit one level deeper -- ``get_url:`` then ``validate_certs:`` --
    which is what :func:`_settings` is for.
    """
    for entry in document.entries():
        if not entry.is_map:
            continue
        sections = []
        for name in _TASK_SECTIONS:
            section = entry.get(name)
            if section is not None:
                sections.append(section)
        if not sections:
            yield entry  # a task file: the entry is the task
            continue
        for section in sections:
            for task in section.entries() if section.is_list else ():
                if task.is_map:
                    yield task
                    yield from _nested_tasks(task)


def _nested_tasks(task: "yamlish.Node") -> "Iterator[yamlish.Node]":
    """Tasks inside a block, rescue or always, which nest arbitrarily."""
    for section in _TASK_SECTIONS:
        node = task.get(section)
        if node is None or not node.is_list:
            continue
        for nested in node.entries():
            if nested.is_map:
                yield nested
                yield from _nested_tasks(nested)


def _settings(task: "yamlish.Node") -> "Iterator[tuple[str, yamlish.Node]]":
    """Every key a task carries, including inside its module's arguments.

    Stops at the sections that hold other tasks. Walking into a ``block`` would
    report its children's settings against the block as well as against the
    task they belong to, which is the same finding twice with the wrong name on
    one of them.
    """
    for key, node in task.items():
        yield key, node
        if key not in _TASK_SECTIONS:
            yield from _descend(node)


def _descend(node: "yamlish.Node") -> "Iterator[tuple[str, yamlish.Node]]":
    for key, child in node.items():
        yield key, child
        yield from _descend(child)
    for entry in node.entries():
        yield from _descend(entry)


def _describe(task: "yamlish.Node") -> str:
    name = task.get("name")
    return f"Task {name.text.strip().strip(chr(34) + chr(39))!r}" if name else "A task"


def _check_verification(path: str, task: "yamlish.Node") -> "Iterator[Finding]":
    """AN001: certificate verification switched off, fleet-wide."""
    for key, node in _settings(task):
        if key not in _VERIFY_KEYS or not node.falsy():
            continue
        yield Finding(
            rule_id="AN001",
            severity=Severity.HIGH,
            title=f"{_describe(task)} skips certificate verification",
            path=path,
            line=node.line,
            evidence=f"{key}: {node.text}",
            remediation=(
                "Ansible applies this to every host the play touches, so it is "
                "not one unverified download but all of them. Trust the "
                "certificate properly: put the CA on the hosts, or point "
                "ca_path at it."
            ),
        )


def _check_modes(path: str, task: "yamlish.Node") -> "Iterator[Finding]":
    """AN002: a file mode that lets any account on the host rewrite the file."""
    for key, node in _settings(task):
        if key not in _MODE_KEYS:
            continue
        mode = node.text.strip().strip("\"'")
        if not _WORLD_WRITABLE.match(mode):
            continue
        yield Finding(
            rule_id="AN002",
            severity=Severity.MEDIUM,
            title=f"{_describe(task)} sets a world-writable mode ({mode})",
            path=path,
            line=node.line,
            evidence=f"mode: {mode}",
            remediation=(
                "Any account on the host can rewrite this, which for a script "
                "or a unit file means any account can decide what runs next. "
                "Give the owner write access and nobody else."
            ),
        )


def _check_plaintext_fetch(path: str, task: "yamlish.Node") -> "Iterator[Finding]":
    """AN003: fetching over plain HTTP, usually to install something."""
    for key, node in _settings(task):
        if key not in ("url", "src", "repo"):
            continue
        value = node.text.strip().strip("\"'")
        match = _HTTP_URL.match(value)
        if match is None or match.group("host").lower() in _LOCAL_HOSTS:
            continue
        # The host may be a template -- "http://{{ hue_ip }}/api" -- in which
        # case naming it says nothing. The scheme is literal either way, which
        # is what the rule is about.
        host = match.group("host")
        where = "" if yamlish.TEMPLATE_PLACEHOLDER in host else f" from {host}"
        yield Finding(
            rule_id="AN003",
            severity=Severity.MEDIUM,
            title=f"{_describe(task)} fetches{where} over plain HTTP",
            path=path,
            line=node.line,
            evidence=f"{key}: {value[:80]}",
            remediation=(
                "Anything on the path can change what arrives, and what "
                "arrives is usually about to be installed or executed. Use "
                "https, and add a checksum if the module takes one."
            ),
            confidence=Confidence.MEDIUM,
        )


_RULES = (_check_verification, _check_modes, _check_plaintext_fetch)


def scan_playbook(
    path: str, text: str, marks: "suppression.Suppressions | None" = None
) -> "list[Finding]":
    """Run every Ansible rule against one playbook or task file."""
    marks = suppression.parse(text) if marks is None else marks
    if marks.whole_file:
        return []

    # Every playbook and task file is a list, so a document with no list item
    # in it cannot be one. The check costs nothing and skips the parse.
    if "\n-" not in text and not text.lstrip().startswith("-"):
        return []

    source = yamlish.strip_templates(text) if "{{" in text else text
    findings: "list[Finding]" = []
    for document in yamlish.parse(source):
        if not is_ansible(document):
            continue
        for task in _tasks(document):
            for rule in _RULES:
                findings.extend(rule(path, task))
    return marks.filter_findings(findings)


def scan_files(
    files: "Iterable[tuple[str, str]]", *, honour_markers: bool = True
) -> "list[Finding]":
    """Scan ``(path, text)`` pairs, ignoring anything that is not Ansible."""
    markers = None if honour_markers else suppression.NONE
    return [
        finding
        for path, text in files
        if is_yaml_path(path)
        for finding in scan_playbook(path, text, markers)
    ]
