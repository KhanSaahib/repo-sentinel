"""Audit Docker Compose files for services that are not really contained.

Compose is where a container's isolation gets negotiated away, usually for a
good reason during development and then permanently by accident. A bind mount
of the Docker socket so the CI runner can build images, ``network_mode: host``
so a service can reach something on the host, ``privileged: true`` because a
device would not appear otherwise -- each of them is one line, none of them is
flagged by anything in the normal review path, and all of them survive the copy
of the file into production.

The port rule is the one people are most often surprised by. ``5432:5432``
publishes PostgreSQL on every interface the host has, firewall permitting, and
on a cloud instance that means the internet. ``127.0.0.1:5432:5432`` is the same
line with the mistake removed.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Iterator

from .. import suppression, wellknown, yamlish
from ..findings import Confidence, Finding, Severity

_YAML_SUFFIXES = (".yaml", ".yml")

#: ``[HOST_IP:]HOST_PORT:CONTAINER_PORT[/PROTOCOL]`` in its short form.
_PORT_MAPPING = re.compile(
    r"""^(?:(?P<ip>\[[0-9a-f:]+\]|[\d.]+):)?
     (?P<host>\d+(?:-\d+)?):(?P<container>\d+(?:-\d+)?)(?:/\w+)?$""",
    re.VERBOSE | re.IGNORECASE,
)
_IMAGE_TAG = re.compile(r"^(?P<image>[^\s@]+?)(?::(?P<tag>[^:/@]+))?(?:@(?P<digest>sha256:\w+))?$")
_UNCONFINED = re.compile(r"(?:seccomp|apparmor)[:=]unconfined", re.IGNORECASE)

#: Addresses that publish a port to everything the host can be reached on.
_ALL_INTERFACES = ("", "0.0.0.0", "::", "[::]")


def is_yaml_path(path: str) -> bool:
    return posixpath.basename(path.replace("\\", "/")).lower().endswith(_YAML_SUFFIXES)


def is_compose(document: "yamlish.Node") -> bool:
    """True for a document that describes Compose services.

    By content rather than filename: a stack file may be called anything, and
    ``services:`` at the root of a document with no ``apiVersion`` is what
    Compose actually is. The apiVersion exclusion keeps Kubernetes manifests --
    which also have services, of a different sort -- out of this scanner.
    """
    if document.get("apiVersion") is not None:
        return False
    services = document.get("services")
    return services is not None and services.is_map


def _services(document: "yamlish.Node") -> "Iterator[tuple[str, yamlish.Node]]":
    services = document.get("services")
    if services is None:
        return
    for name, service in services.items():
        if service.is_map:
            yield name, service


def _list_values(node: "yamlish.Node") -> "list[tuple[str, int]]":
    """Entries of a list, whether written as a block or as inline flow text."""
    if node.is_list:
        return [(entry.text.strip().strip("\"'"), entry.line) for entry in node.entries()]
    text = node.text.strip()
    if text.startswith("[") and text.endswith("]"):
        return [
            (part.strip().strip("\"'"), node.line)
            for part in text[1:-1].split(",")
            if part.strip()
        ]
    return [(text.strip("\"'"), node.line)] if text else []


def _check_privileged(path: str, name: str, service: "yamlish.Node") -> "Iterator[Finding]":
    """DC001: the flag that turns a container into a process with a filesystem."""
    flag = service.get("privileged")
    if flag is None or not flag.truthy():
        return
    yield Finding(
        rule_id="DC001",
        severity=Severity.CRITICAL,
        title=f"Service {name!r} runs privileged",
        path=path,
        line=flag.line,
        evidence="privileged: true",
        remediation=(
            "A privileged container can reach the host's devices and kernel "
            "interfaces, so escaping it is not an exploit but a feature. Add "
            "the specific device or capability the service needs instead."
        ),
    )


def _check_host_namespaces(path: str, name: str, service: "yamlish.Node") -> "Iterator[Finding]":
    """DC003: sharing the host's network, processes or shared memory."""
    checks = (
        ("network_mode", "host", "the host's network stack, firewall rules and localhost services"),
        ("pid", "host", "the host's process table"),
        ("ipc", "host", "the host's shared memory"),
        ("userns_mode", "host", "the host's user namespace, undoing uid remapping"),
    )
    for key, dangerous, consequence in checks:
        node = service.get(key)
        if node is None or node.text.strip().strip("\"'").lower() != dangerous:
            continue
        yield Finding(
            rule_id="DC003",
            severity=Severity.HIGH,
            title=f"Service {name!r} shares the host's {key.replace('_mode', '')} namespace",
            path=path,
            line=node.line,
            evidence=f"{key}: host",
            remediation=(
                f"This exposes {consequence}. Publish the ports the service "
                "needs instead, and keep it on its own network."
            ),
        )


def _check_mounts(path: str, name: str, service: "yamlish.Node") -> "Iterator[Finding]":
    """DC002: a bind mount that reaches out of the container."""
    volumes = service.get("volumes")
    if volumes is None:
        return
    for entry, line in _list_values(volumes):
        source = entry.split(":")[0]
        if not source.startswith(("/", "~")):
            continue  # a named volume, which is the container's own storage
        if not wellknown.is_critical_host_path(source):
            continue
        yield Finding(
            rule_id="DC002",
            severity=Severity.CRITICAL,
            title=f"Service {name!r} bind-mounts {source}",
            path=path,
            line=line,
            evidence=entry,
            remediation=(
                "Anything that can talk to the container runtime socket can "
                "start a privileged container mounting the host's root, so "
                "this grants the host. Use a named volume, or a narrower path, "
                "and add :ro where the service only reads."
            ),
        )


def _check_ports(path: str, name: str, service: "yamlish.Node") -> "Iterator[Finding]":
    """DC005: a sensitive port published on every interface the host has."""
    ports = service.get("ports")
    if ports is None:
        return
    for entry, line in _list_values(ports):
        match = _PORT_MAPPING.match(entry)
        if match is None:
            continue
        if (match.group("ip") or "").strip("[]") not in _ALL_INTERFACES:
            continue
        low, _, high = match.group("host").partition("-")
        exposed = wellknown.services_in_range(int(low), int(high or low))
        if not exposed:
            continue
        yield Finding(
            rule_id="DC005",
            severity=Severity.HIGH,
            title=f"Service {name!r} publishes {', '.join(exposed)} on every interface",
            path=path,
            line=line,
            evidence=f"ports: {entry}",
            remediation=(
                "A short port mapping binds 0.0.0.0, which on a cloud host is "
                "the internet, firewall permitting. Write 127.0.0.1:"
                f"{low}:{match.group('container')} if this is only for you, or "
                "reach the service over the compose network by its name."
            ),
        )


def _check_capabilities(path: str, name: str, service: "yamlish.Node") -> "Iterator[Finding]":
    """DC004: capabilities and confinement given back by hand."""
    added = service.get("cap_add")
    if added is not None:
        granted = {value.upper() for value, _ in _list_values(added)}
        risky = sorted(granted & wellknown.DANGEROUS_CAPABILITIES)
        if risky:
            yield Finding(
                rule_id="DC004",
                severity=Severity.HIGH,
                title=f"Service {name!r} adds capability {', '.join(risky)}",
                path=path,
                line=added.line,
                evidence=f"cap_add: {', '.join(risky)}",
                remediation=(
                    "SYS_ADMIN and ALL are close to privileged. Drop what you "
                    "can with cap_drop and add back only what the process "
                    "actually fails without."
                ),
            )

    options = service.get("security_opt")
    if options is None:
        return
    for value, line in _list_values(options):
        if not _UNCONFINED.search(value):
            continue
        yield Finding(
            rule_id="DC004",
            severity=Severity.HIGH,
            title=f"Service {name!r} runs unconfined ({value})",
            path=path,
            line=line,
            evidence=f"security_opt: {value}",
            remediation=(
                "The default seccomp and AppArmor profiles block the syscalls "
                "container escapes are built from. If one of them breaks the "
                "service, write a profile rather than removing the profile."
            ),
        )


def _check_images(path: str, name: str, service: "yamlish.Node") -> "Iterator[Finding]":
    """DC006: an image reference that can mean something else tomorrow."""
    image = service.get("image")
    if image is None:
        return
    reference = image.text.strip().strip("\"'")
    if wellknown.is_interpolated(reference):
        return  # "${IMAGE_TAG}" is decided elsewhere, so its shape says nothing
    match = _IMAGE_TAG.match(reference)
    if match is None or match.group("digest"):
        return
    tag = match.group("tag")
    if tag is not None and tag != "latest":
        return
    yield Finding(
        rule_id="DC006",
        severity=Severity.LOW,
        title=f"Service {name!r} pulls {reference}, which floats",
        path=path,
        line=image.line,
        evidence=f"image: {reference}",
        remediation=(
            "An unpinned tag means the stack that worked yesterday is not the "
            "stack that comes up today. Pin a version tag."
        ),
        confidence=Confidence.MEDIUM,
    )


_RULES = (
    _check_privileged,
    _check_mounts,
    _check_host_namespaces,
    _check_capabilities,
    _check_ports,
    _check_images,
)


def scan_compose(
    path: str, text: str, marks: "suppression.Suppressions | None" = None
) -> "list[Finding]":
    """Run every Compose rule against one stack file."""
    marks = suppression.parse(text) if marks is None else marks
    if marks.whole_file:
        return []

    findings: "list[Finding]" = []
    for document in yamlish.parse(text):
        if not is_compose(document):
            continue
        for name, service in _services(document):
            for rule in _RULES:
                findings.extend(rule(path, name, service))
    return marks.filter_findings(findings)


def scan_files(
    files: "Iterable[tuple[str, str]]", *, honour_markers: bool = True
) -> "list[Finding]":
    """Scan ``(path, text)`` pairs, ignoring anything that is not a stack file."""
    markers = None if honour_markers else suppression.NONE
    return [
        finding
        for path, text in files
        if is_yaml_path(path)
        for finding in scan_compose(path, text, markers)
    ]
