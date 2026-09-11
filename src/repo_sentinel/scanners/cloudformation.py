"""Audit CloudFormation templates for the mistakes Terraform makes too.

The rules here are TF001 to TF005 with AWS's other vocabulary. The mistakes do
not care which tool describes them: a security group admitting 0.0.0.0/0 to
port 22 is the same security group whether it was written in HCL or YAML, and
a repository that uses both should not have to choose which half gets audited.

Both spellings are read. YAML templates go through the YAML reader; JSON ones
go through :mod:`..jsonish`, which produces the same nodes, so the rules below
never learn which they are looking at. That mattered more than it sounds: the
alternative was a second set of rules for JSON, which would have drifted from
these within a release.

Intrinsic functions come through as text, which is the behaviour worth having:
``CidrIp: !Ref AllowedRange`` is a value decided at deploy time, so no rule
should draw a conclusion from it, and none of them do.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Iterator

from .. import jsonish, suppression, wellknown, yamlish
from ..findings import Finding, Severity

_TEMPLATE_SUFFIXES = (".yaml", ".yml", ".json", ".template")

_PUBLIC_ACLS = ("PublicRead", "PublicReadWrite", "AuthenticatedRead")
_PUBLIC_ACCESS_BLOCK = (
    "BlockPublicAcls",
    "BlockPublicPolicy",
    "IgnorePublicAcls",
    "RestrictPublicBuckets",
)
_ENCRYPTION_KEYS = ("StorageEncrypted", "Encrypted", "EncryptionEnabled")
_RESOURCE_TYPE = re.compile(r"^(?:AWS|Alexa|Custom)::")


def is_template_path(path: str) -> bool:
    """True for the extensions a CloudFormation template is written with."""
    return posixpath.basename(path.replace("\\", "/")).lower().endswith(_TEMPLATE_SUFFIXES)


def is_template(document: "yamlish.Node") -> bool:
    """True for a document CloudFormation would accept as a template.

    ``Resources`` alone is not enough -- a Compose file has services and a
    Helm values file can have anything -- so at least one resource has to
    declare a ``Type`` in AWS's namespace.
    """
    resources = document.get("Resources")
    if resources is None or not resources.is_map:
        return False
    if document.get("AWSTemplateFormatVersion") is not None:
        return True
    return any(
        _RESOURCE_TYPE.match((resource.get("Type") or yamlish.Node("", 0)).text.strip("\"'"))
        for _, resource in resources.items()
    )


def _resources(document: "yamlish.Node") -> "Iterator[tuple[str, str, yamlish.Node]]":
    """Yield ``(logical_name, type, node)`` for every declared resource."""
    resources = document.get("Resources")
    if resources is None:
        return
    for name, resource in resources.items():
        if not resource.is_map:
            continue
        yield name, (resource.get("Type") or yamlish.Node("", 0)).text.strip("\"'"), resource


def _entries(node: "yamlish.Node | None") -> "list[yamlish.Node]":
    return list(node.entries()) if node is not None and node.is_list else []


def _text(node: "yamlish.Node | None") -> str:
    return node.text.strip().strip("\"'") if node is not None else ""


def _check_ingress(path: str, name: str, kind: str, resource: "yamlish.Node") -> "Iterator[Finding]":
    """CF001: a security group rule that admits the internet."""
    properties = resource.get("Properties")
    if properties is None:
        return
    if kind == "AWS::EC2::SecurityGroup":
        rules = _entries(properties.get("SecurityGroupIngress"))
    elif kind == "AWS::EC2::SecurityGroupIngress":
        rules = [properties]
    else:
        return

    for rule in rules:
        opening = next(
            (
                (key, _text(rule.get(key)))
                for key in ("CidrIp", "CidrIpv6")
                if _text(rule.get(key)) in wellknown.OPEN_CIDRS
            ),
            None,
        )
        if opening is None:
            continue
        low, high = _text(rule.get("FromPort")), _text(rule.get("ToPort"))
        services = (
            wellknown.services_in_range(int(low), int(high))
            if low.isdigit() and high.isdigit()
            else ["every port"]
            if _text(rule.get("IpProtocol")) in ("-1", "all")
            else []
        )
        yield Finding(
            rule_id="CF001",
            severity=Severity.CRITICAL if services else Severity.HIGH,
            title=(
                f"{kind} {name!r} admits {opening[1]} to {', '.join(services)}"
                if services
                else f"{kind} {name!r} admits {opening[1]}"
            ),
            path=path,
            line=(rule.get(opening[0]) or rule).line,
            evidence=f"{opening[0]}: {opening[1]}",
            remediation=(
                "Restrict the range to the addresses that need it. If it has to "
                "be reachable from anywhere, put a load balancer in front rather "
                "than opening the instance's own port."
            ),
        )


def _check_public_storage(path: str, name: str, kind: str, resource: "yamlish.Node") -> "Iterator[Finding]":
    """CF002: a bucket handed to anyone who asks."""
    properties = resource.get("Properties")
    if properties is None or kind != "AWS::S3::Bucket":
        return

    acl = properties.get("AccessControl")
    if acl is not None and _text(acl) in _PUBLIC_ACLS:
        yield Finding(
            rule_id="CF002",
            severity=Severity.HIGH,
            title=f"Bucket {name!r} is world-readable through its ACL",
            path=path,
            line=acl.line,
            evidence=f"AccessControl: {_text(acl)}",
            remediation=(
                "Serve public objects through CloudFront with an origin access "
                "identity. A public bucket also exposes its listing, which is "
                "how one exposed object becomes all of them."
            ),
        )

    block = properties.get("PublicAccessBlockConfiguration")
    if block is None:
        return
    for key in _PUBLIC_ACCESS_BLOCK:
        setting = block.get(key)
        if setting is None or not setting.falsy():
            continue
        yield Finding(
            rule_id="CF002",
            severity=Severity.HIGH,
            title=f"Bucket {name!r} disables {key}",
            path=path,
            line=setting.line,
            evidence=f"{key}: false",
            remediation=(
                "The public access block is the backstop that catches a bucket "
                "policy somebody gets wrong later. Leave all four on."
            ),
        )


def _check_encryption(path: str, name: str, kind: str, resource: "yamlish.Node") -> "Iterator[Finding]":
    """CF003: encryption that was available and was switched off."""
    for key, node in resource.walk():
        if key not in _ENCRYPTION_KEYS or not node.falsy():
            continue
        yield Finding(
            rule_id="CF003",
            severity=Severity.MEDIUM,
            title=f"{kind or 'Resource'} {name!r} disables {key}",
            path=path,
            line=node.line,
            evidence=f"{key}: false",
            remediation=(
                "Encryption at rest is close to free on every managed service "
                "and cannot be turned on later without a rebuild. Remove the "
                "property to take the default."
            ),
        )


def _check_public_database(path: str, name: str, kind: str, resource: "yamlish.Node") -> "Iterator[Finding]":
    """CF005: a managed database given a public address."""
    for key, node in resource.walk():
        if key != "PubliclyAccessible" or not node.truthy():
            continue
        yield Finding(
            rule_id="CF005",
            severity=Severity.HIGH,
            title=f"{kind or 'Resource'} {name!r} is publicly accessible",
            path=path,
            line=node.line,
            evidence="PubliclyAccessible: true",
            remediation=(
                "A public endpoint means the database's own authentication is "
                "the only thing between it and the internet. Keep it in private "
                "subnets and reach it through a bastion or a VPN."
            ),
        )


def _check_wildcard_policy(path: str, name: str, kind: str, resource: "yamlish.Node") -> "Iterator[Finding]":
    """CF004: a policy statement granting every action on every resource."""
    for key, node in resource.walk():
        if key != "Statement":
            continue
        for statement in _entries(node) or [node]:
            if not statement.is_map:
                continue
            if _text(statement.get("Effect")) not in ("Allow", ""):
                continue
            if not (_wildcard(statement.get("Action")) and _wildcard(statement.get("Resource"))):
                continue
            yield Finding(
                rule_id="CF004",
                severity=Severity.HIGH,
                title=f"{kind or 'Policy'} {name!r} allows every action on every resource",
                path=path,
                line=statement.line,
                evidence="Action: '*' with Resource: '*'",
                remediation=(
                    "A wildcard policy is indistinguishable from an "
                    "administrator. List the actions the principal uses; IAM "
                    "Access Analyzer will tell you which they are."
                ),
            )


def _wildcard(node: "yamlish.Node | None") -> bool:
    """True when a policy field is ``*``, written as a scalar or a list."""
    if node is None:
        return False
    if node.is_list:
        return any(_text(entry) == "*" for entry in node.entries())
    text = _text(node)
    return text == "*" or text in ("['*']", '["*"]', "[*]")


_RULES = (
    _check_ingress,
    _check_public_storage,
    _check_encryption,
    _check_public_database,
    _check_wildcard_policy,
)


def scan_template(
    path: str, text: str, marks: "suppression.Suppressions | None" = None
) -> "list[Finding]":
    """Run every CloudFormation rule against one template."""
    marks = suppression.parse(text) if marks is None else marks
    if marks.whole_file:
        return []

    documents = jsonish.parse_documents(text) if jsonish.looks_like_json(text) else yamlish.parse(text)
    findings: "list[Finding]" = []
    for document in documents:
        if not is_template(document):
            continue
        for name, kind, resource in _resources(document):
            for rule in _RULES:
                findings.extend(rule(path, name, kind, resource))
    return marks.filter_findings(findings)


def scan_files(
    files: "Iterable[tuple[str, str]]", *, honour_markers: bool = True
) -> "list[Finding]":
    """Scan ``(path, text)`` pairs, ignoring anything that is not a template."""
    markers = None if honour_markers else suppression.NONE
    return [
        finding
        for path, text in files
        if is_template_path(path)
        for finding in scan_template(path, text, markers)
    ]
