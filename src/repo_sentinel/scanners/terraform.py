"""Audit Terraform for infrastructure that is open, unencrypted, or unlimited.

Terraform is where a repository stops describing software and starts describing
the internet-facing surface it runs on, so the mistakes here are the expensive
kind: a security group that admits the world, a bucket whose ACL makes it
public, a database reachable from outside the VPC, a policy that grants every
action on every resource.

Every rule reads block structure through :mod:`..hcl` rather than matching
lines, because the same attribute means different things in different places.
``encrypted = false`` in a ``root_block_device`` is a different finding from the
same words at the top of a resource, and ``cidr_blocks`` in an ``egress`` block
is usually not a finding at all -- letting a host reach the internet is normal;
letting the internet reach a host is not.

What this cannot do is evaluate Terraform. A CIDR supplied through a variable,
a ``for_each`` over a map of rules, a module whose defaults live elsewhere: all
of those are invisible here. A clean report means the literal, obvious form of
each mistake is absent from these files.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Iterator

from .. import hcl, suppression, wellknown
from ..findings import Confidence, Finding, Severity

_TERRAFORM_SUFFIXES = (".tf", ".tf.json")

_PUBLIC_ACLS = ("public-read", "public-read-write", "website")
#: Grants to every AWS account anywhere, which is public with extra steps.
_ANYONE = ("allusers", "allauthenticatedusers", "authenticated-read")

_ENCRYPTION_ATTRIBUTES = (
    "storage_encrypted",
    "encrypted",
    "encryption_enabled",
    "enable_key_rotation",
)
_PUBLIC_ACCESS_BLOCK_ATTRIBUTES = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)

_STRING = re.compile(r'"([^"]*)"')
_NUMBER = re.compile(r"^-?\d+$")


def is_terraform_path(path: str) -> bool:
    """True for files Terraform will read as configuration."""
    name = posixpath.basename(path.replace("\\", "/")).lower()
    return name.endswith(_TERRAFORM_SUFFIXES)


def _strings(value: str) -> "list[str]":
    """The quoted strings in an attribute value, list or scalar alike."""
    return _STRING.findall(value)


def _is_true(value: "str | None") -> bool:
    return value is not None and value.strip().strip('"').lower() == "true"


def _is_false(value: "str | None") -> bool:
    return value is not None and value.strip().strip('"').lower() == "false"


def _port(block: "hcl.Block", name: str) -> "int | None":
    found = block.attribute(name)
    if found is None or not _NUMBER.match(found[1]):
        return None
    return int(found[1])


def _exposed_services(block: "hcl.Block") -> "list[str]":
    """Which well-known services a rule's port range leaves open."""
    low = _port(block, "from_port")
    if low is None:
        low = _port(block, "from_port_number")
    high = _port(block, "to_port")
    if high is None:
        high = _port(block, "to_port_number")
    protocol = (block.attribute("protocol") or (0, ""))[1].strip('"').lower()
    if protocol in ("-1", "all"):
        return ["every port"]
    if low is None and high is None:
        return []
    low = high if low is None else low
    high = low if high is None else high
    if low == 0 and high >= 65535:
        return ["every port"]
    return wellknown.services_in_range(low, high)


def _open_to_the_world(block: "hcl.Block") -> "tuple[int, str] | None":
    """The line and CIDR by which a rule admits the whole internet."""
    for name in ("cidr_blocks", "ipv6_cidr_blocks", "cidr_block", "cidr_ipv4", "cidr_ipv6"):
        found = block.attribute(name)
        if found is None:
            continue
        line, value = found
        for cidr in _strings(value):
            if cidr in wellknown.OPEN_CIDRS:
                return line, cidr
    return None


def _check_ingress(path: str, block: "hcl.Block", rule: "hcl.Block") -> "Finding | None":
    """TF001: one ingress rule, read for what it admits and to what."""
    opening = _open_to_the_world(rule)
    if opening is None:
        return None
    line, cidr = opening
    services = _exposed_services(rule)
    exposed = ", ".join(services)
    return Finding(
        rule_id="TF001",
        severity=Severity.CRITICAL if services else Severity.HIGH,
        title=(
            f"{block.label()} admits {cidr} to {exposed}"
            if services
            else f"{block.label()} admits {cidr}"
        ),
        path=path,
        line=line,
        evidence=f"ingress from {cidr}",
        remediation=(
            "Restrict the source to the addresses that need it. If this has to "
            "be reachable from anywhere, put it behind a load balancer or a "
            "bastion rather than opening the instance's own port."
        ),
    )


def _ingress_rules(block: "hcl.Block") -> "Iterator[hcl.Block]":
    """Ingress, however it was written.

    Four spellings, because AWS has added a resource type roughly every time
    somebody decided the previous one was awkward: a nested ``ingress`` block,
    the standalone ``aws_security_group_rule``, the newer
    ``aws_vpc_security_group_ingress_rule``, and network ACL entries, which
    call the attribute ``cidr_block`` in the singular and mark direction with
    ``egress = true``.
    """
    if block.type == "aws_security_group":
        yield from block.blocks("ingress")
    elif block.type == "aws_security_group_rule":
        kind = (block.attribute("type") or (0, ""))[1].strip('"')
        if kind == "ingress":
            yield block
    elif block.type == "aws_vpc_security_group_ingress_rule":
        yield block
    elif block.type == "aws_network_acl_rule":
        if not _is_true((block.attribute("egress") or (0, "false"))[1]):
            yield block


def _check_public_storage(path: str, block: "hcl.Block") -> "Iterator[Finding]":
    """TF002: buckets and objects handed to anyone who asks."""
    acl = block.attribute("acl")
    if acl is not None and acl[1].strip('"').lower() in _PUBLIC_ACLS + _ANYONE:
        yield Finding(
            rule_id="TF002",
            severity=Severity.HIGH,
            title=f"{block.label()} is world-readable through its ACL",
            path=path,
            line=acl[0],
            evidence=f"acl = {acl[1]}",
            remediation=(
                "Serve public objects through a CDN with an origin access "
                "identity instead. A public bucket also exposes its listing, "
                "which is how one exposed object becomes all of them."
            ),
        )

    for attribute in _PUBLIC_ACCESS_BLOCK_ATTRIBUTES:
        found = block.attribute(attribute)
        if _is_false(found[1] if found else None):
            yield Finding(
                rule_id="TF002",
                severity=Severity.HIGH,
                title=f"{block.label()} disables {attribute}",
                path=path,
                line=found[0],  # type: ignore[index]
                evidence=f"{attribute} = false",
                remediation=(
                    "The public access block is the backstop that catches a "
                    "bucket policy or ACL somebody gets wrong later. Leave all "
                    "four settings on unless a specific object has to be public."
                ),
            )

    for member_attribute in ("member", "members"):
        found = block.attribute(member_attribute)
        if found is None:
            continue
        for member in _strings(found[1]):
            if member.split(":")[-1].lower() in _ANYONE:
                yield Finding(
                    rule_id="TF002",
                    severity=Severity.HIGH,
                    title=f"{block.label()} grants access to {member}",
                    path=path,
                    line=found[0],
                    evidence=f"{member_attribute} includes {member!r}",
                    remediation=(
                        "allUsers and allAuthenticatedUsers are the whole "
                        "internet and every Google account respectively. Grant "
                        "to a service account instead."
                    ),
                )


def _check_encryption(path: str, block: "hcl.Block") -> "Iterator[Finding]":
    """TF003: encryption that was available and was switched off."""
    for scope in block.walk():
        for attribute in _ENCRYPTION_ATTRIBUTES:
            found = scope.attribute(attribute)
            if not _is_false(found[1] if found else None):
                continue
            where = "" if scope is block else f" in its {scope.kind} block"
            yield Finding(
                rule_id="TF003",
                severity=Severity.MEDIUM,
                title=f"{block.label()} disables {attribute}{where}",
                path=path,
                line=found[0],  # type: ignore[index]
                evidence=f"{attribute} = false",
                remediation=(
                    "Encryption at rest is close to free on every managed "
                    "service and cannot be turned on later without a rebuild. "
                    "Remove the attribute to take the provider's default."
                ),
            )


def _check_public_database(path: str, block: "hcl.Block") -> "Iterator[Finding]":
    """TF005: a managed database given a public address."""
    found = block.attribute("publicly_accessible")
    if not _is_true(found[1] if found else None):
        return
    yield Finding(
        rule_id="TF005",
        severity=Severity.HIGH,
        title=f"{block.label()} is publicly accessible",
        path=path,
        line=found[0],  # type: ignore[index]
        evidence="publicly_accessible = true",
        remediation=(
            "A public endpoint means the database's own authentication is the "
            "only thing between it and the internet. Keep it in private "
            "subnets and reach it through a bastion or a VPN."
        ),
    )


def _check_wildcard_policy(path: str, block: "hcl.Block") -> "Iterator[Finding]":
    """TF004: a policy that grants every action on every resource.

    Both spellings: the ``aws_iam_policy_document`` data source, where actions
    and resources are HCL lists, and an inline JSON policy, where they are
    strings inside a heredoc the parser deliberately skipped. The JSON form is
    matched on the raw text, which is why it is reported at lower confidence.
    """
    for statement in block.walk():
        actions = statement.attribute("actions")
        resources = statement.attribute("resources")
        effect = (statement.attribute("effect") or (0, '"Allow"'))[1].strip('"')
        if actions is None or resources is None or effect.lower() != "allow":
            continue
        if "*" in _strings(actions[1]) and "*" in _strings(resources[1]):
            yield Finding(
                rule_id="TF004",
                severity=Severity.HIGH,
                title=f"{block.label()} allows every action on every resource",
                path=path,
                line=actions[0],
                evidence='actions = ["*"], resources = ["*"]',
                remediation=(
                    "A wildcard policy is indistinguishable from an "
                    "administrator. List the actions the principal uses; the "
                    "IAM console's access advisor will tell you which they are."
                ),
            )


_JSON_WILDCARD = re.compile(
    r'"Action"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])(?P<gap>[^{}]*?)"Resource"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])',
    re.IGNORECASE | re.DOTALL,
)


def _check_json_policies(path: str, text: str) -> "Iterator[Finding]":
    """TF004 again, for policies written as JSON inside a heredoc."""
    for match in _JSON_WILDCARD.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        yield Finding(
            rule_id="TF004",
            severity=Severity.HIGH,
            title="Inline policy allows every action on every resource",
            path=path,
            line=line,
            evidence='"Action": "*" with "Resource": "*"',
            remediation=(
                "A wildcard policy is indistinguishable from an administrator. "
                "List the actions the principal uses."
            ),
            confidence=Confidence.MEDIUM,
        )


def _check_backend(path: str, block: "hcl.Block") -> "Iterator[Finding]":
    """TF006: remote state, which holds every secret the plan touched."""
    for backend in block.blocks("backend"):
        if backend.type != "s3":
            continue
        if _is_true((backend.attribute("encrypt") or (0, "false"))[1]):
            continue
        yield Finding(
            rule_id="TF006",
            severity=Severity.MEDIUM,
            title="Terraform state is stored without encryption",
            path=path,
            line=backend.line,
            evidence='backend "s3" without encrypt = true',
            remediation=(
                "State files contain every value Terraform read, including "
                "database passwords and generated keys, in plain text. Set "
                "encrypt = true and restrict the bucket."
            ),
        )


def scan_terraform(path: str, text: str) -> "list[Finding]":
    """Run every Terraform rule against one configuration file."""
    marks = suppression.parse(text)
    if marks.whole_file:
        return []

    findings: "list[Finding]" = []
    for block in hcl.parse(text):
        if block.kind == "terraform":
            findings.extend(_check_backend(path, block))
            continue
        if block.kind not in ("resource", "data"):
            continue
        for rule in _ingress_rules(block):
            finding = _check_ingress(path, block, rule)
            if finding is not None:
                findings.append(finding)
        findings.extend(_check_public_storage(path, block))
        findings.extend(_check_encryption(path, block))
        findings.extend(_check_public_database(path, block))
        findings.extend(_check_wildcard_policy(path, block))

    findings.extend(_check_json_policies(path, text))
    return marks.filter_findings(findings)


def scan_files(files: "Iterable[tuple[str, str]]") -> "list[Finding]":
    """Scan ``(path, text)`` pairs, ignoring anything that is not Terraform."""
    return [
        finding
        for path, text in files
        if is_terraform_path(path)
        for finding in scan_terraform(path, text)
    ]
