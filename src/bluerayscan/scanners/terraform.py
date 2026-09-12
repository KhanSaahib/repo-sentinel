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

#: Source addresses that mean "anywhere", in each provider's spelling. Azure
#: writes "*" or the service tag "Internet"; GCP and AWS write a CIDR.
_OPEN_SOURCES = frozenset({"*", "internet", "any", "0.0.0.0/0", "::/0"})

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


def _ports_from_ranges(specs: "Iterable[str]") -> "list[str]":
    """Services exposed by port specifications written as strings.

    Covers the spellings Azure and GCP use: a single port, a hyphenated range,
    a comma-separated list, and ``*`` for everything.
    """
    exposed: "list[str]" = []
    for spec in specs:
        cleaned = spec.strip().strip('"')
        if cleaned in ("*", "all"):
            return ["every port"]
        for part in cleaned.split(","):
            low, _, high = part.strip().partition("-")
            if not low.strip().isdigit():
                continue
            first = int(low)
            last = int(high) if high.strip().isdigit() else first
            exposed.extend(wellknown.services_in_range(first, last))
    return sorted(set(exposed))


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
    # A rule may name only one end of the range; the other is the same port.
    first = low if low is not None else high
    last = high if high is not None else low
    assert first is not None and last is not None
    if first == 0 and last >= 65535:
        return ["every port"]
    return wellknown.services_in_range(first, last)


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


def _azure_ingress(path: str, block: "hcl.Block", rule: "hcl.Block") -> "Finding | None":
    """TF001, in Azure's spelling: a network security rule open to the world."""
    direction = (rule.attribute("direction") or (0, '"Inbound"'))[1].strip('"').lower()
    access = (rule.attribute("access") or (0, '"Allow"'))[1].strip('"').lower()
    if direction != "inbound" or access != "allow":
        return None

    found = rule.attribute("source_address_prefix") or rule.attribute("source_address_prefixes")
    if found is None:
        return None
    line, value = found
    sources = _strings(value) or [value]
    opening = next(
        (source for source in sources if source.strip().strip('"').lower() in _OPEN_SOURCES),
        None,
    )
    if opening is None:
        return None

    ports = rule.attribute("destination_port_range") or rule.attribute("destination_port_ranges")
    specs = _strings(ports[1]) if ports else []
    if ports and not specs:
        specs = [ports[1]]
    services = _ports_from_ranges(specs)
    return Finding(
        rule_id="TF001",
        severity=Severity.CRITICAL if services else Severity.HIGH,
        title=(
            f"{block.label()} admits {opening} to {', '.join(services)}"
            if services
            else f"{block.label()} admits {opening}"
        ),
        path=path,
        line=line,
        evidence=f"inbound from {opening}",
        remediation=(
            "Restrict the source to the addresses that need it. A service tag "
            "of Internet, or a prefix of *, is every host that can route to "
            "this network."
        ),
    )


def _gcp_ingress(path: str, block: "hcl.Block") -> "Finding | None":
    """TF001, in GCP's spelling: a firewall rule with an open source range."""
    direction = (block.attribute("direction") or (0, '"INGRESS"'))[1].strip('"').upper()
    if direction != "INGRESS":
        return None
    found = block.attribute("source_ranges")
    if found is None:
        return None
    line, value = found
    opening = next(
        (cidr for cidr in _strings(value) if cidr in wellknown.OPEN_CIDRS), None
    )
    if opening is None:
        return None

    specs = [
        port
        for allow in block.blocks("allow")
        for port in (_strings((allow.attribute("ports") or (0, ""))[1]) or ["*"])
    ]
    services = _ports_from_ranges(specs)
    return Finding(
        rule_id="TF001",
        severity=Severity.CRITICAL if services else Severity.HIGH,
        title=(
            f"{block.label()} admits {opening} to {', '.join(services)}"
            if services
            else f"{block.label()} admits {opening}"
        ),
        path=path,
        line=line,
        evidence=f"source_ranges includes {opening}",
        remediation=(
            "Restrict source_ranges to the networks that need it, and prefer a "
            "target_service_account over a tag so the rule cannot widen by "
            "somebody labelling an instance."
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


def _azure_rules(block: "hcl.Block") -> "Iterator[hcl.Block]":
    """Azure security rules, standalone or nested in a security group."""
    if block.type == "azurerm_network_security_rule":
        yield block
    elif block.type == "azurerm_network_security_group":
        yield from block.blocks("security_rule")


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


#: Attributes that switch off transport security. Each is a provider saying
#: "yes, serve this over plain HTTP", which is a different failure from
#: encryption at rest and needs a different fix.
_TRANSPORT_ATTRIBUTES = (
    "enable_https_traffic_only",
    "https_only",
    "enforce_https",
    "min_tls_version",
    "ssl_enforcement_enabled",
    "require_ssl",
)


def _check_transport(path: str, block: "hcl.Block") -> "Iterator[Finding]":
    """TF007: a service told to accept unencrypted connections."""
    for scope in block.walk():
        for attribute in _TRANSPORT_ATTRIBUTES:
            found = scope.attribute(attribute)
            if found is None:
                continue
            value = found[1].strip().strip('"').lower()
            if attribute == "min_tls_version":
                if value not in ("tls1_0", "tls1_1", "1.0", "1.1"):
                    continue
            elif not _is_false(found[1]):
                continue
            yield Finding(
                rule_id="TF007",
                severity=Severity.HIGH,
                title=f"{block.label()} accepts unencrypted connections ({attribute})",
                path=path,
                line=found[0],
                evidence=f"{attribute} = {found[1]}",
                remediation=(
                    "Anything that can see the network can read a plaintext "
                    "connection and change it. Require TLS 1.2 or better; "
                    "every provider defaults to it now, so this is a setting "
                    "somebody turned off rather than one nobody turned on."
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


def _check_public_principal(path: str, block: "hcl.Block") -> "Iterator[Finding]":
    """TF008: a policy that names everybody as the principal.

    ``principals { type = "AWS" identifiers = ["*"] }`` in an Allow statement
    is a different mistake from TF004's wildcard action: that one says the
    principal may do anything, this one says anybody may be the principal. On
    a role's trust policy it means any AWS account can assume the role; on a
    bucket or a key policy it means any AWS account can use it.
    """
    for statement in block.walk():
        effect = (statement.attribute("effect") or (0, '"Allow"'))[1].strip('"')
        if effect.lower() != "allow":
            continue
        for principals in statement.blocks("principals"):
            identifiers = principals.attribute("identifiers")
            if identifiers is None or "*" not in _strings(identifiers[1]):
                continue
            kind = (principals.attribute("type") or (0, '"AWS"'))[1].strip('"')
            yield Finding(
                rule_id="TF008",
                severity=Severity.HIGH,
                title=f"{block.label()} allows any {kind} principal",
                path=path,
                line=identifiers[0],
                evidence=f'type = "{kind}", identifiers = ["*"]',
                remediation=(
                    "Anybody is the principal here: on a role's trust policy "
                    "that is any AWS account assuming the role, and on a "
                    "bucket or key policy it is any account using it. Name the "
                    "accounts, or add a condition that narrows it -- an "
                    "aws:PrincipalOrgID or a source account."
                ),
            )


_JSON_PUBLIC_PRINCIPAL = re.compile(
    r'"Principal"\s*:\s*(?:"\*"|\{\s*"AWS"\s*:\s*(?:"\*"|\[\s*"\*"\s*\])\s*\})',
    re.IGNORECASE,
)


def _check_json_principals(path: str, text: str) -> "Iterator[Finding]":
    """TF008 again, for the policies written as JSON inside a heredoc."""
    for match in _JSON_PUBLIC_PRINCIPAL.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        yield Finding(
            rule_id="TF008",
            severity=Severity.HIGH,
            title="Inline policy allows any principal",
            path=path,
            line=line,
            evidence='"Principal": "*"',
            remediation=(
                "Anybody is the principal here. Name the accounts, or add a "
                "condition that narrows it. A trust policy written this way "
                "lets any AWS account assume the role."
            ),
            confidence=Confidence.MEDIUM,
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


def scan_terraform(
    path: str, text: str, marks: "suppression.Suppressions | None" = None
) -> "list[Finding]":
    """Run every Terraform rule against one configuration file."""
    marks = suppression.parse(text) if marks is None else marks
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
        for rule in _azure_rules(block):
            finding = _azure_ingress(path, block, rule)
            if finding is not None:
                findings.append(finding)
        if block.type == "google_compute_firewall":
            finding = _gcp_ingress(path, block)
            if finding is not None:
                findings.append(finding)
        findings.extend(_check_public_storage(path, block))
        findings.extend(_check_encryption(path, block))
        findings.extend(_check_transport(path, block))
        findings.extend(_check_public_database(path, block))
        findings.extend(_check_wildcard_policy(path, block))
        findings.extend(_check_public_principal(path, block))

    findings.extend(_check_json_policies(path, text))
    findings.extend(_check_json_principals(path, text))
    return marks.filter_findings(findings)


def scan_files(
    files: "Iterable[tuple[str, str]]", *, honour_markers: bool = True
) -> "list[Finding]":
    """Scan ``(path, text)`` pairs, ignoring anything that is not Terraform."""
    markers = None if honour_markers else suppression.NONE
    return [
        finding
        for path, text in files
        if is_terraform_path(path)
        for finding in scan_terraform(path, text, markers)
    ]
