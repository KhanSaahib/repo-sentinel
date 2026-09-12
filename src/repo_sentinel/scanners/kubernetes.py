"""Audit Kubernetes manifests for workloads that escape their container.

The container boundary is the only thing between a compromised process and the
node it runs on, and every rule here is about a manifest that removes part of
it: a privileged container, a host namespace, a hostPath mount that reaches the
node's filesystem, a capability set that was never narrowed.

Manifests are found by content rather than by filename. A Kubernetes document
is one with ``apiVersion`` and ``kind`` at its root, which is a far better test
than a path pattern: manifests live under ``deploy/``, ``k8s/``, ``manifests/``,
``charts/templates/`` and half a dozen other conventions, and a workflow file
that happens to sit in one of them is not a workload.

The last rule is the interesting one. A ``Secret`` manifest stores its values
base64-encoded, which is not encryption and never was, but it does make a
committed credential invisible to every scanner that reads lines. So K8S007
decodes them and asks the secret rules what they see.
"""

from __future__ import annotations

import base64
import binascii
import posixpath
import re
from collections.abc import Callable, Iterable, Iterator

from .. import jsonish, suppression, wellknown, yamlish
from ..findings import Confidence, Finding, Severity, redact
from ..heuristics import looks_generated
from . import secrets

_MANIFEST_SUFFIXES = (".yaml", ".yml", ".json")

#: Namespaces shared with the node. Any of them dissolves a part of the
#: isolation the container was supposed to provide.
_HOST_NAMESPACES = {
    "hostNetwork": "the node's network, including services bound to localhost",
    "hostPID": "the node's process table, where other containers' processes are visible",
    "hostIPC": "the node's shared memory",
}

_CONTAINER_KEYS = ("containers", "initContainers", "ephemeralContainers")

#: Subjects that are not a person or a workload but a category of everybody.
#: ``system:authenticated`` is every account the cluster will authenticate,
#: which on a cluster with any external identity provider is a great many.
_EVERYONE = {
    "system:anonymous": "unauthenticated callers",
    "system:unauthenticated": "unauthenticated callers",
    "system:authenticated": "every authenticated account, including every service account",
}

_RBAC_ROLES = ("Role", "ClusterRole")
_RBAC_BINDINGS = ("RoleBinding", "ClusterRoleBinding")
_IMAGE_TAG = re.compile(r"^(?P<image>[^\s@]+?)(?::(?P<tag>[^:/@]+))?(?:@(?P<digest>sha256:\w+))?$")


def is_manifest_path(path: str) -> bool:
    """True for the extensions a manifest is written with, YAML or JSON."""
    return posixpath.basename(path.replace("\\", "/")).lower().endswith(_MANIFEST_SUFFIXES)


#: Kinds that describe the *shape* of a resource rather than being one. A
#: CustomResourceDefinition carries an OpenAPI schema, and a schema names every
#: property a resource may have -- hostPath, privileged, capabilities -- as
#: keys, which is how a CRD comes to look like the worst workload ever written.
#: Measured on the Grafana operator: three critical findings, all of them a
#: schema saying the field exists.
_SCHEMA_KINDS = frozenset({"CustomResourceDefinition"})


def is_manifest(document: "yamlish.Node") -> bool:
    """True for a document that declares itself to the Kubernetes API.

    A schema for a resource is not one. Nothing in a CustomResourceDefinition
    runs: it tells the API server what fields a custom resource may carry, and
    the fields it names are exactly the ones these rules look for.
    """
    if document.get("apiVersion") is None or document.get("kind") is None:
        return False
    kind = (document.get("kind") or yamlish.Node("", 0)).text.strip().strip("\"'")
    return kind not in _SCHEMA_KINDS


def _describe(document: "yamlish.Node") -> str:
    """``Deployment "web"``, for a report that names what it is talking about."""
    kind = (document.get("kind") or yamlish.Node("", 0)).text or "workload"
    name = (document.get("metadata", "name") or yamlish.Node("", 0)).text
    # A chart's name comes from a template, so quoting the placeholder back at
    # the reader says nothing; the kind and the path already locate it.
    if not name or yamlish.TEMPLATE_PLACEHOLDER in name:
        return kind
    return f"{kind} {name!r}"


def _containers(document: "yamlish.Node") -> "Iterator[tuple[str, yamlish.Node]]":
    """Every container in the document, whatever workload kind wraps it.

    Found by walking for the container list keys rather than by knowing the
    shape of each kind: a Pod, a Deployment, a CronJob and a custom resource
    that embeds a pod template all nest their containers at different depths,
    and enumerating those depths is a list that would always be one short.
    """
    for key, node in document.walk():
        if key not in _CONTAINER_KEYS or not node.is_list:
            continue
        for container in node.entries():
            name = (container.get("name") or yamlish.Node("", container.line)).text
            yield name or "container", container


def _security_context(container: "yamlish.Node") -> "yamlish.Node | None":
    return container.get("securityContext")


def _check_privileged(path: str, document: "yamlish.Node") -> "Iterator[Finding]":
    """K8S001: privileged is root on the node with the safety catches removed."""
    for name, container in _containers(document):
        flag = container.get("securityContext", "privileged")
        if flag is None or not flag.truthy():
            continue
        yield Finding(
            rule_id="K8S001",
            severity=Severity.CRITICAL,
            title=f"Container {name!r} in {_describe(document)} runs privileged",
            path=path,
            line=flag.line,
            evidence="privileged: true",
            remediation=(
                "A privileged container holds every capability and can reach "
                "the node's devices, which makes container escape a formality. "
                "Grant the one capability the workload needs instead."
            ),
        )


def _check_host_namespaces(path: str, document: "yamlish.Node") -> "Iterator[Finding]":
    """K8S003: isolation the pod asked to do without."""
    for key, node in document.walk():
        if key not in _HOST_NAMESPACES or not node.truthy():
            continue
        yield Finding(
            rule_id="K8S003",
            severity=Severity.HIGH,
            title=f"{_describe(document)} shares {key} with the node",
            path=path,
            line=node.line,
            evidence=f"{key}: true",
            remediation=(
                f"This exposes {_HOST_NAMESPACES[key]}. Remove it unless the "
                "workload is a node agent that genuinely needs it, and confine "
                "that agent to its own namespace with its own policy."
            ),
        )


def _check_host_paths(path: str, document: "yamlish.Node") -> "Iterator[Finding]":
    """K8S002: a mount that reaches out of the container and into the node."""
    for key, node in document.walk():
        if key != "hostPath":
            continue
        mounted = (node.get("path") or yamlish.Node("", node.line)).text.strip().strip("\"'")
        # The root entry is matched exactly: treating it as a prefix would
        # make every absolute path critical, which is the same as none of them.
        critical = wellknown.is_critical_host_path(mounted)
        yield Finding(
            rule_id="K8S002",
            severity=Severity.CRITICAL if critical else Severity.HIGH,
            title=(
                f"{_describe(document)} mounts host path {mounted}"
                if mounted
                else f"{_describe(document)} mounts a path from the node"
            ),
            path=path,
            line=node.line,
            evidence=f"hostPath: {mounted}" if mounted else "hostPath volume",
            remediation=(
                "A hostPath mount is shared with the node and every other pod "
                "that mounts it. The container runtime socket in particular is "
                "root on the node. Use a PersistentVolume, a projected volume, "
                "or a CSI driver."
            ),
        )


#: The value both confinement mechanisms use to mean "none of it". seccomp
#: spells it in a securityContext, AppArmor in an annotation, and the word is
#: the same.
_UNCONFINED = "unconfined"
_APPARMOR_PREFIX = "container.apparmor.security.beta.kubernetes.io/"


def _check_confinement(path: str, document: "yamlish.Node") -> "Iterator[Finding]":
    """K8S012: a syscall or AppArmor profile turned off by name.

    Both are written down on purpose. Unconfined is what a cluster without a
    Pod Security Standard gives you anyway, so the value is not a change of
    behaviour -- it is somebody recording that they needed it, usually to make
    one syscall work, and it removes the filter from all of them.
    """
    for name, container in _containers(document):
        profile = container.get("securityContext", "seccompProfile", "type")
        if profile is not None and profile.text.strip().strip("\"'").lower() == _UNCONFINED:
            yield _unconfined_finding(
                path, profile.line, f"Container {name!r} runs without a seccomp profile",
                "seccompProfile: Unconfined",
                "Unconfined leaves every syscall available to the container, "
                "which is most of what a container escape needs. "
                "RuntimeDefault is the profile the runtime already ships.",
            )

    for key, node in document.walk():
        if not key.startswith(_APPARMOR_PREFIX):
            continue
        if node.text.strip().strip("\"'").lower() != _UNCONFINED:
            continue
        yield _unconfined_finding(
            path, node.line,
            f"Container {key[len(_APPARMOR_PREFIX):]!r} runs without an AppArmor profile",
            f"{key}: unconfined",
            "The annotation switches AppArmor off for that container by name. "
            "Use runtime/default, or a profile written for the workload.",
        )

    for key, node in document.walk():
        if key != "seccompProfile" or not node.is_map:
            continue
        kind = node.get("type")
        if kind is None or kind.text.strip().strip("\"'").lower() != _UNCONFINED:
            continue
        if _inside_container(document, node):
            continue
        yield _unconfined_finding(
            path, kind.line, "Pod runs without a seccomp profile",
            "seccompProfile: Unconfined",
            "Set at pod level this covers every container in it. "
            "RuntimeDefault is the profile the runtime already ships.",
        )


def _unconfined_finding(
    path: str, line: int, title: str, evidence: str, remediation: str
) -> Finding:
    return Finding(
        rule_id="K8S012",
        severity=Severity.HIGH,
        title=title,
        path=path,
        line=line,
        evidence=evidence,
        remediation=remediation,
    )


def _inside_container(document: "yamlish.Node", node: "yamlish.Node") -> bool:
    """True when this seccompProfile belongs to a container, not to the pod.

    The container form is reported by name above, and reporting it again as
    the pod's is the same finding with the wrong subject on one of them.
    """
    for _, container in _containers(document):
        context = _security_context(container)
        if context is not None and context.get("seccompProfile") is node:
            return True
    return False


def _check_capabilities(path: str, document: "yamlish.Node") -> "Iterator[Finding]":
    """K8S006: privilege handed back after it was dropped."""
    for name, container in _containers(document):
        context = _security_context(container)
        if context is None:
            continue
        escalation = context.get("allowPrivilegeEscalation")
        if escalation is not None and escalation.truthy():
            yield Finding(
                rule_id="K8S006",
                severity=Severity.MEDIUM,
                title=f"Container {name!r} allows privilege escalation",
                path=path,
                line=escalation.line,
                evidence="allowPrivilegeEscalation: true",
                remediation=(
                    "Setting this to false blocks setuid binaries from gaining "
                    "privileges the pod was not granted. Very little needs it."
                ),
            )
        added = context.get("capabilities", "add")
        if added is None:
            continue
        granted = {
            entry.text.strip().strip("\"'").upper()
            for entry in (added.entries() if added.is_list else ())
        } or set(re.findall(r"[A-Z_]+", added.text.upper()))
        risky = sorted(granted & wellknown.DANGEROUS_CAPABILITIES)
        if not risky:
            continue
        yield Finding(
            rule_id="K8S006",
            severity=Severity.HIGH,
            title=f"Container {name!r} adds capability {', '.join(risky)}",
            path=path,
            line=added.line,
            evidence=f"capabilities.add includes {', '.join(risky)}",
            remediation=(
                "SYS_ADMIN and ALL are close to privileged; NET_RAW enables "
                "ARP spoofing between pods. Drop ALL and add back only what "
                "the process fails without."
            ),
        )


def _check_root(path: str, document: "yamlish.Node") -> "Iterator[Finding]":
    """K8S005: a workload that says, in writing, that it runs as root."""
    for name, container in _containers(document):
        context = _security_context(container)
        if context is None:
            continue
        user = context.get("runAsUser")
        non_root = context.get("runAsNonRoot")
        if user is not None and user.text.strip().strip("\"'") == "0":
            evidence, line = "runAsUser: 0", user.line
        elif non_root is not None and non_root.falsy():
            evidence, line = "runAsNonRoot: false", non_root.line
        else:
            continue
        yield Finding(
            rule_id="K8S005",
            severity=Severity.MEDIUM,
            title=f"Container {name!r} in {_describe(document)} runs as root",
            path=path,
            line=line,
            evidence=evidence,
            remediation=(
                "Root in the container is root against the kernel if anything "
                "escapes it. Build the image with a user and set runAsNonRoot."
            ),
        )


def _check_resources(path: str, document: "yamlish.Node") -> "Iterator[Finding]":
    """K8S004: a container with no ceiling, which is a noisy-neighbour outage.

    Low severity on purpose. It is a real availability problem and a real
    finding, but it is not a way in, and reporting it at the same level as a
    privileged container would teach people to read neither.
    """
    for name, container in _containers(document):
        limits = container.get("resources", "limits")
        if limits is not None and limits.is_map:
            continue
        yield Finding(
            rule_id="K8S004",
            severity=Severity.LOW,
            title=f"Container {name!r} in {_describe(document)} declares no resource limits",
            path=path,
            line=container.line,
            evidence="no resources.limits",
            remediation=(
                "Without a limit one container can exhaust the node's memory "
                "and take its neighbours down with it. Set cpu and memory "
                "limits, or a LimitRange for the namespace."
            ),
            confidence=Confidence.MEDIUM,
        )


def _check_images(path: str, document: "yamlish.Node") -> "Iterator[Finding]":
    """K8S008: an image reference that can point somewhere else tomorrow."""
    for name, container in _containers(document):
        image = container.get("image")
        if image is None:
            continue
        reference = image.text.strip().strip("\"'")
        if wellknown.is_interpolated(reference):
            continue  # decided elsewhere; its shape here means nothing
        match = _IMAGE_TAG.match(reference)
        if match is None or match.group("digest"):
            continue
        tag = match.group("tag")
        if tag is not None and tag != "latest":
            continue
        yield Finding(
            rule_id="K8S008",
            severity=Severity.MEDIUM,
            title=f"Container {name!r} pulls {reference}, which floats",
            path=path,
            line=image.line,
            evidence=f"image: {reference}",
            remediation=(
                "An unpinned tag means two pods of the same Deployment can run "
                "different code, and a rollback restores nothing. Pin a version "
                "tag, or a digest where the registry is not yours."
            ),
        )


def _check_rbac_wildcards(path: str, document: "yamlish.Node") -> "Iterator[Finding]":
    """K8S009: a role that grants every verb on every resource.

    The Kubernetes equivalent of a wildcard IAM policy, and it reads the same
    way: a subject holding this can create a pod that mounts the node, read
    every Secret in the cluster, and grant itself anything it is missing.
    """
    kind = (document.get("kind") or yamlish.Node("", 0)).text.strip("\"'")
    if kind not in _RBAC_ROLES:
        return
    rules = document.get("rules")
    if rules is None:
        return
    for rule in rules.entries():
        verbs = _values(rule.get("verbs"))
        resources = _values(rule.get("resources"))
        if "*" not in verbs or "*" not in resources:
            continue
        yield Finding(
            rule_id="K8S009",
            severity=Severity.CRITICAL if kind == "ClusterRole" else Severity.HIGH,
            title=f"{_describe(document)} grants every verb on every resource",
            path=path,
            line=(rule.get("verbs") or rule).line,
            evidence='verbs: ["*"] with resources: ["*"]',
            remediation=(
                "A wildcard role is indistinguishable from cluster-admin: it "
                "can read every Secret and grant itself the rest. List the "
                "verbs and resources the workload uses; `kubectl auth "
                "can-i --list` will tell you which they are."
            ),
        )


def _check_rbac_subjects(path: str, document: "yamlish.Node") -> "Iterator[Finding]":
    """K8S010: a binding whose subject is a category of everybody."""
    kind = (document.get("kind") or yamlish.Node("", 0)).text.strip("\"'")
    if kind not in _RBAC_BINDINGS:
        return
    subjects = document.get("subjects")
    role = (document.get("roleRef", "name") or yamlish.Node("", 0)).text.strip("\"'")
    if subjects is None:
        return
    for subject in subjects.entries():
        name_node = subject.get("name")
        if name_node is None:
            continue
        name = name_node.text.strip().strip("\"'").lower()
        who = _EVERYONE.get(name)
        if who is None:
            continue
        granted = f" the {role!r} role" if role else ""
        yield Finding(
            rule_id="K8S010",
            severity=Severity.CRITICAL,
            title=f"{_describe(document)} grants{granted} to {name}",
            path=path,
            line=name_node.line,
            evidence=f"subject {name}",
            remediation=(
                f"This binds to {who}. Bind to the service account of the "
                "workload that needs the permission, and check the role it "
                "points at while you are there."
            ),
        )


def _values(node: "yamlish.Node | None") -> "list[str]":
    """A YAML list, or an inline one, as plain strings."""
    if node is None:
        return []
    if node.is_list:
        return [entry.text.strip().strip("\"'") for entry in node.entries()]
    text = node.text.strip()
    if text.startswith("[") and text.endswith("]"):
        return [part.strip().strip("\"'") for part in text[1:-1].split(",") if part.strip()]
    return [text.strip("\"'")] if text else []


def _check_host_ports(path: str, document: "yamlish.Node") -> "Iterator[Finding]":
    """K8S011: a container port bound on the node itself.

    A hostPort skips the Service and the NetworkPolicy and puts the container
    on the node's own address, which means anything that can reach the node can
    reach the container -- and that only one pod per node can have it, so the
    scheduler quietly stops being able to place the workload.
    """
    for name, container in _containers(document):
        ports = container.get("ports")
        if ports is None or not ports.is_list:
            continue
        for entry in ports.entries():
            node = entry.get("hostPort")
            if node is None or not node.text.strip().strip("\"'").isdigit():
                continue
            port = int(node.text.strip().strip("\"'"))
            service = wellknown.ADMIN_PORTS.get(port)
            yield Finding(
                rule_id="K8S011",
                severity=Severity.HIGH if service or port < 1024 else Severity.MEDIUM,
                title=(
                    f"Container {name!r} binds {service or port} on the node itself"
                    if service
                    else f"Container {name!r} binds port {port} on the node itself"
                ),
                path=path,
                line=node.line,
                evidence=f"hostPort: {port}",
                remediation=(
                    "A hostPort bypasses the Service and any NetworkPolicy in "
                    "front of it: whatever can reach the node can reach this "
                    "container. Publish it through a Service, or through an "
                    "ingress controller that is meant to be exposed."
                ),
            )


def _check_secret_data(path: str, document: "yamlish.Node") -> "Iterator[Finding]":
    """K8S007: a credential committed inside a Secret manifest.

    base64 is an encoding, not encryption -- but it is enough to hide a value
    from every rule that reads lines, so the value is decoded and handed to the
    secret rules. When they recognise it, the finding says what it is; when
    they only find entropy, it says that instead, at lower confidence.
    """
    if (document.get("kind") or yamlish.Node("", 0)).text.strip("\"'") != "Secret":
        return

    for field, decode in (("data", True), ("stringData", False)):
        section = document.get(field)
        if section is None or not section.is_map:
            continue
        for key, node in section.items():
            raw = node.text.strip().strip("\"'")
            value = _decode(raw) if decode else raw
            if not value:
                continue
            recognised = next(
                (
                    finding
                    for finding in secrets.scan_line(path, node.line, value)
                    if not finding.rule_id.startswith("SEC10")
                ),
                None,
            )
            if recognised is not None:
                yield Finding(
                    rule_id="K8S007",
                    severity=Severity.CRITICAL,
                    title=f"{_describe(document)} contains {recognised.title.lower()} in {key!r}",
                    path=path,
                    line=node.line,
                    evidence=recognised.evidence,
                    remediation=(
                        "The value is committed, base64 notwithstanding. Rotate "
                        "it, then keep secrets out of manifests: use a sealed or "
                        "external secret, or create it out of band."
                    ),
                    subject=recognised.subject,
                )
            elif looks_generated(value):
                yield Finding(
                    rule_id="K8S007",
                    severity=Severity.HIGH,
                    title=f"{_describe(document)} carries a literal value in {key!r}",
                    path=path,
                    line=node.line,
                    evidence=f"{key}: {redact(value)}",
                    remediation=(
                        "base64 is an encoding, not encryption: anyone with the "
                        "repository has this value. Rotate it and move it to a "
                        "sealed or external secret."
                    ),
                    confidence=Confidence.MEDIUM,
                )


def _decode(value: str) -> str:
    """base64-decode a Secret value, or return "" when it is not text."""
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return ""


#: What every rule below looks like: a path and a document in, findings out.
#: Spelled out so that the two rule sets and the variable holding one of them
#: agree about their type -- otherwise a checker reads each tuple as its own
#: fixed-length type and refuses the assignment.
_Rule = Callable[[str, "yamlish.Node"], "Iterator[Finding]"]

#: Rules that read a value the document actually contains. These are as sound
#: on a Helm template as on a finished manifest: "privileged: true" written in
#: a chart is privileged: true when it is installed.
_POSITIVE_RULES: "tuple[_Rule, ...]" = (
    _check_privileged,
    _check_host_paths,
    _check_host_namespaces,
    _check_capabilities,
    _check_confinement,
    _check_root,
    _check_host_ports,
    _check_secret_data,
    _check_rbac_wildcards,
    _check_rbac_subjects,
)

#: Rules that conclude something from what is *missing* or from a value's
#: exact shape. A template cannot answer either question: the values file
#: supplies the limits and the image tag, and neither is in front of us.
_COMPLETE_DOCUMENT_RULES: "tuple[_Rule, ...]" = (
    _check_resources,
    _check_images,
)

_RULES: "tuple[_Rule, ...]" = _POSITIVE_RULES + _COMPLETE_DOCUMENT_RULES


def scan_manifest(
    path: str, text: str, marks: "suppression.Suppressions | None" = None
) -> "list[Finding]":
    """Run every rule against every Kubernetes document in one file."""
    marks = suppression.parse(text) if marks is None else marks
    if marks.whole_file:
        return []

    active: "tuple[_Rule, ...]"
    # Nothing without an apiVersion can be a manifest, and parsing a file to
    # learn that is most of what this scanner used to spend its time on. Five
    # scanners read the same YAML files; each now refuses in a substring test
    # what it used to refuse after a parse.
    if "apiVersion" not in text:
        return []

    if jsonish.looks_like_json(text):
        # `kubectl get -o json` and anything that generates manifests. Same
        # rules, same nodes, a different reader.
        documents = jsonish.parse_documents(text)
        active = _RULES
    else:
        templated = yamlish.is_templated(text)
        documents = tuple(yamlish.parse(yamlish.strip_templates(text) if templated else text))
        active = _POSITIVE_RULES if templated else _RULES

    findings: "list[Finding]" = []
    for document in documents:
        if not is_manifest(document):
            continue
        for rule in active:
            findings.extend(rule(path, document))
    return marks.filter_findings(findings)


#: What a chart's values file is called. Helm reads values.yaml; everything
#: else here is the convention for an environment's overrides, and a
#: production one is exactly where a privileged setting ends up.
_VALUES_NAMES = ("values.yaml", "values.yml")
_VALUES_PREFIXES = ("values-", "values.")

#: Settings whose meaning does not depend on where in the chart they land.
#: Each is (key, rule, severity, title, remediation), and each is read only
#: where the key's own name says what it is for: "privileged: true" under a
#: securityContext is the container setting, and under "annotations" it is
#: somebody's label.
_VALUE_FLAGS = (
    ("hostNetwork", "K8S003", Severity.HIGH, "shares the node's network namespace",
     "A pod on the host network sees every interface the node has, and binds "
     "its ports. Publish the workload through a Service instead."),
    ("hostPID", "K8S003", Severity.HIGH, "shares the node's process namespace",
     "Every process on the node is visible, and its /proc with it. Remove this "
     "unless the workload is a node agent that genuinely needs it."),
    ("hostIPC", "K8S003", Severity.HIGH, "shares the node's IPC namespace",
     "Shared memory belonging to every other pod on the node is reachable. "
     "Remove this unless the workload is a node agent that needs it."),
)


#: A cheap gate in front of the parse: every rule below needs one of these
#: words, so a values file without any of them -- which is most of them -- is
#: skipped without being read. A hint missing from this tuple disables a rule
#: silently, which is why the corpus test exists.
_VALUES_HINTS = ("true", "hostPath", "capabilities", "Unconfined")


def is_values_path(path: str) -> bool:
    """True for a file named the way Helm names a chart's values."""
    name = posixpath.basename(path.replace("\\", "/")).lower()
    if name in _VALUES_NAMES:
        return True
    return name.startswith(_VALUES_PREFIXES) and name.endswith(_MANIFEST_SUFFIXES)


def chart_directories(paths: "Iterable[str]") -> "frozenset[str]":
    """Directories holding a ``Chart.yaml``, which is what makes a chart a chart."""
    return frozenset(
        posixpath.dirname(path.replace("\\", "/"))
        for path in paths
        if posixpath.basename(path.replace("\\", "/")).lower() == "chart.yaml"
    )


def scan_values(
    path: str, text: str, marks: "suppression.Suppressions | None" = None
) -> "list[Finding]":
    """Read a chart's values for the settings that mean the same anywhere.

    A values file is not a manifest: it has no apiVersion, no kind, and no
    containers, so the manifest rules never look at it. What it does have is
    the settings a chart hands to its templates, and a handful of those carry
    their meaning with them. ``privileged: true`` under a ``securityContext``
    is the container setting wherever it is written, because that is the only
    thing a chart can do with a key of that name.

    Reported at medium confidence throughout: the chart *should* pass these
    through, and this reader has not read the template that does it.
    """
    marks = suppression.parse(text) if marks is None else marks
    if marks.whole_file:
        return []
    if not any(hint in text for hint in _VALUES_HINTS):
        return []

    source = yamlish.strip_templates(text) if yamlish.is_templated(text) else text
    findings: "list[Finding]" = []
    for document in yamlish.parse(source):
        findings.extend(_values_findings(path, document))
    return marks.filter_findings(findings)


def _values_findings(path: str, document: "yamlish.Node") -> "Iterator[Finding]":
    for key, node in document.walk():
        for name, rule_id, severity, what, remediation in _VALUE_FLAGS:
            if key == name and node.truthy():
                yield Finding(
                    rule_id=rule_id,
                    severity=severity,
                    title=f"Chart values set {name}: the workload {what}",
                    path=path,
                    line=node.line,
                    evidence=f"{name}: {node.text.strip()}",
                    remediation=remediation,
                    confidence=Confidence.MEDIUM,
                )
        if key != "securityContext" or not node.is_map:
            continue
        yield from _values_security_context(path, node)
        continue

    for key, node in document.walk():
        if key != "hostPath" or not node.is_map:
            continue
        # A Kubernetes hostPath volume always carries a path -- the API
        # requires it -- and a values file is full of sections named after the
        # feature they configure. Dagger's chart has a "hostPath:" block whose
        # keys are dataVolume and runVolume, which is an option, not a mount.
        mounted = (node.get("path") or yamlish.Node("", node.line)).text.strip().strip("\"'")
        if not mounted:
            continue
        yield Finding(
            rule_id="K8S002",
            severity=Severity.CRITICAL if wellknown.is_critical_host_path(mounted) else Severity.HIGH,
            title=f"Chart values mount host path {mounted}",
            path=path,
            line=node.line,
            evidence=f"hostPath: {mounted}" if mounted else "hostPath volume",
            remediation=(
                "A hostPath mount is shared with the node and every other pod "
                "that mounts it. Use a PersistentVolume, a projected volume, "
                "or a CSI driver."
            ),
            confidence=Confidence.MEDIUM,
        )


def _values_security_context(path: str, context: "yamlish.Node") -> "Iterator[Finding]":
    """The securityContext keys a chart can only mean one way."""
    privileged = context.get("privileged")
    if privileged is not None and privileged.truthy():
        yield Finding(
            rule_id="K8S001",
            severity=Severity.CRITICAL,
            title="Chart values run the container privileged",
            path=path,
            line=privileged.line,
            evidence="privileged: true",
            remediation=(
                "A privileged container holds every capability and can reach "
                "the node's devices. Grant the one capability the workload "
                "needs instead."
            ),
            confidence=Confidence.MEDIUM,
        )

    escalation = context.get("allowPrivilegeEscalation")
    if escalation is not None and escalation.truthy():
        yield Finding(
            rule_id="K8S006",
            severity=Severity.MEDIUM,
            title="Chart values allow privilege escalation",
            path=path,
            line=escalation.line,
            evidence="allowPrivilegeEscalation: true",
            remediation=(
                "Setting this to false blocks setuid binaries from gaining "
                "privileges the pod was not granted. Very little needs it."
            ),
            confidence=Confidence.MEDIUM,
        )

    profile = context.get("seccompProfile", "type")
    if profile is not None and profile.text.strip().strip("\"'").lower() == _UNCONFINED:
        yield Finding(
            rule_id="K8S012",
            severity=Severity.HIGH,
            title="Chart values ask for no seccomp profile",
            path=path,
            line=profile.line,
            evidence="seccompProfile: Unconfined",
            remediation=(
                "Unconfined leaves every syscall available to the container. "
                "RuntimeDefault is the profile the runtime already ships."
            ),
            confidence=Confidence.MEDIUM,
        )

    added = context.get("capabilities", "add")
    if added is None:
        return
    # A flow list -- add: ["SYS_ADMIN"] -- comes through as text, which is what
    # the reader promises to do with structure it does not parse. The names are
    # still in it.
    granted = {
        entry.text.strip().strip("\"'").upper()
        for entry in (added.entries() if added.is_list else ())
    } or set(re.findall(r"[A-Z_]+", added.text.upper()))
    risky = sorted(granted & wellknown.DANGEROUS_CAPABILITIES)
    if risky:
        yield Finding(
            rule_id="K8S006",
            severity=Severity.HIGH,
            title=f"Chart values add capability {', '.join(risky)}",
            path=path,
            line=added.line,
            evidence=f"capabilities.add: {', '.join(risky)}",
            remediation=(
                "These capabilities are root by another name: SYS_ADMIN and "
                "SYS_PTRACE in particular. Drop ALL and add back only what the "
                "workload calls for."
            ),
            confidence=Confidence.MEDIUM,
        )


def scan_files(
    files: "Iterable[tuple[str, str]]", *, honour_markers: bool = True
) -> "list[Finding]":
    """Scan ``(path, text)`` pairs: manifests, and the values files beside charts.

    A values file is only read when a ``Chart.yaml`` sits in the same
    directory. Without that test, every ``values.yaml`` in every application
    repository -- and they are everywhere -- would be read as a chart's.
    """
    markers = None if honour_markers else suppression.NONE
    pairs = list(files)
    charts = chart_directories(path for path, _ in pairs)
    findings: "list[Finding]" = []
    for path, text in pairs:
        if is_manifest_path(path):
            findings.extend(scan_manifest(path, text, markers))
        if is_values_path(path) and posixpath.dirname(path.replace("\\", "/")) in charts:
            findings.extend(scan_values(path, text, markers))
    return findings
