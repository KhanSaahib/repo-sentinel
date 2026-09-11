"""The catalogue of every rule the scanners can emit.

Scanners carry their own detection logic and their own remediation text, which
is where that material belongs -- next to the pattern it explains. What they
cannot carry is a *list*: nothing in the codebase could answer "what does this
tool check for" without running it against a file that happens to trip every
rule.

So the catalogue exists separately, for the two consumers that need the rule
rather than the finding: SARIF, which describes rules once and then references
them, and ``repo-sentinel rules``, which prints the table that would otherwise
live only in the README and rot there.

The obvious failure mode of a hand-maintained catalogue is drift, so the test
suite asserts in both directions: every rule the scanners emit is described
here, and every rule described here is one a scanner can emit.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence

from .findings import Severity


@dataclasses.dataclass(frozen=True)
class Rule:
    """What one rule is called, what it looks for, and how bad that is."""

    id: str
    name: str
    summary: str
    severity: Severity

    @property
    def category(self) -> str:
        return _CATEGORIES[self.id[:3]]


_CATEGORIES = {"SEC": "secrets", "WF0": "workflows", "DK0": "dockerfiles", "TF0": "terraform", "K8S": "kubernetes", "DC0": "compose", "FN0": "filenames", "GL0": "gitlab", "CF0": "cloudformation", "SC0": "dependencies"}


def _rules(*entries: tuple[str, str, str, Severity]) -> "dict[str, Rule]":
    return {entry[0]: Rule(*entry) for entry in entries}


RULES: "dict[str, Rule]" = _rules(
    ("SEC001", "aws-access-key-id", "AWS access key id", Severity.CRITICAL),
    ("SEC002", "github-pat", "GitHub personal access token", Severity.CRITICAL),
    ("SEC003", "github-fine-grained-token", "GitHub fine-grained token", Severity.CRITICAL),
    ("SEC004", "private-key-block", "PEM private key block", Severity.CRITICAL),
    ("SEC005", "stripe-live-key", "Stripe live secret key", Severity.CRITICAL),
    ("SEC006", "slack-token", "Slack API token", Severity.HIGH),
    ("SEC007", "google-api-key", "Google API key", Severity.HIGH),
    ("SEC008", "openai-style-key", "OpenAI-style API key", Severity.HIGH),
    ("SEC009", "jwt", "JSON Web Token", Severity.MEDIUM),
    ("SEC010", "stripe-test-key", "Stripe test key", Severity.LOW),
    ("SEC011", "azure-storage-key", "Azure storage account key", Severity.CRITICAL),
    ("SEC012", "google-oauth-secret", "Google OAuth client secret", Severity.CRITICAL),
    ("SEC013", "sendgrid-key", "SendGrid API key", Severity.CRITICAL),
    ("SEC014", "twilio-key-sid", "Twilio API key SID", Severity.HIGH),
    ("SEC015", "npm-token", "npm access token", Severity.CRITICAL),
    ("SEC016", "pypi-token", "PyPI upload token", Severity.CRITICAL),
    ("SEC017", "dockerhub-token", "Docker Hub access token", Severity.CRITICAL),
    ("SEC018", "slack-webhook", "Slack incoming webhook URL", Severity.HIGH),
    ("SEC019", "huggingface-token", "Hugging Face access token", Severity.HIGH),
    ("SEC020", "url-credentials", "Credentials embedded in a URL", Severity.HIGH),
    ("SEC021", "gcp-service-account", "Google service account key file", Severity.CRITICAL),
    # Inherits the severity of whatever it decodes to, so the worst case is
    # the worst case of every provider rule.
    ("SEC022", "base64-wrapped-credential", "Provider credential hidden inside base64", Severity.CRITICAL),
    ("SEC100", "entropy-quoted", "High-entropy value assigned to a secret-shaped name", Severity.HIGH),
    ("SEC101", "entropy-value-position", "High-entropy value in an unquoted config value position", Severity.HIGH),
    ("SEC900", "unterminated-suppression", "Suppression block opened and never closed", Severity.MEDIUM),
    ("WF001", "action-not-pinned", "Action pinned to a mutable tag, or not pinned at all", Severity.MEDIUM),
    ("WF002", "no-permissions", "Job inherits the default GITHUB_TOKEN permissions", Severity.MEDIUM),
    ("WF003", "script-injection", "Attacker-controlled context interpolated into a run: block", Severity.CRITICAL),
    ("WF004", "pull-request-target-checkout", "pull_request_target checking out untrusted code", Severity.CRITICAL),
    ("WF005", "write-all-permissions", "GITHUB_TOKEN granted write-all", Severity.HIGH),
    ("WF006", "self-hosted-runner", "Job runs on a self-hosted runner", Severity.MEDIUM),
    ("WF007", "secret-to-third-party", "Secret passed as input to a third-party action", Severity.MEDIUM),
    ("WF008", "workflow-run-checkout", "workflow_run checking out untrusted code", Severity.CRITICAL),
    ("WF009", "persisted-credentials", "Checkout leaves a usable token in .git/config", Severity.HIGH),
    ("WF010", "secret-exported", "Secret written to a job output or environment", Severity.HIGH),
    ("GL001", "floating-job-image", "Pipeline image tag can point elsewhere tomorrow", Severity.MEDIUM),
    ("GL002", "gitlab-script-injection", "Outsider-supplied variable interpolated into a script", Severity.CRITICAL),
    ("GL003", "gitlab-pipe-to-shell", "Job pipes a download into a shell", Severity.HIGH),
    ("GL004", "debug-trace", "CI_DEBUG_TRACE writes every variable to the job log", Severity.HIGH),
    ("DK001", "unpinned-base-image", "Base image not pinned to a digest", Severity.MEDIUM),
    ("DK002", "root-container", "Final image runs as root", Severity.MEDIUM),
    ("DK003", "pipe-to-shell", "Build step pipes a download into a shell", Severity.HIGH),
    ("DK004", "secret-in-layer", "Credential baked into an image layer", Severity.HIGH),
    ("DK005", "add-remote-url", "ADD fetches a remote URL without verification", Severity.MEDIUM),
    ("DK006", "insecure-fetch", "Build step disables transport security", Severity.MEDIUM),
    ("TF001", "open-ingress", "Security group admits 0.0.0.0/0", Severity.CRITICAL),
    ("TF002", "public-storage", "Storage granted to the public or to every account", Severity.HIGH),
    ("TF003", "encryption-disabled", "Encryption at rest explicitly switched off", Severity.MEDIUM),
    ("TF004", "wildcard-policy", "Policy allows every action on every resource", Severity.HIGH),
    ("TF005", "public-database", "Managed database given a public endpoint", Severity.HIGH),
    ("TF006", "unencrypted-state", "Terraform state stored without encryption", Severity.MEDIUM),
    ("TF007", "plaintext-transport", "Service accepts unencrypted connections", Severity.HIGH),
    ("SC001", "plaintext-package-source", "Packages fetched over plain HTTP", Severity.HIGH),
    ("SC002", "install-script-executes-download", "Install-time script downloads code and runs it", Severity.HIGH),
    ("SC003", "unpinned-source-dependency", "Dependency comes from a source that can move", Severity.MEDIUM),
    ("SC004", "package-verification-disabled", "Package manager skips certificate verification", Severity.HIGH),
    ("CF001", "cfn-open-ingress", "Security group admits 0.0.0.0/0", Severity.CRITICAL),
    ("CF002", "cfn-public-bucket", "Bucket granted to the public", Severity.HIGH),
    ("CF003", "cfn-encryption-disabled", "Encryption at rest explicitly switched off", Severity.MEDIUM),
    ("CF004", "cfn-wildcard-policy", "Policy allows every action on every resource", Severity.HIGH),
    ("CF005", "cfn-public-database", "Managed database given a public endpoint", Severity.HIGH),
    ("K8S001", "privileged-container", "Container runs privileged", Severity.CRITICAL),
    ("K8S002", "host-path-mount", "Volume mounts a path from the node", Severity.CRITICAL),
    ("K8S003", "host-namespace", "Pod shares a namespace with the node", Severity.HIGH),
    ("K8S004", "no-resource-limits", "Container declares no resource limits", Severity.LOW),
    ("K8S005", "runs-as-root", "Container declares that it runs as root", Severity.MEDIUM),
    ("K8S006", "capability-granted", "Privilege handed back after being dropped", Severity.HIGH),
    ("K8S007", "secret-in-manifest", "Credential committed inside a Secret manifest", Severity.CRITICAL),
    ("K8S008", "floating-image", "Container image tag can point elsewhere tomorrow", Severity.MEDIUM),
    ("K8S009", "rbac-wildcard", "Role grants every verb on every resource", Severity.CRITICAL),
    ("K8S010", "rbac-binds-everyone", "Binding grants to anonymous or all authenticated users", Severity.CRITICAL),
    ("DC001", "privileged-service", "Compose service runs privileged", Severity.CRITICAL),
    ("DC002", "host-bind-mount", "Service bind-mounts a path that grants the host", Severity.CRITICAL),
    ("DC003", "host-namespace-share", "Service shares a host namespace", Severity.HIGH),
    ("DC004", "confinement-removed", "Capability added or confinement disabled", Severity.HIGH),
    ("DC005", "port-on-every-interface", "Sensitive port published on every interface", Severity.HIGH),
    ("FN001", "committed-key-file", "A file that is private key material by name", Severity.CRITICAL),
    ("FN002", "unreadable-key-candidate", "A key-shaped file nothing could read", Severity.MEDIUM),
    ("FN003", "committed-credential-file", "A file whose purpose is to hold a credential", Severity.MEDIUM),
    ("DC006", "floating-compose-image", "Service image tag can point elsewhere tomorrow", Severity.LOW),
)


def matcher(patterns: "Sequence[str]"):
    """Build a predicate over rule ids, for the places a person names rules.

    Patterns are rule ids or a family prefix ending in ``*`` -- ``K8S004``,
    ``DC*``. Matching is case-insensitive because nobody remembers whether it
    was ``k8s`` or ``K8S`` at the moment they are silencing something.

    Both callers matter and are different: a project switching a rule off in
    its config, and a line in a file saying which rule it means to suppress.
    Sharing the syntax means the answer to "what do I write here" is the same
    in both places.
    """
    exact = {pattern.strip().upper() for pattern in patterns if not pattern.strip().endswith("*")}
    prefixes = tuple(
        pattern.strip()[:-1].upper() for pattern in patterns if pattern.strip().endswith("*")
    )

    def matches(rule_id: str) -> bool:
        upper = rule_id.upper()
        return upper in exact or (bool(prefixes) and upper.startswith(prefixes))

    return matches


def get(rule_id: str) -> "Rule | None":
    return RULES.get(rule_id)


def by_category() -> "dict[str, list[Rule]]":
    """The catalogue grouped for printing, in catalogue order."""
    grouped: "dict[str, list[Rule]]" = {}
    for rule in RULES.values():
        grouped.setdefault(rule.category, []).append(rule)
    return grouped
