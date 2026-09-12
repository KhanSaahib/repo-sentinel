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
from collections.abc import Iterable

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

    @property
    def cwe(self) -> "str | None":
        """The weakness class this rule reports, as a CWE identifier.

        Useful to anyone who has to map findings onto a framework they did not
        choose, and to SARIF consumers that group by weakness. It is a claim
        rather than a decoration -- ``None`` where no class fits, which is the
        honest answer for the scanner's own hygiene checks.
        """
        return _CWE.get(self.id)


_CATEGORIES = {"SEC": "secrets", "WF0": "workflows", "DK0": "dockerfiles", "TF0": "terraform", "K8S": "kubernetes", "DC0": "compose", "FN0": "filenames", "GL0": "gitlab", "CF0": "cloudformation", "SC0": "dependencies", "AN0": "ansible", "AZ0": "azure", "CC0": "circleci", "JK0": "jenkins", "SH0": "shell"}


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
    ("SEC023", "gitlab-pat", "GitLab personal access token", Severity.CRITICAL),
    ("SEC024", "gitlab-runner-token", "GitLab runner registration token", Severity.CRITICAL),
    ("SEC025", "digitalocean-token", "DigitalOcean personal access token", Severity.CRITICAL),
    ("SEC026", "shopify-token", "Shopify access token", Severity.CRITICAL),
    ("SEC027", "databricks-token", "Databricks personal access token", Severity.CRITICAL),
    ("SEC028", "doppler-token", "Doppler service token", Severity.CRITICAL),
    ("SEC029", "grafana-token", "Grafana service account token", Severity.HIGH),
    ("SEC030", "telegram-bot-token", "Telegram bot token", Severity.HIGH),
    ("SEC031", "postman-key", "Postman API key", Severity.HIGH),
    ("SEC032", "linear-key", "Linear API key", Severity.HIGH),
    ("SEC033", "atlassian-token", "Atlassian API token", Severity.HIGH),
    ("SEC034", "square-token", "Square access token", Severity.CRITICAL),
    ("SEC035", "slack-app-token", "Slack app-level token", Severity.HIGH),
    ("SEC036", "discord-bot-token", "Discord bot token", Severity.CRITICAL),
    ("SEC037", "mailgun-key", "Mailgun API key", Severity.HIGH),
    ("SEC038", "mailchimp-key", "Mailchimp API key", Severity.HIGH),
    ("SEC039", "newrelic-key", "New Relic API key", Severity.HIGH),
    ("SEC040", "sentry-dsn", "Sentry DSN", Severity.MEDIUM),
    ("SEC041", "asana-token", "Asana personal access token", Severity.HIGH),
    ("SEC042", "dropbox-token", "Dropbox access token", Severity.CRITICAL),
    ("SEC043", "figma-token", "Figma personal access token", Severity.HIGH),
    ("SEC044", "airtable-token", "Airtable personal access token", Severity.HIGH),
    ("SEC045", "artifactory-token", "JFrog Artifactory token", Severity.CRITICAL),
    ("SEC046", "terraform-cloud-token", "Terraform Cloud API token", Severity.CRITICAL),
    ("SEC047", "fcm-server-key", "Firebase Cloud Messaging server key", Severity.HIGH),
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
    ("WF011", "secrets-inherited-offsite", "Every secret passed to a workflow in another repository", Severity.HIGH),
    ("WF012", "action-input-interpolated", "Composite action interpolates an input into a shell command", Severity.MEDIUM),
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
    ("SH001", "script-downloads-and-runs", "Script downloads code and runs it in one step", Severity.HIGH),
    ("SH002", "script-skips-verification", "Script disables certificate verification", Severity.MEDIUM),
    ("SH003", "script-world-writable", "Script makes something world-writable", Severity.MEDIUM),
    ("SC001", "plaintext-package-source", "Packages fetched over plain HTTP", Severity.HIGH),
    ("SC002", "install-script-executes-download", "Install-time script downloads code and runs it", Severity.HIGH),
    ("SC003", "unpinned-source-dependency", "Dependency comes from a source that can move", Severity.MEDIUM),
    ("SC004", "package-verification-disabled", "Package manager skips certificate verification", Severity.HIGH),
    ("AN001", "ansible-verification-off", "Task skips certificate verification", Severity.HIGH),
    ("AN002", "world-writable-mode", "Task sets a world-writable file mode", Severity.MEDIUM),
    ("AN003", "ansible-plaintext-fetch", "Task fetches over plain HTTP", Severity.MEDIUM),
    ("AZ001", "azure-script-injection", "Outsider-supplied variable expanded into a command", Severity.CRITICAL),
    ("AZ002", "azure-self-hosted-pool", "Pipeline runs on a self-hosted pool", Severity.MEDIUM),
    ("AZ003", "azure-floating-container", "Pipeline container image can point elsewhere tomorrow", Severity.MEDIUM),
    ("AZ004", "azure-debug-logging", "system.debug writes every variable to the job log", Severity.HIGH),
    ("CC001", "circleci-script-injection", "Outsider-supplied variable expanded into a command", Severity.CRITICAL),
    ("CC002", "moving-orb", "Orb pinned to a reference the registry moves", Severity.HIGH),
    ("CC003", "circleci-floating-image", "Job image can point elsewhere tomorrow", Severity.MEDIUM),
    ("CC004", "circleci-pipe-to-shell", "Step pipes a download into a shell", Severity.HIGH),
    ("JK001", "groovy-interpolation", "Groovy interpolates outsider text into a shell step", Severity.CRITICAL),
    ("JK002", "jenkins-floating-image", "Agent image can point elsewhere tomorrow", Severity.MEDIUM),
    ("JK003", "jenkins-pipe-to-shell", "Shell step pipes a download into a shell", Severity.HIGH),
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
    ("K8S011", "host-port", "Container port bound on the node itself", Severity.HIGH),
    ("DC001", "privileged-service", "Compose service runs privileged", Severity.CRITICAL),
    ("DC002", "host-bind-mount", "Service bind-mounts a path that grants the host", Severity.CRITICAL),
    ("DC003", "host-namespace-share", "Service shares a host namespace", Severity.HIGH),
    ("DC004", "confinement-removed", "Capability added or confinement disabled", Severity.HIGH),
    ("DC005", "port-on-every-interface", "Sensitive port published on every interface", Severity.HIGH),
    ("FN001", "committed-key-file", "A file that is private key material by name", Severity.CRITICAL),
    ("FN002", "unreadable-key-candidate", "A key-shaped file nothing could read", Severity.MEDIUM),
    ("FN003", "committed-credential-file", "A file whose purpose is to hold a credential", Severity.MEDIUM),
    ("FN004", "secret-bearing-byproduct", "A file that records secrets as a side effect", Severity.CRITICAL),
    ("DC006", "floating-compose-image", "Service image tag can point elsewhere tomorrow", Severity.LOW),
)


#: The weakness each rule reports. Grouped by the claim rather than by family,
#: because the claim is what a reader checking this list cares about: five CI
#: systems share one injection weakness, and "unpinned" means the same thing
#: for an action, an orb, a base image and a dependency.
#:
#: SEC900 has no entry on purpose. It reports that a suppression block was left
#: open, which is a mistake in this tool's own configuration rather than a
#: weakness in anybody's software.
_CWE: "dict[str, str]" = {}


def _claim(cwe: str, *rule_ids: str) -> None:
    for rule_id in rule_ids:
        _CWE[rule_id] = cwe


# Use of hard-coded credentials.
_claim(
    "CWE-798",
    *[f"SEC{index:03d}" for index in range(1, 48)],
    "SEC100",
    "SEC101",
    "FN001",
    "FN002",
    "FN003",
    "DK004",
    "K8S007",
)
# Sensitive information in a file that should not hold it.
_claim("CWE-538", "FN004")
# OS command injection: the same weakness in five CI systems.
_claim("CWE-78", "WF003", "WF012", "GL002", "AZ001", "CC001", "JK001")
# Download of code without an integrity check.
_claim("CWE-494", "DK003", "DK005", "GL003", "CC004", "JK003", "SC002", "AN003", "SH001")
# Reliance on a component that can be replaced under you.
_claim(
    "CWE-1357",
    "WF001",
    "DK001",
    "K8S008",
    "DC006",
    "GL001",
    "AZ003",
    "CC002",
    "CC003",
    "JK002",
    "SC003",
)
# Cleartext transmission.
_claim("CWE-319", "SC001", "TF007")
# Improper certificate validation.
_claim("CWE-295", "SC004", "DK006", "AN001", "SH002")
# Execution with unnecessary privileges.
_claim("CWE-250", "DK002", "DC001", "DC004", "K8S001", "K8S005", "K8S006")
# Incorrect permission assignment for a critical resource.
_claim(
    "CWE-732",
    "WF002",
    "WF005",
    "TF002",
    "TF004",
    "CF002",
    "CF004",
    "K8S009",
    "K8S010",
    "AN002",
    "SH003",
)
# Improper access control: something reachable that should not be.
_claim("CWE-284", "TF001", "TF005", "CF001", "CF005", "DC005", "K8S011")
# Missing encryption of data at rest.
_claim("CWE-311", "TF003", "TF006", "CF003")
# Exposure of a resource to the wrong control sphere.
_claim("CWE-668", "K8S002", "K8S003", "DC002", "DC003", "WF006", "WF011", "AZ002")
# Inclusion of functionality from an untrusted control sphere.
_claim("CWE-829", "WF004", "WF007", "WF008")
# Insufficiently protected credentials, and credentials written to a log.
_claim("CWE-522", "WF009")
_claim("CWE-532", "WF010", "GL004", "AZ004")
# Allocation of resources without limits.
_claim("CWE-770", "K8S004")


def matcher(patterns: "Iterable[str]"):
    """Build a predicate over rule ids, for the places a person names rules.

    Patterns are rule ids or a family prefix ending in ``*`` -- ``K8S004``,
    ``DC*``. Matching is case-insensitive because nobody remembers whether it
    was ``k8s`` or ``K8S`` at the moment they are silencing something.

    Both callers matter and are different: a project switching a rule off in
    its config, and a line in a file saying which rule it means to suppress.
    Sharing the syntax means the answer to "what do I write here" is the same
    in both places.
    """
    cleaned = [pattern.strip() for pattern in patterns]
    exact = {pattern.upper() for pattern in cleaned if not pattern.endswith("*")}
    prefixes = tuple(pattern[:-1].upper() for pattern in cleaned if pattern.endswith("*"))

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
