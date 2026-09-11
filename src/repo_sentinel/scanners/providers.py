"""The credential shapes this scanner knows by sight.

Separated from :mod:`.secrets` because the two change for different reasons and
at different rates. This file is a table: a new provider publishes a token
prefix and an entry gets added, which is a five-minute change somebody makes
without needing to understand how the scanning works. What is left next door is
the machinery -- entropy, encoding, suppression, context -- which changes
rarely and carefully.

Every entry matches on structure a vendor documents, so every entry is high
confidence unless it says otherwise. Two do say otherwise, and both explain
themselves where they sit.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Callable, Iterator
from typing import Optional, Union

from ..findings import Confidence, Severity, redact
from ..heuristics import looks_like_placeholder


@dataclasses.dataclass(frozen=True)
class ProviderRule:
    """One credential shape, and what to say when it turns up."""

    rule_id: str
    title: str
    severity: Severity
    pattern: "re.Pattern[str]"
    remediation: str
    confidence: Confidence = Confidence.HIGH
    #: Which group holds the credential itself. Group 0 -- the whole match --
    #: is the common case; a named group is used where the match carries
    #: context worth keeping in the report, such as the host a URL points at.
    secret_group: Union[int, str] = 0
    #: Optional second opinion, for shapes loose enough to need one.
    reject: Optional[Callable[["re.Match[str]"], bool]] = None


#: ``scheme://user:password@host`` is how every manual writes a connection
#: string, so a bare lowercase word in the password position is documentation
#: far more often than it is a credential. Real ones carry a digit, a capital
#: or a symbol; the ones that do not are a weak-password problem rather than a
#: leaked-password one, and this is not that tool.
_PROSE_PASSWORD = re.compile(r"[a-z]{1,12}$")


def _url_credential_is_noise(match: "re.Match[str]") -> bool:
    """Filter for SEC020: most ``user:pass@host`` matches are documentation."""
    password = match.group("password")
    if looks_like_placeholder(password) or len(set(password)) <= 3:
        return True
    if _PROSE_PASSWORD.match(password):
        return True
    return looks_like_placeholder(match.group(0))


RULES: tuple[ProviderRule, ...] = (
    ProviderRule(
        "SEC001",
        "AWS access key id",
        Severity.CRITICAL,
        re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b"),
        "Deactivate the key in IAM, then rotate it. Deleting the commit is not enough.",
    ),
    ProviderRule(
        "SEC002",
        "GitHub personal access token",
        Severity.CRITICAL,
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,251}\b"),
        "Revoke the token at github.com/settings/tokens and issue a new one.",
    ),
    ProviderRule(
        "SEC003",
        "GitHub fine-grained token",
        Severity.CRITICAL,
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
        "Revoke the token at github.com/settings/tokens and issue a new one.",
    ),
    ProviderRule(
        "SEC004",
        "Private key block",
        Severity.CRITICAL,
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        "Treat the key as compromised: generate a new pair and rotate every authorized_keys entry.",
    ),
    ProviderRule(
        "SEC005",
        "Stripe live secret key",
        Severity.CRITICAL,
        re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}\b"),
        "Roll the key in the Stripe dashboard immediately.",
    ),
    ProviderRule(
        "SEC006",
        "Slack token",
        Severity.HIGH,
        re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
        "Revoke the token in the Slack app configuration.",
    ),
    ProviderRule(
        "SEC007",
        "Google API key",
        Severity.HIGH,
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "Delete the key in the Google Cloud console and add API restrictions to its replacement.",
    ),
    ProviderRule(
        "SEC008",
        "OpenAI-style API key",
        Severity.HIGH,
        re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b"),
        "Revoke the key in the provider dashboard.",
    ),
    ProviderRule(
        "SEC009",
        "JSON Web Token",
        Severity.MEDIUM,
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "Check what the token grants; if it is a live session or service token, invalidate it.",
    ),
    ProviderRule(
        "SEC010",
        "Stripe test key",
        Severity.LOW,
        re.compile(r"\b[sr]k_test_[A-Za-z0-9]{16,}\b"),
        "Test keys are low risk, but keep them out of version control anyway.",
    ),
    ProviderRule(
        "SEC011",
        "Azure storage account key",
        Severity.CRITICAL,
        re.compile(r"AccountKey=(?P<key>[A-Za-z0-9+/]{86}==)"),
        "Rotate the key in the storage account, then switch clients to a SAS token or managed identity.",
        secret_group="key",
    ),
    ProviderRule(
        "SEC012",
        "Google OAuth client secret",
        Severity.CRITICAL,
        re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{28}\b"),
        "Reset the client secret in the Google Cloud console credentials page.",
    ),
    ProviderRule(
        "SEC013",
        "SendGrid API key",
        Severity.CRITICAL,
        re.compile(r"\bSG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}\b"),
        "Delete the key in SendGrid settings; it can send mail as your domain.",
    ),
    ProviderRule(
        "SEC014",
        "Twilio API key SID",
        Severity.HIGH,
        # Loose by nature: 32 hex characters behind a two-letter prefix. Real,
        # but not distinctive enough to assert on its own, hence the confidence.
        re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
        "Delete the key in the Twilio console. Its paired secret is shown only once, so treat both as lost.",
        confidence=Confidence.MEDIUM,
    ),
    ProviderRule(
        "SEC015",
        "npm access token",
        Severity.CRITICAL,
        re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        "Revoke the token at npmjs.com/settings/~/tokens; it can publish under your account.",
    ),
    ProviderRule(
        "SEC016",
        "PyPI upload token",
        Severity.CRITICAL,
        re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}"),
        "Revoke the token in your PyPI account settings; it can publish releases of your project.",
    ),
    ProviderRule(
        "SEC017",
        "Docker Hub access token",
        Severity.CRITICAL,
        re.compile(r"\bdckr_pat_[A-Za-z0-9_-]{20,}\b"),
        "Delete the token in Docker Hub security settings; it can push images others will run.",
    ),
    ProviderRule(
        "SEC018",
        "Slack incoming webhook URL",
        Severity.HIGH,
        re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_/+-]{20,}"),
        "Anyone holding the URL can post as the app. Regenerate the webhook in the Slack app configuration.",
    ),
    ProviderRule(
        "SEC019",
        "Hugging Face access token",
        Severity.HIGH,
        re.compile(r"\bhf_[A-Za-z0-9]{34}\b"),
        "Revoke the token at huggingface.co/settings/tokens.",
    ),
    ProviderRule(
        "SEC020",
        "Credentials embedded in a URL",
        Severity.HIGH,
        re.compile(
            r"\b(?P<scheme>[a-z][a-z0-9+.-]{1,15})://"
            r"(?P<user>[^\s/:@]{1,64}):(?P<password>[^\s/:@]{3,128})@(?P<host>[^\s/:@]+)",
            re.IGNORECASE,
        ),
        "Move the password out of the connection string; most clients accept it from the environment instead.",
        confidence=Confidence.MEDIUM,
        secret_group="password",
        reject=_url_credential_is_noise,
    ),
    ProviderRule(
        "SEC023",
        "GitLab personal access token",
        Severity.CRITICAL,
        re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
        "Revoke it in GitLab under Preferences, Access Tokens. It carries your own permissions.",
    ),
    ProviderRule(
        "SEC024",
        "GitLab runner registration token",
        Severity.CRITICAL,
        re.compile(r"\bglrt-[A-Za-z0-9_-]{20,}\b"),
        "Reset it in the project's CI/CD settings. It lets anyone register a runner and receive jobs.",
    ),
    ProviderRule(
        "SEC025",
        "DigitalOcean personal access token",
        Severity.CRITICAL,
        re.compile(r"\bdop_v1_[a-f0-9]{64}\b"),
        "Revoke it in the DigitalOcean API settings; it can create and destroy droplets.",
    ),
    ProviderRule(
        "SEC026",
        "Shopify access token",
        Severity.CRITICAL,
        re.compile(r"\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b"),
        "Revoke it in the Shopify admin; depending on its scopes it can read orders and customers.",
    ),
    ProviderRule(
        "SEC027",
        "Databricks personal access token",
        Severity.CRITICAL,
        re.compile(r"\bdapi[a-f0-9]{32}(?:-\d+)?\b"),
        "Revoke it in the Databricks workspace settings; it can run jobs against your data.",
    ),
    ProviderRule(
        "SEC028",
        "Doppler service token",
        Severity.CRITICAL,
        re.compile(r"\bdp\.(?:pt|st|sa|ct)\.[A-Za-z0-9]{40,}\b"),
        "Revoke it in Doppler. A token to a secrets manager is every secret it holds.",
    ),
    ProviderRule(
        "SEC029",
        "Grafana service account token",
        Severity.HIGH,
        re.compile(r"\bgl(?:sa|c)_[A-Za-z0-9_]{32,}\b"),
        "Revoke it in Grafana under Administration, Service accounts.",
    ),
    ProviderRule(
        "SEC030",
        "Telegram bot token",
        Severity.HIGH,
        re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"),
        "Revoke it with BotFather. Anyone holding it can read and send as the bot.",
    ),
    ProviderRule(
        "SEC031",
        "Postman API key",
        Severity.HIGH,
        re.compile(r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b"),
        "Revoke it in Postman; it can read every collection and environment in the workspace.",
    ),
    ProviderRule(
        "SEC032",
        "Linear API key",
        Severity.HIGH,
        re.compile(r"\blin_api_[A-Za-z0-9]{40}\b"),
        "Revoke it in Linear under Settings, API.",
    ),
    ProviderRule(
        "SEC033",
        "Atlassian API token",
        Severity.HIGH,
        re.compile(r"\bATATT3x[A-Za-z0-9_\-=]{100,}"),
        "Revoke it at id.atlassian.com under API tokens; it acts as the account that made it.",
    ),
    ProviderRule(
        "SEC034",
        "Square access token",
        Severity.CRITICAL,
        re.compile(r"\b(?:sq0atp-[A-Za-z0-9_-]{22}|EAAA[A-Za-z0-9_-]{56,})\b"),
        "Revoke it in the Square dashboard; a live token can move money.",
    ),
    ProviderRule(
        "SEC035",
        "Slack app-level token",
        Severity.HIGH,
        re.compile(r"\bxapp-\d-[A-Z0-9]+-\d+-[a-f0-9]{32,}\b"),
        "Regenerate it in the Slack app configuration; it authenticates the app itself.",
    ),
    ProviderRule(
        "SEC036",
        "Discord bot token",
        Severity.CRITICAL,
        re.compile(r"\b[MNO][A-Za-z\d_-]{23,25}\.[\w-]{6}\.[\w-]{27,}\b"),
        "Regenerate it in the Discord developer portal; it can act as the bot in every guild.",
    ),
    ProviderRule(
        "SEC037",
        "Mailgun API key",
        Severity.HIGH,
        re.compile(r"\bkey-[0-9a-f]{32}\b"),
        "Rotate it in the Mailgun dashboard; it can send mail as your domain.",
    ),
    ProviderRule(
        "SEC038",
        "Mailchimp API key",
        Severity.HIGH,
        re.compile(r"\b[0-9a-f]{32}-us\d{1,2}\b"),
        "Revoke it in the Mailchimp account settings; it reaches your whole audience list.",
    ),
    ProviderRule(
        "SEC039",
        "New Relic API key",
        Severity.HIGH,
        re.compile(r"\bNRAK-[A-Z0-9]{27}\b|\b[a-f0-9]{40}NRAL\b"),
        "Revoke it in the New Relic API keys page.",
    ),
    ProviderRule(
        "SEC040",
        "Sentry DSN",
        Severity.MEDIUM,
        re.compile(r"https://[0-9a-f]{32}@[\w.-]+/\d+"),
        "A DSN lets anyone send events as your project, which is enough to fill a quota or bury a real alert.",
        confidence=Confidence.MEDIUM,
    ),
    ProviderRule(
        "SEC041",
        "Asana personal access token",
        Severity.HIGH,
        re.compile(r"\b1/\d{16}:[0-9a-f]{32}\b"),
        "Revoke it in Asana under My Settings, Apps.",
    ),
    ProviderRule(
        "SEC042",
        "Dropbox access token",
        Severity.CRITICAL,
        re.compile(r"\bsl\.[A-Za-z0-9_-]{130,}"),
        "Revoke it in the Dropbox app console; it reads and writes the account's files.",
    ),
    ProviderRule(
        "SEC043",
        "Figma personal access token",
        Severity.HIGH,
        re.compile(r"\bfigd_[A-Za-z0-9_-]{40,}\b"),
        "Revoke it in Figma under Settings, Personal access tokens.",
    ),
    ProviderRule(
        "SEC044",
        "Airtable personal access token",
        Severity.HIGH,
        re.compile(r"\bpat[A-Za-z0-9]{14}\.[0-9a-f]{64}\b"),
        "Revoke it in the Airtable builder hub; it reads every base the token was scoped to.",
    ),
    ProviderRule(
        "SEC045",
        "JFrog Artifactory token",
        Severity.CRITICAL,
        re.compile(r"\bAKCp8[A-Za-z0-9]{60,}\b"),
        "Revoke it in Artifactory; it can publish artifacts that your builds will install.",
    ),
    ProviderRule(
        "SEC046",
        "Terraform Cloud API token",
        Severity.CRITICAL,
        re.compile(r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{40,}"),
        "Revoke it in Terraform Cloud; it can read state, which holds every secret a plan touched.",
    ),
    ProviderRule(
        "SEC047",
        "Firebase Cloud Messaging server key",
        Severity.HIGH,
        re.compile(r"\bAAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{130,}"),
        "Rotate it in the Firebase console; it can push notifications to every installed app.",
    ),
)

#: One alternation of every provider pattern, used only to answer "is there any
#: point looking closer at this line". Almost no line in a repository contains a
#: credential, and running twenty patterns over each of them to discover that is
#: most of the time this scanner spends. Built from the rules themselves rather
#: than hand-written, so it cannot drift away from what it is standing in for;
#: named groups are stripped because two rules may reuse a group name and the
#: combined pattern would not compile.
#: A gate in front of the gate. Every provider rule needs either a long run of
#: credential characters, a PEM header, or a URL carrying a password -- and
#: four fifths of the lines in a repository have none of the three. Testing
#: that first halves the cost of the pass, because one simple pattern is much
#: cheaper for the engine than an alternation of twenty.
#:
#: It is a correctness risk as well as a speed win: a line this rejects is
#: never looked at again. The corpus test asserts that every provider rule's
#: example clears it, which is what keeps the threshold honest.
_CANDIDATE = re.compile(r"[A-Za-z0-9+/_=-]{14}|-----BEGIN|://[^\s/]*:[^\s/]*@")

_ANY_PROVIDER = re.compile(
    "|".join(
        "(?{flags}:{body})".format(
            flags="i" if rule.pattern.flags & re.IGNORECASE else "",
            body=re.sub(r"\(\?P<\w+>", "(?:", rule.pattern.pattern),
        )
        for rule in RULES
    )
)

#: One alternation of every provider pattern, used only to answer "is there any
#: point looking closer at this line". Almost no line in a repository contains a
#: credential, and running twenty patterns over each of them to discover that is
#: most of the time this scanner spends. Built from the rules themselves rather
#: than hand-written, so it cannot drift away from what it is standing in for;
#: named groups are stripped because two rules may reuse a group name and the
#: combined pattern would not compile.
#: A gate in front of the gate. Every provider rule needs either a long run of
#: credential characters, a PEM header, or a URL carrying a password -- and
#: four fifths of the lines in a repository have none of the three. Testing
#: that first halves the cost of the pass, because one simple pattern is much
#: cheaper for the engine than an alternation of twenty.
#:
#: It is a correctness risk as well as a speed win: a line this rejects is
#: never looked at again. The corpus test asserts that every provider rule's
#: example clears it, which is what keeps the threshold honest.
_CANDIDATE = re.compile(r"[A-Za-z0-9+/_=-]{14}|-----BEGIN|://[^\s/]*:[^\s/]*@")

_ANY_PROVIDER = re.compile(
    "|".join(
        "(?{flags}:{body})".format(
            flags="i" if rule.pattern.flags & re.IGNORECASE else "",
            body=re.sub(r"\(\?P<\w+>", "(?:", rule.pattern.pattern),
        )
        for rule in RULES
    )
)

#: A run of base64 long enough to be hiding something. Encoding is not
#: encryption, but it is enough to make a credential invisible to every rule
#: that reads the line it sits on -- kubeconfigs, CI variables and manifests
#: are full of them -- so SEC022 decodes these and asks the provider rules
#: what they see.
#: Two alphabets, scanned separately on purpose. A single class containing
#: both would swallow the name in front of the value -- "TOKEN=QUtJ..." is one
#: unbroken run of it -- and the joined string decodes to nothing, which is how
#: a rule quietly stops firing.
_BASE64_RUNS = (
    re.compile(r"[A-Za-z0-9+/]{24,}"),
    re.compile(r"[A-Za-z0-9_-]{24,}"),
)

#: The two fields that together make a file a Google service account key.
#: Either alone is unremarkable; the pair is a credential with no expiry that
#: is accepted by every Google API the account can reach.
_SERVICE_ACCOUNT_TYPE = re.compile(r'"type"\s*:\s*"service_account"')
#: The key field *and its value*: a chart shipping a template service account
#: with "private_key": "" is showing the shape, not leaking the key.
_SERVICE_ACCOUNT_KEY = re.compile(r'"private_key(?:_id)?"\s*:\s*"(?P<value>[^"]*)"')


#: One alternation of every provider pattern, used only to answer "is there any
#: point looking closer at this line". Almost no line in a repository contains a
#: credential, and running thirty-four patterns over each of them to discover
#: that is most of the time this scanner spends. Built from the rules
#: themselves rather than hand-written, so it cannot drift away from what it is
#: standing in for; named groups are stripped because two rules may reuse a
#: group name and the combined pattern would not compile.
ANY = re.compile(
    "|".join(
        "(?{flags}:{body})".format(
            flags="i" if rule.pattern.flags & re.IGNORECASE else "",
            body=re.sub(r"\(\?P<\w+>", "(?:", rule.pattern.pattern),
        )
        for rule in RULES
    )
)

#: A gate in front of the gate. Every provider rule needs either a long run of
#: credential characters, a PEM header, or a URL carrying a password -- and
#: four fifths of the lines in a repository have none of the three. Testing
#: that first halves the cost of the pass, because one simple pattern is much
#: cheaper for the engine than an alternation of thirty-four.
#:
#: It is a correctness risk as well as a speed win: a line this rejects is
#: never looked at again. The corpus test asserts that every provider rule's
#: example clears it, which is what keeps the threshold honest.
CANDIDATE = re.compile(r"[A-Za-z0-9+/_=-]{14}|-----BEGIN|://[^\s/]*:[^\s/]*@")


def evidence_for(match: "re.Match[str]", rule: ProviderRule) -> str:
    """Redact the credential while keeping whatever context the match carries."""
    if rule.secret_group == 0:
        return redact(match.group(0))
    start, end = match.span(rule.secret_group)
    whole_start = match.start()
    text = match.group(0)
    return (
        text[: start - whole_start]
        + redact(match.group(rule.secret_group))
        + text[end - whole_start :]
    )


def findings_in(
    path: str,
    line_number: int,
    line: str,
    matched_spans: "list[tuple[int, int]]",
    allow_examples: bool,
    is_known_example: "Callable[[str], bool]",
) -> "Iterator[tuple[ProviderRule, str, str]]":
    """Yield ``(rule, secret, evidence)`` for every shape matched on one line.

    Spans of everything matched are recorded even when the match is dropped as
    a known example, so that a value the allowlist silenced cannot resurface
    under the entropy rules.

    The allowlist arrives as an argument rather than an import: this module is
    a table of shapes, and which of them are public documentation is a
    different question, asked by a different file.
    """
    if not CANDIDATE.search(line) or not ANY.search(line):
        return
    for rule in RULES:
        for match in rule.pattern.finditer(line):
            secret = match.group(rule.secret_group)
            matched_spans.append(match.span(rule.secret_group))
            if rule.reject is not None and rule.reject(match):
                continue
            if allow_examples and is_known_example(secret):
                continue
            yield rule, secret, evidence_for(match, rule)
