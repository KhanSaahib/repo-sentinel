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
    #: Literal substrings, at least one of which appears in *every* string this
    #: pattern can match. Testing for them is what makes a scan of a large
    #: repository finish: a substring search is an order of magnitude cheaper
    #: than running the pattern, and nine out of ten candidate lines have none
    #: of these in them.
    #:
    #: An empty tuple means "no literal exists", and the rule's pattern then
    #: runs on every candidate line. That costs speed. A *wrong* hint costs
    #: coverage, silently, which is why the corpus test exists: every rule has
    #: to fire on a line carrying its own shape, and a hint absent from that
    #: line stops it.
    hints: "tuple[str, ...]" = ()


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
        hints=("AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA"),
    ),
    ProviderRule(
        "SEC002",
        "GitHub personal access token",
        Severity.CRITICAL,
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,251}\b"),
        "Revoke the token at github.com/settings/tokens and issue a new one.",
        hints=("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
    ),
    ProviderRule(
        "SEC003",
        "GitHub fine-grained token",
        Severity.CRITICAL,
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
        "Revoke the token at github.com/settings/tokens and issue a new one.",
        hints=("github_pat_",),
    ),
    ProviderRule(
        "SEC004",
        "Private key block",
        Severity.CRITICAL,
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        "Treat the key as compromised: generate a new pair and rotate every authorized_keys entry.",
        hints=("PRIVATE KEY",),
    ),
    ProviderRule(
        "SEC005",
        "Stripe live secret key",
        Severity.CRITICAL,
        re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}\b"),
        "Roll the key in the Stripe dashboard immediately.",
        hints=("k_live_",),
    ),
    ProviderRule(
        "SEC006",
        "Slack token",
        Severity.HIGH,
        re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
        "Revoke the token in the Slack app configuration.",
        hints=("xox",),
    ),
    ProviderRule(
        "SEC007",
        "Google API key",
        Severity.HIGH,
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "Delete the key in the Google Cloud console and add API restrictions to its replacement.",
        hints=("AIza",),
    ),
    ProviderRule(
        "SEC008",
        "OpenAI-style API key",
        Severity.HIGH,
        re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b"),
        "Revoke the key in the provider dashboard.",
        hints=("sk-",),
    ),
    ProviderRule(
        "SEC009",
        "JSON Web Token",
        Severity.MEDIUM,
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "Check what the token grants; if it is a live session or service token, invalidate it.",
        hints=("eyJ",),
    ),
    ProviderRule(
        "SEC010",
        "Stripe test key",
        Severity.LOW,
        re.compile(r"\b[sr]k_test_[A-Za-z0-9]{16,}\b"),
        "Test keys are low risk, but keep them out of version control anyway.",
        hints=("k_test_",),
    ),
    ProviderRule(
        "SEC011",
        "Azure storage account key",
        Severity.CRITICAL,
        re.compile(r"AccountKey=(?P<key>[A-Za-z0-9+/]{86}==)"),
        "Rotate the key in the storage account, then switch clients to a SAS token or managed identity.",
        secret_group="key",
        hints=("AccountKey=",),
    ),
    ProviderRule(
        "SEC012",
        "Google OAuth client secret",
        Severity.CRITICAL,
        re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{28}\b"),
        "Reset the client secret in the Google Cloud console credentials page.",
        hints=("GOCSPX-",),
    ),
    ProviderRule(
        "SEC013",
        "SendGrid API key",
        Severity.CRITICAL,
        re.compile(r"\bSG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}\b"),
        "Delete the key in SendGrid settings; it can send mail as your domain.",
        hints=("SG.",),
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
        hints=("SK",),
    ),
    ProviderRule(
        "SEC015",
        "npm access token",
        Severity.CRITICAL,
        re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        "Revoke the token at npmjs.com/settings/~/tokens; it can publish under your account.",
        hints=("npm_",),
    ),
    ProviderRule(
        "SEC016",
        "PyPI upload token",
        Severity.CRITICAL,
        re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}"),
        "Revoke the token in your PyPI account settings; it can publish releases of your project.",
        hints=("pypi-AgEIcHlwaS5vcmc",),
    ),
    ProviderRule(
        "SEC017",
        "Docker Hub access token",
        Severity.CRITICAL,
        re.compile(r"\bdckr_pat_[A-Za-z0-9_-]{20,}\b"),
        "Delete the token in Docker Hub security settings; it can push images others will run.",
        hints=("dckr_pat_",),
    ),
    ProviderRule(
        "SEC018",
        "Slack incoming webhook URL",
        Severity.HIGH,
        re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_/+-]{20,}"),
        "Anyone holding the URL can post as the app. Regenerate the webhook in the Slack app configuration.",
        hints=("hooks.slack.com",),
    ),
    ProviderRule(
        "SEC019",
        "Hugging Face access token",
        Severity.HIGH,
        re.compile(r"\bhf_[A-Za-z0-9]{34}\b"),
        "Revoke the token at huggingface.co/settings/tokens.",
        hints=("hf_",),
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
        hints=("://",),
    ),
    ProviderRule(
        "SEC023",
        "GitLab personal access token",
        Severity.CRITICAL,
        re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
        "Revoke it in GitLab under Preferences, Access Tokens. It carries your own permissions.",
        hints=("glpat-",),
    ),
    ProviderRule(
        "SEC024",
        "GitLab runner registration token",
        Severity.CRITICAL,
        re.compile(r"\bglrt-[A-Za-z0-9_-]{20,}\b"),
        "Reset it in the project's CI/CD settings. It lets anyone register a runner and receive jobs.",
        hints=("glrt-",),
    ),
    ProviderRule(
        "SEC025",
        "DigitalOcean personal access token",
        Severity.CRITICAL,
        re.compile(r"\bdop_v1_[a-f0-9]{64}\b"),
        "Revoke it in the DigitalOcean API settings; it can create and destroy droplets.",
        hints=("dop_v1_",),
    ),
    ProviderRule(
        "SEC026",
        "Shopify access token",
        Severity.CRITICAL,
        re.compile(r"\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b"),
        "Revoke it in the Shopify admin; depending on its scopes it can read orders and customers.",
        hints=("shpat_", "shpss_", "shpca_", "shppa_"),
    ),
    ProviderRule(
        "SEC027",
        "Databricks personal access token",
        Severity.CRITICAL,
        re.compile(r"\bdapi[a-f0-9]{32}(?:-\d+)?\b"),
        "Revoke it in the Databricks workspace settings; it can run jobs against your data.",
        hints=("dapi",),
    ),
    ProviderRule(
        "SEC028",
        "Doppler service token",
        Severity.CRITICAL,
        re.compile(r"\bdp\.(?:pt|st|sa|ct)\.[A-Za-z0-9]{40,}\b"),
        "Revoke it in Doppler. A token to a secrets manager is every secret it holds.",
        hints=("dp.pt.", "dp.st.", "dp.sa.", "dp.ct."),
    ),
    ProviderRule(
        "SEC029",
        "Grafana service account token",
        Severity.HIGH,
        re.compile(r"\bgl(?:sa|c)_[A-Za-z0-9_]{32,}\b"),
        "Revoke it in Grafana under Administration, Service accounts.",
        hints=("glsa_", "glc_"),
    ),
    ProviderRule(
        "SEC030",
        "Telegram bot token",
        Severity.HIGH,
        re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"),
        "Revoke it with BotFather. Anyone holding it can read and send as the bot.",
        hints=(":AA",),
    ),
    ProviderRule(
        "SEC031",
        "Postman API key",
        Severity.HIGH,
        re.compile(r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b"),
        "Revoke it in Postman; it can read every collection and environment in the workspace.",
        hints=("PMAK-",),
    ),
    ProviderRule(
        "SEC032",
        "Linear API key",
        Severity.HIGH,
        re.compile(r"\blin_api_[A-Za-z0-9]{40}\b"),
        "Revoke it in Linear under Settings, API.",
        hints=("lin_api_",),
    ),
    ProviderRule(
        "SEC033",
        "Atlassian API token",
        Severity.HIGH,
        re.compile(r"\bATATT3x[A-Za-z0-9_\-=]{100,}"),
        "Revoke it at id.atlassian.com under API tokens; it acts as the account that made it.",
        hints=("ATATT3x",),
    ),
    ProviderRule(
        "SEC034",
        "Square access token",
        Severity.CRITICAL,
        re.compile(r"\b(?:sq0atp-[A-Za-z0-9_-]{22}|EAAA[A-Za-z0-9_-]{56,})\b"),
        "Revoke it in the Square dashboard; a live token can move money.",
        hints=("sq0atp-", "EAAA"),
    ),
    ProviderRule(
        "SEC035",
        "Slack app-level token",
        Severity.HIGH,
        re.compile(r"\bxapp-\d-[A-Z0-9]+-\d+-[a-f0-9]{32,}\b"),
        "Regenerate it in the Slack app configuration; it authenticates the app itself.",
        hints=("xapp-",),
    ),
    ProviderRule(
        "SEC036",
        "Discord bot token",
        Severity.CRITICAL,
        re.compile(r"\b[MNO][A-Za-z\d_-]{23,25}\.[\w-]{6}\.[\w-]{27,}\b"),
        "Regenerate it in the Discord developer portal; it can act as the bot in every guild.",
        # A Discord token is base64 all the way through and carries no literal
        # worth hinting at: every candidate for it is a dot, which is every
        # line. The pattern runs unhinted instead.
    ),
    ProviderRule(
        "SEC037",
        "Mailgun API key",
        Severity.HIGH,
        re.compile(r"\bkey-[0-9a-f]{32}\b"),
        "Rotate it in the Mailgun dashboard; it can send mail as your domain.",
        hints=("key-",),
    ),
    ProviderRule(
        "SEC038",
        "Mailchimp API key",
        Severity.HIGH,
        re.compile(r"\b[0-9a-f]{32}-us\d{1,2}\b"),
        "Revoke it in the Mailchimp account settings; it reaches your whole audience list.",
        hints=("-us",),
    ),
    ProviderRule(
        "SEC039",
        "New Relic API key",
        Severity.HIGH,
        re.compile(r"\bNRAK-[A-Z0-9]{27}\b|\b[a-f0-9]{40}NRAL\b"),
        "Revoke it in the New Relic API keys page.",
        hints=("NRAK-", "NRAL"),
    ),
    ProviderRule(
        "SEC040",
        "Sentry DSN",
        Severity.MEDIUM,
        re.compile(r"https://[0-9a-f]{32}@[\w.-]+/\d+"),
        "A DSN lets anyone send events as your project, which is enough to fill a quota or bury a real alert.",
        confidence=Confidence.MEDIUM,
        hints=("https://",),
    ),
    ProviderRule(
        "SEC041",
        "Asana personal access token",
        Severity.HIGH,
        re.compile(r"\b1/\d{16}:[0-9a-f]{32}\b"),
        "Revoke it in Asana under My Settings, Apps.",
        hints=("1/",),
    ),
    ProviderRule(
        "SEC042",
        "Dropbox access token",
        Severity.CRITICAL,
        re.compile(r"\bsl\.[A-Za-z0-9_-]{130,}"),
        "Revoke it in the Dropbox app console; it reads and writes the account's files.",
        hints=("sl.",),
    ),
    ProviderRule(
        "SEC043",
        "Figma personal access token",
        Severity.HIGH,
        re.compile(r"\bfigd_[A-Za-z0-9_-]{40,}\b"),
        "Revoke it in Figma under Settings, Personal access tokens.",
        hints=("figd_",),
    ),
    ProviderRule(
        "SEC044",
        "Airtable personal access token",
        Severity.HIGH,
        re.compile(r"\bpat[A-Za-z0-9]{14}\.[0-9a-f]{64}\b"),
        "Revoke it in the Airtable builder hub; it reads every base the token was scoped to.",
        hints=("pat",),
    ),
    ProviderRule(
        "SEC045",
        "JFrog Artifactory token",
        Severity.CRITICAL,
        re.compile(r"\bAKCp8[A-Za-z0-9]{60,}\b"),
        "Revoke it in Artifactory; it can publish artifacts that your builds will install.",
        hints=("AKCp8",),
    ),
    ProviderRule(
        "SEC046",
        "Terraform Cloud API token",
        Severity.CRITICAL,
        re.compile(r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{40,}"),
        "Revoke it in Terraform Cloud; it can read state, which holds every secret a plan touched.",
        hints=(".atlasv1.",),
    ),
    ProviderRule(
        "SEC047",
        "Firebase Cloud Messaging server key",
        Severity.HIGH,
        re.compile(r"\bAAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{130,}"),
        "Rotate it in the Firebase console; it can push notifications to every installed app.",
        hints=(":APA91b",),
    ),
)

#: The first of two gates. Every provider rule needs either a long run of
#: credential characters, a PEM header, or a URL carrying a password, and four
#: fifths of the lines in a repository have none of the three. The second gate
#: is each rule's own ``hints``.
#:
#: A gate is a correctness risk as much as a speed win: a line this rejects is
#: never looked at again. The corpus test asserts that every provider rule's
#: example clears it, which is what keeps the threshold honest.
CANDIDATE = re.compile(r"[A-Za-z0-9+/_=-]{14}|-----BEGIN|://[^\s/]*:[^\s/]*@")

#: Every rule's hints, flattened. Checked as one pass before the per-rule loop,
#: because the loop builds a generator per rule and that allocation costs more
#: than the searching does: a line with no hint at all is the common case by a
#: wide margin, and it should cost one pass rather than forty-five.
ALL_HINTS = tuple({hint for rule in RULES for hint in rule.hints})

#: Rules with no literal to hint at, which therefore run on every candidate
#: line. One shape in forty-five is worth that; a habit of it would not be.
ALWAYS_RUN = tuple(rule for rule in RULES if not rule.hints)


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
    if not CANDIDATE.search(line):
        return
    if not (ALWAYS_RUN or any(hint in line for hint in ALL_HINTS)):
        return
    for rule in RULES:
        # The hints are why a large repository finishes scanning: one
        # substring search per rule, and nine candidate lines in ten carry
        # none of them, so the patterns themselves are almost never run.
        if rule.hints and not any(hint in line for hint in rule.hints):
            continue
        for match in rule.pattern.finditer(line):
            secret = match.group(rule.secret_group)
            matched_spans.append(match.span(rule.secret_group))
            if rule.reject is not None and rule.reject(match):
                continue
            if allow_examples and is_known_example(secret):
                continue
            yield rule, secret, evidence_for(match, rule)
