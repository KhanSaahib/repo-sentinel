"""Deciding whether a string looks like a generated credential.

Every rule that is not a documented token shape ends up here: the entropy
rule, the value-position rules for ``.env`` files, the Dockerfile ``ENV``
check. Keeping the judgement in one module means a placeholder that one rule
learns to ignore is ignored by all of them.

The interesting part is the entropy floor. A single global threshold cannot
work, because the maximum entropy a string can reach depends on both its
alphabet and its length: a 12-character hex token tops out at 3.58 bits per
character and a 200-character base64 blob at 6, so one number is simultaneously
too strict for the first and too lax for the second. What generalises is the
*ratio*: a generated credential lands near the ceiling of what its alphabet and
length allow, and a hand-written value lands well below it.
"""

from __future__ import annotations

import math
import re
import string

#: Fraction of the achievable maximum a value must reach to look generated.
#: Measured against real tokens: random hex, base64 and alphanumeric secrets
#: all sit above 0.9, while words, dates, paths and version strings fall well
#: under 0.7. The gap is wide, so the exact figure matters less than the shape.
ENTROPY_RATIO = 0.75

#: An absolute floor beneath the ratio, so that a very short value over a tiny
#: alphabet cannot clear the bar simply because its ceiling is low too.
MIN_ENTROPY = 2.5

#: Shortest value worth judging. Below this, entropy is noise.
MIN_SECRET_LENGTH = 12

_HEX = set(string.hexdigits)
_ALNUM = set(string.ascii_letters + string.digits)
_BASE64ISH = _ALNUM | set("+/=-_.")

#: Names that promise a credential lives on the other side of the assignment.
SECRET_NAME = re.compile(
    r"""(?ix)
    \b(?P<name>[A-Za-z0-9_.\[\]-]*
        (?:passwd|password|secret|token|api[_-]?key|apikey|access[_-]?key|
           private[_-]?key|client[_-]?secret|credential|
           auth[_-]?(?:token|key|secret|pass|pw|header)|authorization|bearer)
     [A-Za-z0-9_.\[\]-]*)
    """
)

_PLACEHOLDER = re.compile(
    r"""(?ix)
    ^(?:
        x{3,} | \*+ | \.+ | -+ |
        (?:change|changeme|placeholder|example|sample|dummy|redacted|removed|
           todo|fixme|none|null|nil|true|false|test|testing|foo|bar|baz)
        [_-]?\w* |
        your[_-]?.* | my[_-]?.* | some[_-]?.* | insert[_-]?.* |
        # Repeated dollars are how Compose escapes interpolation, so
        # "$$(cat /run/secrets/db-password)" is a command, not a credential.
        <.*> | \{\{.*\}\} | \$+\{.*\} | \$+\(.*\) | %\w+% | \$+[A-Za-z_]\w* |
        .*(?:example\.com|localhost|127\.0\.0\.1).*
    )$
    """
)

#: Values that are structure rather than secret: paths, URLs without a
#: password in them, version constraints, dotted identifiers, dates.
_STRUCTURED = (
    re.compile(r"^[~.]{0,2}/[^\s]*$"),                     # /etc/ssl/private, ./key.pem
    re.compile(r"^[a-z][a-z0-9+.-]*://[^:@\s]*$", re.I),   # a URL carrying no credential
    re.compile(r"^[~^><=v\s]*\d+(?:\.\d+)*(?:[-+][\w.]+)*$", re.I),  # 1.2.3-alpha.4, ^2.0
    re.compile(r"^\d{4}-\d{2}-\d{2}[T \d:.+Z-]*$", re.I),  # timestamps
    re.compile(r"^[A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*){2,}$"),  # com.example.thing
    re.compile(r"^[\[{]"),                                # a list or object, not a value
    # A quoted type expression: tuple[int, str, int], dict[str, Node]. Common
    # wherever annotations are strings, and this one caught this project out.
    re.compile(r"^[A-Za-z_][\w.]*\[[^\]]*\]$"),
    # A screaming identifier, snake or kebab: AZURE_FEDERATED_TOKEN_FILE is the
    # name of an environment variable and PRIVATE-TOKEN is the name of an HTTP
    # header. Real tokens in this shape do not exist; they carry mixed case,
    # digits and punctuation.
    re.compile(r"^_?[A-Z][A-Z0-9]*(?:[-_][A-Z0-9]+)+$"),
    # A snake- or kebab-cased identifier whose words may carry digits:
    # "shared_credentials_2". Each word is two or more letters or a short run
    # of digits, and the separators are what make this safe -- a generated
    # credential does not contain them, and a JWT's base64 segments do not
    # break into words.
    re.compile(
        r"^(?:[A-Z]?[a-z]{2,}[0-9]{0,2}|[0-9]{1,4})"
        r"(?:[-_](?:[A-Z]?[a-z]{2,}[0-9]{0,2}|[0-9]{1,4}))+$"
    ),
    # Camel or Pascal case with no digits: "ImagePullSecret", "privateToken".
    # Identifiers assigned to identifier-shaped names, which is what a
    # constants file is. A generated credential carries digits or punctuation.
    re.compile(r"^[A-Za-z][a-z]*(?:[A-Z][a-z]+)+$"),
    # A URN, or anything else colon-separated and spelled out:
    # "urn:ietf:params:oauth:token-type:jwt", "urn:oasis:names:tc:SAML:1.0:am:password".
    # Identifiers in a specification, which is what an OAuth or SAML constants
    # file is made of, and every one of them ends in a word like "password".
    re.compile(r"^urn:[\w.:+-]+$", re.I),
    re.compile(r"^[A-Za-z][\w.+-]*(?::[A-Za-z0-9][\w.+-]*){2,}$"),
    # Space-separated identifiers: "code id_token token", the OAuth response
    # types. Words with underscores in them, which the prose pattern below
    # does not allow because prose has none.
    re.compile(r"^[a-z][a-z0-9_+-]*(?: +[a-z][a-z0-9_+-]*)+$"),
    # Two identifiers joined by a plus: "dpop+id_token". A media type or a
    # scheme, and never a generated value.
    re.compile(r"^[a-z][a-z0-9_-]*(?:\+[a-z][a-z0-9_-]*)+$"),
    # A Ruby or C++ constant path: "DiscourseAi::Tokenizer::Mistral". The
    # separator is two colons, which no credential format uses.
    re.compile(r"^[A-Za-z_]\w*(?:::[A-Za-z_]\w*)+$"),
    # Hyphenated words in any language: "OAuth-clientgeheim". Letters only --
    # a credential of that length carries digits or punctuation, and a
    # translated label does not.
    re.compile(r"^[A-Za-z]+(?:[-_][A-Za-z]+)+$"),
    # A namespaced key, colon-separated and lowercase, with or without the
    # trailing colon a prefix carries: "user_api_key:device:lock:". Cache and
    # queue keys live in constants whose names end in KEY or TOKEN.
    re.compile(r"^[a-z][\w.-]*(?::[\w.-]+)+:?$"),
    # A modular crypt string: "$2a$10$N9qo8uLOickgx2ZMRZo...", "$argon2id$v=19$...",
    # "$pbkdf2-sha256$i=64000,l=32$". This is the *output* of hashing a
    # password, which is the one thing that cannot be used as one -- and it is
    # what a fixture assigns to a key called password. The prefixes are
    # enumerated rather than matched loosely, because "$something$" is also
    # what a shell writes.
    re.compile(
        r"^\$(?:2[abxy]?|1|5|6|y|7|sha1|md5|argon2[a-z]*|scrypt|bcrypt|"
        r"pbkdf2[\w-]*|s?sha\d*)\$\S*$",
        re.I,
    ),
    # A sentence in any Latin-script language: letters, digits, punctuation,
    # and -- the part that matters -- a space in it. Translated interface
    # strings are assigned to names like password_too_long in every locale a
    # project ships. Without the space requirement this swallows
    # "AdminPassword123!", which is a password ending in punctuation and is
    # exactly the finding a deliberately vulnerable repository is testing for.
    re.compile(r"^(?=[^\W\d_])(?=[^\n]*\s)[\w .,;:!?'’\"()\\/-]+[.!?\"]$"),
    # Words with spaces between them: "shhhh, very secret", "manny is cool".
    # Prose, in other words, which is what a placeholder in an example app
    # looks like. A generated credential has no spaces in it.
    re.compile(r"^[A-Za-z][A-Za-z'’.,!?-]*(?: +[A-Za-z][A-Za-z'’.,!?-]*)+$"),
    # An all-lowercase relative path: "testdata/secret_key". Anchored to
    # lowercase on purpose -- a base64 blob containing slashes has mixed case,
    # so this does not swallow one.
    re.compile(r"^[a-z0-9][a-z0-9._-]*(?:/[a-z0-9._-]+)+$"),
    # A YAML anchor or alias: "&externalAuthorization", "*externalAuthorization".
    # The value is a name pointing at a block somewhere else in the document.
    re.compile(r"^[&*][A-Za-z_][\w.-]*$"),
    # A lowercase dotted name: "tracing.yaml", "example.internal",
    # "com.example.app". Filenames turn up constantly on the right of a key
    # ending in "secret" or "key", and none of them is a credential.
    re.compile(r"^[a-z0-9][a-z0-9_-]*(?:\.[a-z0-9_-]{1,8})+$"),
    # A query or selector expression: "type!=kubernetes.io/dockercfg,type!=x".
    # Comparison operators do not appear in credentials; they appear in filters.
    re.compile(r".*(?:!=|==|>=|<=).*$"),
    # A reference to where the value lives, rather than the value: "env:NPM_TOKEN",
    # "vault:secret/data/ci". The scheme-with-slashes form is already covered by
    # the URL pattern above; this is the bare one, which CLI tools use precisely
    # so that the credential does not appear in the command line.
    re.compile(r"^(?:env|vault|secret|file|cmd|op|ssm|keyring):[\w./:@+-]+$", re.I),
    # A quoted type expression carrying a union: "Secret | None",
    # "list[Secret] | None". Python annotations are strings wherever they are
    # forward references, and a generated client is thousands of them.
    re.compile(r"^[A-Za-z_][\w.\[\], ]*(?:\s*\|\s*[A-Za-z_][\w.\[\], ]*)+$"),
    # A fragment of code: `+fmt.Sprintf(` picked up where a name inside one
    # string literal meets a value inside the next, `!areAllCredentialsSet` or
    # `item.credentials ?? []` in a template binding, `access_token=' +` where
    # a string is being concatenated. Brackets and operators do not appear in
    # credentials; they appear in expressions.
    # (The filters are applied with match(), so anything that asks "does this
    # contain" says so with a leading .* -- as the comparison pattern below
    # already does.)
    re.compile(r"^[+*/&|!?~]|.*[()]|.*\s(?:\?\??|&&|\|\||\+)\s"),
    # A sentinel constant, which by convention starts where an identifier
    # cannot: "__n8n_BLANK_VALUE_e5362baf-...". Credentials do not.
    re.compile(r"^__"),
    # A reference into a document: "#/components/schemas/PasswordChallenge".
    # An OpenAPI schema is tens of thousands of these, and the ones that end in
    # a word like "Challenge" or "Token" are the ones a secret rule reads.
    re.compile(r"^#/[\w./~%{}-]+$"),
    # A lowercase dotted identifier with no digits: "git.authheadersecret".
    # Constants files are full of these, and a constant whose *name* ends in
    # "secret" is still a name.
    re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$"),
    # Words joined by hyphens or underscores: "unstructured", "content-type",
    # "Proxy-Authorization". Generated credentials carry digits
    # or mixed case; a pure word-list slug is vocabulary. The cost is that a
    # deliberate passphrase secret goes unreported, which is a trade worth
    # making -- this pattern is most of what a real codebase assigns to names
    # like token_type and auth_scheme.
    re.compile(r"^[A-Z]?[a-z]+(?:[-_][A-Z]?[a-z]+)*$"),
)


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character. Random base64 lands near 6, English near 4."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def alphabet_size(value: str) -> int:
    """The nominal size of the alphabet ``value`` appears to be drawn from.

    Nominal rather than observed: a 16-character hex token uses at most 16
    distinct characters however random it is, and judging it against its own
    observed alphabet would make every string look maximally random.
    """
    chars = set(value)
    if chars <= set(string.digits):
        return 10
    if chars <= _HEX:
        return 16
    if chars <= set(string.ascii_lowercase + string.digits + "_-"):
        return 38
    if chars <= set(string.ascii_uppercase + string.digits + "_-"):
        return 38
    if chars <= _ALNUM:
        return 62
    if chars <= _BASE64ISH:
        return 68
    return 90


def entropy_floor(value: str) -> float:
    """The entropy ``value`` must reach for its length and alphabet to look generated.

    The ceiling for a string of length *n* over an alphabet of *k* symbols is
    ``log2(min(k, n))`` -- capped by *n* because a string cannot use more
    distinct symbols than it has characters. A credential sits near that
    ceiling; a word or a version number does not.
    """
    if not value:
        return MIN_ENTROPY
    ceiling = math.log2(min(alphabet_size(value), len(value)))
    return max(MIN_ENTROPY, ENTROPY_RATIO * ceiling)


#: Interpolation anywhere in a value, not only at its start:
#: ``"GITHUB_TOKEN_${org^^}"`` is a variable name being assembled.
#: A value with a brace-delimited placeholder in it: "${VAR}", "{{ x }}",
#: "%{count}", "#{Rails.env}", "Bearer {env:TOKEN}". Credentials have no
#: braces in them, so the last of these is as safe as the rest.
_EMBEDDED_INTERPOLATION = re.compile(r"\$\{|\$\(|\{\{|%\(|%\{|#\{|\{[^\s{}]{1,64}\}")

#: An angle-bracket placeholder anywhere in a value: "glrt-<TOKEN>" is what
#: documentation writes where a real token will go.
_ANGLE_PLACEHOLDER = re.compile(r"<[A-Za-z_][\w .-]*>")


def looks_like_placeholder(value: str) -> bool:
    """True when a value is obviously a stand-in rather than a real credential."""
    stripped = value.strip()
    if not stripped or _PLACEHOLDER.match(stripped):
        return True
    if _EMBEDDED_INTERPOLATION.search(stripped) or _ANGLE_PLACEHOLDER.search(stripped):
        return True
    if any(pattern.match(stripped) for pattern in _STRUCTURED):
        return True
    # "aaaaaaaaaaaa" and friends: one repeated character is nobody's password.
    return len(set(stripped)) <= 2


#: Words that turn a credential-ish name into a label for one. "credentialType"
#: holds the name of a credential kind, "secretName" the name of a Kubernetes
#: Secret, "tokenPattern" a regular expression -- none of them holds the thing
#: itself. Measured on n8n, whose nodes assign a credential *type* to a key
#: called credentialType seven hundred times over.
#:
#: "header" is deliberately absent: an auth header's value is the credential.
_LABEL_SUFFIXES = (
    "type", "types", "kind", "kinds", "name", "names", "field", "fields",
    "label", "labels", "prefix", "suffix", "pattern", "patterns",
    "placeholder", "example", "format", "scheme", "column", "table",
)


def is_secret_name(name: str) -> bool:
    """True when an identifier announces that its value is a credential."""
    if SECRET_NAME.search(name) is None:
        return False
    trimmed = re.sub(r"[^a-z]", "", name.lower())
    return not trimmed.endswith(_LABEL_SUFFIXES)


def looks_generated(value: str) -> bool:
    """True when ``value`` is long enough, random enough and not a placeholder.

    The single question every heuristic rule asks. Whether the *name* on the
    other side of the assignment justifies asking it is the caller's problem.
    """
    stripped = value.strip()
    if len(stripped) < MIN_SECRET_LENGTH:
        return False
    if not stripped.isascii():
        # Credentials are ASCII, because they travel through headers, URLs and
        # environment variables that are. Text in another script is not, and
        # its entropy is high for a reason that has nothing to do with
        # randomness: a larger alphabet raises the per-character measure.
        # Measured on Discourse, whose translated interface strings produced
        # 1,600 findings -- "password" in Arabic, forty times per locale.
        return False
    if looks_like_placeholder(stripped):
        return False
    return shannon_entropy(stripped) >= entropy_floor(stripped)
