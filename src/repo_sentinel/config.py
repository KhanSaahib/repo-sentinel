"""Project defaults, so a team does not retype its flags.

Every project that adopts a scanner ends up with a preferred invocation --
these excludes, that threshold, this rule switched off because the third-party
chart it vendors will never satisfy it. Keeping that in a Makefile means the
pre-commit hook and the pipeline disagree with each other and with whoever runs
the tool by hand.

The file is JSON rather than TOML for two reasons: ``tomllib`` arrived in 3.11
and this project supports 3.9, and the baseline file is already JSON, so a
repository that adopts both learns one format. It is small on purpose. A
configuration format that can express everything eventually expresses a policy
engine, and this tool is not one.

Values here are *defaults*: anything passed on the command line wins, so a
config file can never stop someone auditing their own repository more strictly
than the project usually does.
"""

from __future__ import annotations

import json
import os
from collections.abc import Sequence

#: Looked for beside the scanned tree when ``--config`` is not given.
DEFAULT_PATH = ".repo-sentinel.json"

#: Recognised keys, each mapping to the ``scan`` argument it supplies.
#: Anything else is a typo, and a typo in a security tool's configuration
#: should be loud rather than ignored.
_KEYS = {
    "exclude": list,
    "fail_on": str,
    "min_severity": str,
    "min_confidence": str,
    "baseline": str,
    "sort": str,
    "disable": list,
    "gitignore": bool,
    "example_allowlist": bool,
}


class ConfigError(Exception):
    """The configuration file could not be read, or asked for something odd."""


def find(root: str, explicit: "str | None") -> "str | None":
    """The config file to use: the one named, or the one beside the tree."""
    if explicit is not None:
        return explicit
    candidate = os.path.join(root if os.path.isdir(root) else os.path.dirname(root) or ".", DEFAULT_PATH)
    return candidate if os.path.isfile(candidate) else None


def load(path: str) -> dict:
    """Read and validate a config file into a dict of scan defaults."""
    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except OSError as error:
        raise ConfigError(f"could not read {path!r}: {error}") from None
    except json.JSONDecodeError as error:
        raise ConfigError(f"{path!r} is not valid JSON: {error}") from None

    if not isinstance(payload, dict):
        raise ConfigError(f"{path!r} should hold a JSON object")

    unknown = sorted(set(payload) - set(_KEYS))
    if unknown:
        known = ", ".join(sorted(_KEYS))
        raise ConfigError(
            f"{path!r} has unknown setting(s): {', '.join(unknown)}. Known settings: {known}"
        )

    settings = {}
    for key, expected in _KEYS.items():
        if key not in payload:
            continue
        value = payload[key]
        if expected is list:
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ConfigError(f"{path!r}: {key!r} should be a list of strings")
        elif expected is bool:
            if not isinstance(value, bool):
                raise ConfigError(f"{path!r}: {key!r} should be true or false")
        elif not isinstance(value, str):
            raise ConfigError(f"{path!r}: {key!r} should be a string")
        settings[key] = value
    return settings


def disabled_matcher(patterns: Sequence[str]):
    """Build a predicate for rule ids a project has switched off.

    Patterns are rule ids, or a family prefix ending in ``*`` -- ``K8S004``,
    ``DC*``. Matching is case-insensitive because nobody remembers whether it
    was ``k8s`` or ``K8S`` at the moment they are silencing something.
    """
    exact = {pattern.upper() for pattern in patterns if not pattern.endswith("*")}
    prefixes = tuple(pattern[:-1].upper() for pattern in patterns if pattern.endswith("*"))

    def disabled(rule_id: str) -> bool:
        upper = rule_id.upper()
        return upper in exact or upper.startswith(prefixes) if prefixes else upper in exact

    return disabled
