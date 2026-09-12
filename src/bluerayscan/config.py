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

import dataclasses
import json
import os

from . import gitignore, rules
from collections.abc import Iterable, Sequence

#: Looked for beside the scanned tree when ``--config`` is not given.
DEFAULT_PATH = ".bluerayscan.json"

#: What that file was called before the project was renamed. Still read when
#: the current name is absent, because a configuration file that quietly stops
#: being found turns off every exclusion in it at once, and the person it
#: happens to learns that from a screen of findings rather than from a message.
LEGACY_PATH = ".repo-sentinel.json"

#: Recognised keys, each mapping to the ``scan`` argument it supplies.
#: Anything else is a typo, and a typo in a security tool's configuration
#: should be loud rather than ignored.
_KEYS = {
    "exclude": list,
    "fail_on": str,
    "min_severity": str,
    "min_confidence": str,
    "baseline": str,
    "max_file_size": str,
    "sort": str,
    "disable": list,
    "gitignore": bool,
    "example_allowlist": bool,
    "paths": dict,
}


class ConfigError(Exception):
    """The configuration file could not be read, or asked for something odd."""


def find(root: str, explicit: "str | None") -> "str | None":
    """The config file to use: the one named, or the one beside the tree."""
    if explicit is not None:
        return explicit
    directory = root if os.path.isdir(root) else os.path.dirname(root) or "."
    for name in (DEFAULT_PATH, LEGACY_PATH):
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate):
            return candidate
    return None


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
        if expected is dict:
            _validate_paths(path, value)
        elif expected is list:
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ConfigError(f"{path!r}: {key!r} should be a list of strings")
        elif expected is bool:
            if not isinstance(value, bool):
                raise ConfigError(f"{path!r}: {key!r} should be true or false")
        elif not isinstance(value, str):
            raise ConfigError(f"{path!r}: {key!r} should be a string")
        settings[key] = value
    return settings


def _validate_paths(path: str, value) -> None:
    """Check the ``paths`` table: a glob mapping to settings for that subtree."""
    if not isinstance(value, dict):
        raise ConfigError(f"{path!r}: 'paths' should be an object keyed by glob")
    for glob, settings in value.items():
        where = f"{path!r}: paths[{glob!r}]"
        if not isinstance(settings, dict):
            raise ConfigError(f"{where} should be an object")
        unknown = sorted(set(settings) - {"disable"})
        if unknown:
            raise ConfigError(f"{where} has unknown setting(s): {', '.join(unknown)}")
        rules_off = settings.get("disable", [])
        if not isinstance(rules_off, list) or not all(
            isinstance(item, str) for item in rules_off
        ):
            raise ConfigError(f"{where}: 'disable' should be a list of strings")


@dataclasses.dataclass(frozen=True)
class PathScope:
    """Rules switched off for the files under one glob.

    The glob is matched with the same engine that reads ``.gitignore``, so
    ``examples/``, ``charts/vendor/**`` and ``*.tf`` all mean here what they
    would mean there. Inventing a second glob dialect for one config key is how
    a tool ends up with two subtly different answers to "does this path match".
    """

    pattern: str
    disable: "tuple[str, ...]"
    _rules: "gitignore.GitIgnoreFile"

    @classmethod
    def build(cls, pattern: str, disable: "Sequence[str]") -> "PathScope":
        return cls(pattern, tuple(disable), gitignore.GitIgnoreFile.from_lines([pattern]))

    def covers(self, path: str) -> bool:
        """True when ``path`` is the file, or sits under a matched directory.

        The walk gets this for free: a directory it excludes is a directory it
        never descends into. Matching a path after the fact has to do the same
        work by hand, or ``"examples/"`` would cover nothing at all.
        """
        parts = path.split("/")
        candidates = [(path, False)]
        candidates += [("/".join(parts[:depth]), True) for depth in range(1, len(parts))]
        return any(
            rule.matches(candidate, is_dir) and not rule.negated
            for candidate, is_dir in candidates
            for rule in self._rules.patterns
        )


def path_scopes(settings: dict) -> "list[PathScope]":
    """The per-path rules from a loaded config, in the order they were written."""
    return [
        PathScope.build(pattern, options.get("disable", []))
        for pattern, options in settings.get("paths", {}).items()
    ]


def disabled_matcher(patterns: 'Iterable[str]'):
    """The predicate for rules a project has switched off.

    The syntax is :func:`bluerayscan.rules.matcher`'s, shared with the
    suppression markers, so that naming a rule means the same thing in a config
    file and in a comment.
    """
    return rules.matcher(patterns)
