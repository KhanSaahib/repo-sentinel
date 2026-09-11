"""The command line: what was asked for, and which command answers it.

Scanning lives in :mod:`.engine`, formatting in :mod:`.report`, and what each
command actually does in :mod:`.commands`. What is left here is the parser, the
config file that supplies its defaults, and the dispatch -- which is worth
keeping unmixed with the rest, because for a tool whose job is to fail a build
at the right moment, "did the user ask for this" and "is this a finding" are
questions that should not be able to confuse each other.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence

from . import __version__, baseline as baseline_module, config as config_module
from .commands import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, init_command, rules_command, scan_command
from .engine import scan_path  # noqa: F401  (re-exported: this is the public API)

__all__ = ["EXIT_ERROR", "EXIT_FINDINGS", "EXIT_OK", "build_parser", "main", "scan_path"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repo-sentinel",
        description="Audit a repository for leaked secrets and insecure configuration.",
    )
    parser.add_argument("--version", action="version", version=f"repo-sentinel {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="scan a directory or file")
    scan_parser.add_argument("path", nargs="?", default=".", help="path to scan (default: .)")
    scan_parser.add_argument(
        "--format",
        choices=("text", "json", "sarif", "markdown", "github"),
        default="text",
        help="output format",
    )
    scan_parser.add_argument(
        "--output",
        metavar="FILE",
        help="write the report to FILE instead of stdout (SARIF uploads want a file)",
    )
    scan_parser.add_argument(
        "--min-severity",
        default="low",
        help="hide findings below this severity (low, medium, high, critical)",
    )
    scan_parser.add_argument(
        "--min-confidence",
        default="low",
        help="hide findings below this confidence (low, medium, high)",
    )
    scan_parser.add_argument(
        "--fail-on",
        default="medium",
        help="exit non-zero when a finding reaches this severity (default: medium)",
    )
    scan_parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="extra file or directory glob to skip (repeatable)",
    )
    scan_parser.add_argument(
        "--baseline",
        nargs="?",
        const=baseline_module.DEFAULT_PATH,
        metavar="FILE",
        help=(
            "treat findings recorded in FILE as accepted and fail only on new ones "
            f"(default file: {baseline_module.DEFAULT_PATH})"
        ),
    )
    scan_parser.add_argument(
        "--write-baseline",
        nargs="?",
        const=baseline_module.DEFAULT_PATH,
        metavar="FILE",
        help="record the current findings as accepted, then exit without failing",
    )
    scan_parser.add_argument(
        "--config",
        metavar="FILE",
        help=(
            "project defaults, as JSON "
            f"(default: {config_module.DEFAULT_PATH} beside the scanned tree, if present)"
        ),
    )
    scan_parser.add_argument(
        "--disable",
        action="append",
        default=[],
        metavar="RULE",
        help="switch off a rule or a family ('K8S004', 'DC*'); repeatable",
    )
    scan_parser.add_argument(
        "--paths-from",
        metavar="FILE",
        help=(
            "scan only the files listed in FILE, one per line ('-' for stdin). "
            "Pipe in `git diff --name-only origin/main` for a fast pull request run"
        ),
    )
    scan_parser.add_argument(
        "--sort",
        choices=("severity", "path"),
        default="severity",
        help="order findings worst-first (default) or by file",
    )
    scan_parser.add_argument(
        "--quiet",
        action="store_true",
        help="print only the summary, not each finding",
    )
    scan_parser.add_argument(
        "--no-gitignore",
        action="store_true",
        help="also scan files git was told to ignore",
    )
    scan_parser.add_argument(
        "--no-suppression",
        action="store_true",
        help="read the 'repo-sentinel: ignore' markers but do not obey them",
    )
    scan_parser.add_argument(
        "--no-example-allowlist",
        action="store_true",
        help="also report credentials published as vendor or RFC examples",
    )
    scan_parser.add_argument("--no-color", action="store_true", help="disable coloured output")

    init_parser = subparsers.add_parser(
        "init", help="set this repository up: a config, a baseline, and a CI snippet"
    )
    init_parser.add_argument("path", nargs="?", default=".", help="repository to set up")
    init_parser.add_argument(
        "--fail-on",
        default="high",
        help="severity the generated config should fail on (default: high)",
    )
    init_parser.add_argument(
        "--force", action="store_true", help="overwrite an existing config or baseline"
    )
    init_parser.add_argument(
        "--no-baseline",
        action="store_true",
        help="do not record existing findings as accepted",
    )

    rules_parser = subparsers.add_parser("rules", help="list every rule the scanner knows")
    rules_parser.add_argument("--format", choices=("text", "json"), default="text")
    # Kept for the second parse in main(), where a config file supplies
    # defaults that explicit flags then override.
    parser.scan_parser = scan_parser  # type: ignore[attr-defined]
    return parser


#: Config key -> the argparse destination it supplies a default for. The two
#: booleans are inverted because the flags are phrased as opt-outs.
_CONFIG_TO_DEST = {
    "exclude": ("exclude", False),
    "fail_on": ("fail_on", False),
    "min_severity": ("min_severity", False),
    "min_confidence": ("min_confidence", False),
    "baseline": ("baseline", False),
    "sort": ("sort", False),
    "disable": ("disable", False),
    "gitignore": ("no_gitignore", True),
    "example_allowlist": ("no_example_allowlist", True),
}


def _apply_config(parser: argparse.ArgumentParser, argv: "Sequence[str] | None") -> argparse.Namespace:
    """Parse twice: once to find the config file, once with it as defaults.

    Parsing again is cheaper than working out whether each flag was passed
    explicitly, and it gets the precedence right by construction -- argparse
    already prefers what is on the command line to whatever the defaults say.
    """
    args = parser.parse_args(argv)
    if args.command != "scan":
        return args
    args.path_scopes = []

    path = config_module.find(args.path, args.config)
    if path is None:
        return args

    settings = config_module.load(path)
    # A path in the config file is relative to the config file, not to
    # whatever directory the command happened to be run from. Without this,
    # `repo-sentinel scan some/repo` cannot find the baseline that repo's own
    # config points at, which is exactly what `init` sets up.
    if "baseline" in settings and not os.path.isabs(settings["baseline"]):
        settings["baseline"] = os.path.join(os.path.dirname(path) or ".", settings["baseline"])
    defaults = {}
    for key, value in settings.items():
        mapping = _CONFIG_TO_DEST.get(key)
        if mapping is None:
            continue  # a setting with no flag, like the paths table
        dest, inverted = mapping
        defaults[dest] = (not value) if inverted else value
    parser.scan_parser.set_defaults(**defaults)  # type: ignore[attr-defined]
    reparsed = parser.parse_args(argv)
    reparsed.config = path
    # Per-path rules have no command line form -- a glob table does not belong
    # on one -- so unlike every other setting they travel on the namespace
    # rather than through argparse's defaults.
    reparsed.path_scopes = config_module.path_scopes(settings)
    return reparsed


def main(argv: "Sequence[str] | None" = None) -> int:
    parser = build_parser()
    try:
        args = _apply_config(parser, argv)
    except config_module.ConfigError as error:
        print(f"repo-sentinel: {error}", file=sys.stderr)
        return EXIT_ERROR

    if args.command == "init":
        return init_command(args, parser)
    if args.command == "rules":
        return rules_command(args)
    return scan_command(args, parser)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
