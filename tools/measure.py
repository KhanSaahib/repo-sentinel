#!/usr/bin/env python3
"""Scan real repositories and summarise what the rules said about them.

Every scanner author fixes the false positives they imagined. The ones that
matter are the ones a real repository produces, and the only way to see those
is to point the tool at a few and read every finding.

This is the harness for doing that: it scans the directories you give it,
prints a per-rule table with timings, and -- with ``--sample`` -- shows a few
findings per rule so they can actually be judged.

The corpus is pinned. ``tools/corpus.json`` lists the repositories the
heuristics have been measured against and the commit each was measured at, so
that a change to a rule can be measured rather than argued about::

    python3 tools/measure.py --fetch ~/corpora     # clone or update the pins
    python3 tools/measure.py --corpus ~/corpora --save before.json
    # ...change a heuristic...
    python3 tools/measure.py --corpus ~/corpora --compare before.json

Counts are kept per rule *and per confidence*, because a change that moves a
finding from medium to high moves no total at all and would otherwise read as
"nothing moved".

The comparison is the point. A filter that removes 1,400 findings and costs
nothing is a different thing from one that removes 1,400 findings and takes a
real one with it, and the difference is invisible in a total.

Usage::

    python3 tools/measure.py ~/corpora/*
    python3 tools/measure.py --sample 3 ~/corpora/discourse

It is not a test. Nothing here asserts anything, because the output needs a
person: "is this a real problem in this repository" is not a question a program
can answer. What the program can do is tell you what changed.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from bluerayscan import engine  # noqa: E402  (after the path fix above)


CORPUS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus.json")


def pins() -> "list[dict]":
    with open(CORPUS, encoding="utf-8") as handle:
        return json.load(handle)["repositories"]


def fetch(into: str) -> int:
    """Clone or update every pinned repository under ``into``.

    A pin is fetched by commit rather than by branch, so the tree is the one
    the numbers were measured on however far the project has moved since.
    """
    os.makedirs(into, exist_ok=True)
    for repository in pins():
        target = os.path.join(into, repository["name"])
        if not os.path.isdir(os.path.join(target, ".git")):
            run(["git", "init", "--quiet", target])
            run(["git", "-C", target, "remote", "add", "origin", repository["url"]])
        print(f"{repository['name']}: {repository['commit'][:12]}  {repository['for']}")
        run(["git", "-C", target, "fetch", "--quiet", "--depth", "1", "origin", repository["commit"]])
        run(["git", "-C", target, "checkout", "--quiet", "FETCH_HEAD"])
    return 0


def run(command: "list[str]") -> None:
    subprocess.run(command, check=True)


def is_dated(saved: "dict[str, dict[str, int]]") -> bool:
    """True for a file written before the counts carried a confidence.

    The old shape counted by rule id alone; this one counts by rule id and
    confidence, because a change that moves a finding from medium to high
    moves no count at all under the old shape and reads as "nothing moved".
    That happened -- twice -- which is why the key changed.
    """
    return any(" " not in rule for counts in saved.values() for rule in counts)


def by_rule(counts: "dict[str, int]") -> "dict[str, int]":
    """Counts keyed by rule id alone, for comparing against an older file."""
    folded: "collections.Counter" = collections.Counter()
    for rule, count in counts.items():
        folded[rule.split(" ")[0]] += count
    return dict(folded)


def compare(before: "dict[str, dict[str, int]]", after: "dict[str, dict[str, int]]") -> None:
    """Print what changed, per repository and per rule.

    Both directions matter and they mean opposite things. Fewer findings from
    a heuristic change is the point of the change; fewer findings from the two
    deliberately vulnerable repositories is the change going wrong. A finding
    that only changed confidence is a third thing, and it shows here as one
    row falling and another rising.
    """
    print("\nchanges against the saved run")
    if is_dated(before):
        print(
            "  (the saved file predates confidence tracking, so this compares "
            "rule counts only -- re-save to see confidence move)"
        )
        after = {name: by_rule(counts) for name, counts in after.items()}
    names = sorted(set(before) | set(after))
    quiet = True
    for name in names:
        was, now = before.get(name, {}), after.get(name, {})
        rules = sorted(set(was) | set(now))
        rows = [
            (rule, was.get(rule, 0), now.get(rule, 0))
            for rule in rules
            if was.get(rule, 0) != now.get(rule, 0)
        ]
        if not rows:
            continue
        quiet = False
        total = sum(now.values()) - sum(was.values())
        print(f"\n  {name}: {total:+d}")
        for rule, old_count, new_count in sorted(rows, key=lambda row: row[1] - row[2]):
            print(f"    {rule:<8} {old_count:>5} -> {new_count:<5} ({new_count - old_count:+d})")
    if quiet:
        print("  nothing moved.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="*", help="repositories to scan")
    parser.add_argument(
        "--corpus",
        metavar="DIR",
        help="scan the pinned repositories under DIR instead of naming paths",
    )
    parser.add_argument(
        "--fetch",
        metavar="DIR",
        help="clone or update the pinned repositories under DIR, then exit",
    )
    parser.add_argument("--save", metavar="FILE", help="write the per-rule counts to FILE")
    parser.add_argument(
        "--compare",
        metavar="FILE",
        help="print what changed against a file written by --save",
    )
    parser.add_argument(
        "--sample",
        type=int,
        default=0,
        metavar="N",
        help="print N findings per rule, so they can be judged rather than counted",
    )
    parser.add_argument(
        "--min-confidence",
        default="low",
        help="hide findings below this confidence, as the CLI flag does",
    )
    args = parser.parse_args(argv)

    if args.fetch:
        return fetch(args.fetch)

    paths = list(args.paths)
    if args.corpus:
        paths += [
            os.path.join(args.corpus, repository["name"])
            for repository in pins()
            if os.path.isdir(os.path.join(args.corpus, repository["name"]))
        ]
    if not paths:
        parser.error("name some repositories, or point --corpus at the pinned ones")

    from bluerayscan.findings import Confidence

    floor = Confidence.parse(args.min_confidence)
    totals: "collections.Counter" = collections.Counter()

    measured: "dict[str, dict[str, int]]" = {}
    for path in paths:
        result = engine.scan(path)
        findings = [finding for finding in result.findings if finding.confidence >= floor]
        counts = collections.Counter(
            f"{finding.rule_id} {finding.confidence.value}" for finding in findings
        )
        totals.update(counts)

        name = os.path.basename(os.path.normpath(path))
        measured[name] = dict(counts)
        rate = result.file_count / result.duration if result.duration else 0
        print(
            f"\n{name}: {len(findings)} finding(s) in {result.file_count} file(s), "
            f"{result.duration:.1f}s ({rate:,.0f} files/s)"
        )
        for key, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
            rule_id = key.split(" ")[0]
            print(f"  {key:<16} {count:>4}")
            shown = [
                f for f in findings if f"{f.rule_id} {f.confidence.value}" == key
            ][: args.sample]
            for finding in shown:
                print(f"        {finding.path}:{finding.line}  {finding.title[:70]}")

    if len(paths) > 1:
        print(f"\nacross {len(paths)} repositories: {sum(totals.values())} finding(s)")
        for key, count in sorted(totals.items(), key=lambda item: (-item[1], item[0])):
            print(f"  {key:<16} {count:>4}")

    if args.compare:
        with open(args.compare, encoding="utf-8") as handle:
            compare(json.load(handle), measured)

    if args.save:
        with open(args.save, "w", encoding="utf-8") as handle:
            json.dump(measured, handle, indent=2, sort_keys=True)
        print(f"\nsaved to {args.save}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
