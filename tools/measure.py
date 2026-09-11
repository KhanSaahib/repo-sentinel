#!/usr/bin/env python3
"""Scan real repositories and summarise what the rules said about them.

Every scanner author fixes the false positives they imagined. The ones that
matter are the ones a real repository produces, and the only way to see those
is to point the tool at a few and read every finding.

This is the harness for doing that: it scans the directories you give it,
prints a per-rule table with timings, and -- with ``--sample`` -- shows a few
findings per rule so they can actually be judged. It is not a test. Nothing
here asserts anything, because the output needs a person: "is this a real
problem in this repository" is not a question a program can answer.

Suggested corpus, chosen for coverage rather than fame::

    git clone --depth 1 https://github.com/docker/awesome-compose
    git clone --depth 1 https://github.com/prometheus/prometheus
    git clone --depth 1 https://github.com/prometheus-community/helm-charts
    git clone --depth 1 https://github.com/terraform-aws-modules/terraform-aws-vpc
    git clone --depth 1 https://github.com/bridgecrewio/terragoat
    git clone --depth 1 https://github.com/madhuakula/kubernetes-goat

The last two are deliberately vulnerable, so they measure the other direction:
what the rules fail to notice.

Usage::

    python3 tools/measure.py ~/corpora/*
    python3 tools/measure.py --sample 3 ~/corpora/prometheus
"""

from __future__ import annotations

import argparse
import collections
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from repo_sentinel import engine  # noqa: E402  (after the path fix above)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="+", help="repositories to scan")
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

    from repo_sentinel.findings import Confidence

    floor = Confidence.parse(args.min_confidence)
    totals: "collections.Counter" = collections.Counter()

    for path in args.paths:
        result = engine.scan(path)
        findings = [finding for finding in result.findings if finding.confidence >= floor]
        counts = collections.Counter(finding.rule_id for finding in findings)
        totals.update(counts)

        name = os.path.basename(os.path.normpath(path))
        rate = result.file_count / result.duration if result.duration else 0
        print(
            f"\n{name}: {len(findings)} finding(s) in {result.file_count} file(s), "
            f"{result.duration:.1f}s ({rate:,.0f} files/s)"
        )
        for rule_id, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
            print(f"  {rule_id}  {count:>4}")
            for finding in [f for f in findings if f.rule_id == rule_id][: args.sample]:
                print(f"        {finding.path}:{finding.line}  {finding.title[:70]}")

    if len(args.paths) > 1:
        print(f"\nacross {len(args.paths)} repositories: {sum(totals.values())} finding(s)")
        for rule_id, count in sorted(totals.items(), key=lambda item: (-item[1], item[0])):
            print(f"  {rule_id}  {count:>4}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
