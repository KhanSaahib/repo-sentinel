"""The rule catalogue must describe exactly what the scanners can emit."""

import pathlib
import unittest

import corpus
from repo_sentinel import rules
from repo_sentinel.scanners import (
    ansible,
    appcode,
    azure,
    circleci,
    cloudformation,
    compose,
    dependencies,
    dockerfiles,
    filenames,
    gitlab,
    jenkins,
    kubernetes,
    providers,
    secrets,
    shell,
    terraform,
    workflows,
)


#: Every scanner that reads ``(path, text)`` pairs. Listed once, because a new
#: scanner missing from this tuple would make the drift test pass by not
#: asking -- the one way for that test to be useless.
CONTENT_SCANNERS = (
    ansible,
    appcode,
    azure,
    circleci,
    cloudformation,
    compose,
    dependencies,
    dockerfiles,
    gitlab,
    jenkins,
    kubernetes,
    secrets,
    shell,
    terraform,
    workflows,
)


def all_findings():
    """Every finding the corpus produces, from every scanner there is."""
    findings = list(filenames.scan_paths(corpus.PATHS))
    for scanner in CONTENT_SCANNERS:
        findings += scanner.scan_files(corpus.FILES)
    return findings


def emitted_rule_ids():
    return {finding.rule_id for finding in all_findings()}


class TestCoverageOfTheScanners(unittest.TestCase):
    def test_every_scanner_module_is_asked(self):
        # A new scanner missing from CONTENT_SCANNERS would make the drift
        # tests pass by not asking it anything.
        from repo_sentinel import scanners

        modules = {
            getattr(scanners, name)
            for name in scanners.__all__
            if name not in ("allowlist", "filenames")
        }
        self.assertEqual(modules, set(CONTENT_SCANNERS))


_ONES = (
    "zero", "one", "two", "three", "four", "five", "six", "seven", "eight",
    "nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen",
    "sixteen", "seventeen", "eighteen", "nineteen",
)
_TENS = ("", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety")


def in_words(number: int) -> str:
    """Spell a number the way the README does, capitalised.

    This used to be a hand-written table of every total the catalogue had
    passed through, extended by whoever added the rule that broke it. The
    test it serves is about the README rotting, not about arithmetic.
    """
    if number >= 100:
        rest = number % 100
        hundreds = f"{_ONES[number // 100]} hundred"
        spelled = hundreds if not rest else f"{hundreds} and {in_words(rest).lower()}"
    elif number >= 20:
        tens, ones = divmod(number, 10)
        spelled = _TENS[tens] if not ones else f"{_TENS[tens]}-{_ONES[ones]}"
    else:
        spelled = _ONES[number]
    return spelled[0].upper() + spelled[1:]


def _documentation() -> str:
    root = pathlib.Path(__file__).resolve().parents[1]
    return (root / "docs" / "RULES.md").read_text(encoding="utf-8")


class TestCatalogue(unittest.TestCase):
    def test_every_emitted_rule_is_catalogued(self):
        undescribed = emitted_rule_ids() - set(rules.RULES)
        self.assertEqual(undescribed, set(), "scanners emit rules the catalogue omits")

    def test_every_catalogued_rule_can_fire(self):
        # The other direction, which is the one that rots quietly: a rule
        # renamed or deleted in a scanner leaves its entry behind, and the
        # README grows a row for a check that no longer exists.
        unreachable = set(rules.RULES) - emitted_rule_ids()
        self.assertEqual(unreachable, set(), "catalogue describes rules nothing emits")

    def test_every_family_says_what_it_reads_and_where_it_is_written_up(self):
        categories = {rule.category for rule in rules.RULES.values()}
        self.assertEqual(categories, set(rules.FAMILIES))

    def test_every_family_anchor_is_a_real_heading(self):
        # The card printed for a single rule sends people to docs/RULES.md by
        # anchor, and a link into a document is exactly the kind of thing that
        # goes stale without anyone noticing.
        headings = {
            line[3:].strip().lower().replace(" ", "-").replace("&", "")
            for line in _documentation().splitlines()
            if line.startswith("## ")
        }
        for name, family in rules.FAMILIES.items():
            with self.subTest(family=name):
                self.assertIn(family.anchor, headings)

    def test_the_candidate_gate_lets_every_provider_rule_through(self):
        # providers.CANDIDATE decides which lines are worth looking at closely,
        # and a line it rejects is never looked at again. Every line of the
        # corpus that trips a provider rule has to clear it.
        for path, text in corpus.FILES:
            for number, line in enumerate(text.splitlines(), start=1):
                hits = [
                    finding
                    for finding in secrets.scan_line(path, number, line)
                    if not finding.rule_id.startswith("SEC1")
                ]
                if hits:
                    with self.subTest(rule=hits[0].rule_id):
                        self.assertIsNotNone(providers.CANDIDATE.search(line))

    def test_no_rule_is_worse_in_practice_than_the_catalogue_says(self):
        # The catalogue lists the worst case, which is what a reader planning a
        # gate needs: "TF001 is critical" has to mean it never arrives at
        # something higher. Several rules grade themselves down by context, so
        # the invariant is one-directional.
        for finding in all_findings():
            with self.subTest(rule=finding.rule_id):
                self.assertLessEqual(
                    finding.severity,
                    rules.RULES[finding.rule_id].severity,
                    f"{finding.rule_id} reported {finding.severity.value} but the "
                    f"catalogue promises at most {rules.RULES[finding.rule_id].severity.value}",
                )

    #: Shapes with no literal anywhere in them, which therefore run their
    #: pattern on every candidate line. A Discord token is base64 all the way
    #: through: the only thing every one of them contains is a dot, and a hint
    #: of "." is every line in the repository.
    UNHINTED = {"SEC036"}

    def test_only_the_known_rules_run_without_a_hint(self):
        # A rule with no hint still works; it just costs what the hints exist
        # to avoid. Asserting the exact set means adding another is a decision
        # somebody makes on purpose rather than by omission.
        without = {rule.rule_id for rule in providers.RULES if not rule.hints}
        self.assertEqual(without, self.UNHINTED)

    def test_a_rule_fires_only_where_its_hint_appears(self):
        # The other direction, and the dangerous one: a hint that does not
        # appear in what the pattern matches disables the rule silently. The
        # corpus catches it, so assert the property directly on that corpus.
        for path, text in corpus.FILES:
            for number, line in enumerate(text.splitlines(), start=1):
                for finding in secrets.scan_line(path, number, line):
                    rule = next(
                        (item for item in providers.RULES if item.rule_id == finding.rule_id),
                        None,
                    )
                    if rule is None or not rule.hints:
                        continue
                    with self.subTest(rule=rule.rule_id):
                        self.assertTrue(
                            any(hint in line for hint in rule.hints),
                            f"{rule.rule_id} fired on a line containing none of its hints",
                        )

    def test_provider_rules_agree_with_the_catalogue_on_severity(self):
        for rule in providers.RULES:
            with self.subTest(rule=rule.rule_id):
                self.assertEqual(rules.RULES[rule.rule_id].severity, rule.severity)

    def test_every_rule_is_documented(self):
        # The catalogue keeps the scanners honest; this keeps the prose honest.
        # A rule table nobody is forced to update is a rule table that
        # describes the release before last.
        root = pathlib.Path(__file__).resolve().parents[1]
        documentation = (root / "docs" / "RULES.md").read_text(encoding="utf-8")
        undocumented = sorted(
            rule_id for rule_id in rules.RULES if rule_id not in documentation
        )
        self.assertEqual(undocumented, [], "rules missing from docs/RULES.md")

    def test_the_documented_severity_matches_the_catalogue(self):
        # The tables carry a severity column, and a column nobody checks drifts
        # from the code it describes. Several rows qualify the answer ("critical
        # to an admin port, otherwise high"), so the assertion is that the
        # catalogue's word appears in the row, not that the row is only that.
        root = pathlib.Path(__file__).resolve().parents[1]
        documentation = (root / "docs" / "RULES.md").read_text(encoding="utf-8")
        rows = {
            line.split("|")[1].strip(): line
            for line in documentation.splitlines()
            if line.startswith("| ") and line.count("|") >= 4
        }
        for rule_id, rule in rules.RULES.items():
            with self.subTest(rule=rule_id):
                row = rows.get(rule_id)
                self.assertIsNotNone(row, f"{rule_id} has no table row")
                self.assertIn(
                    rule.severity.value,
                    row.lower(),
                    f"{rule_id} is {rule.severity.value} in the catalogue but the "
                    f"table says: {row.strip()}",
                )

    def test_the_readme_summary_counts_the_rules_correctly(self):
        # The README quotes a total. A number in prose is a number that rots.
        root = pathlib.Path(__file__).resolve().parents[1]
        readme = (root / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"{in_words(len(rules.RULES))} rules", readme)

    def test_the_readme_counts_the_families_correctly(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        readme = (root / "README.md").read_text(encoding="utf-8")
        families = in_words(len(rules.FAMILIES)).lower()
        self.assertIn(f"across {families} families", readme)

    def test_every_rule_names_the_weakness_it_reports(self):
        # A CWE is a claim, not a decoration, so the only rule without one is
        # the one that reports a mistake in this tool's own configuration
        # rather than a weakness in anybody's software.
        without = {rule.id for rule in rules.RULES.values() if rule.cwe is None}
        self.assertEqual(without, {"SEC900"})

    def test_the_weakness_identifiers_are_well_formed(self):
        for rule in rules.RULES.values():
            if rule.cwe is None:
                continue
            with self.subTest(rule=rule.id):
                self.assertRegex(rule.cwe, r"^CWE-\d{1,4}$")

    def test_ids_are_unique_and_sorted_within_a_category(self):
        for category, catalogued in rules.by_category().items():
            ids = [rule.id for rule in catalogued]
            with self.subTest(category=category):
                self.assertEqual(ids, sorted(ids))
                self.assertEqual(len(ids), len(set(ids)))


if __name__ == "__main__":
    unittest.main()
