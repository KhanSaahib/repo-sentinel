"""Output formats: what the person, the pipeline and GitHub each get told."""

import dataclasses
import json
import unittest

from repo_sentinel import report, rules
from repo_sentinel.findings import Confidence, Finding, Severity

CRITICAL = Finding(
    rule_id="SEC001",
    severity=Severity.CRITICAL,
    title="AWS access key id",
    path="terraform/main.tf",
    line=14,
    evidence="AKIA****LM3D",
    remediation="Deactivate the key in IAM.",
)
GUESS = Finding(
    rule_id="SEC100",
    severity=Severity.HIGH,
    title="High-entropy quoted string assigned to 'api_key'",
    path="app.py",
    line=2,
    evidence="Qq7Z****Rt8W",
    confidence=Confidence.MEDIUM,
)


class TestText(unittest.TestCase):
    def test_clean_run_says_so_without_claiming_safety(self):
        self.assertIn("not proof of safety", report.format_text([], colour=False))

    def test_confidence_is_shown_only_when_it_is_not_certain(self):
        certain = report.format_text([CRITICAL], colour=False)
        guess = report.format_text([GUESS], colour=False)
        self.assertNotIn("confidence", certain)
        self.assertIn("(medium confidence)", guess)

    def test_notes_follow_the_summary(self):
        text = report.format_text([CRITICAL], colour=False, notes=["3 accepted."])
        self.assertTrue(text.endswith("3 accepted."))
        self.assertIn("1 finding(s): 1 critical", text)

    def test_colour_is_off_by_request(self):
        self.assertNotIn("\033", report.format_text([CRITICAL], colour=False))
        self.assertIn("\033", report.format_text([CRITICAL], colour=True))


class TestRepeatedValues(unittest.TestCase):
    """One credential pasted many times is one finding, and says so."""

    REPEATED = Finding(
        rule_id="SEC001",
        severity=Severity.CRITICAL,
        title="AWS access key id",
        path="fixtures/data.rb",
        line=27,
        evidence="AKIA****RBBQ",
        occurrences=758,
    )

    def test_the_text_report_says_how_many_other_lines(self):
        self.assertIn("(and on 757 more lines)", report.format_text([self.REPEATED], colour=False))

    def test_one_other_line_is_singular(self):
        twice = dataclasses.replace(self.REPEATED, occurrences=2)
        self.assertIn("(and on 1 more line)", report.format_text([twice], colour=False))

    def test_a_single_occurrence_says_nothing(self):
        self.assertNotIn("more line", report.format_text([CRITICAL], colour=False))

    def test_the_sarif_message_carries_the_count(self):
        payload = json.loads(report.format_sarif([self.REPEATED], version="0"))
        message = payload["runs"][0]["results"][0]["message"]["text"]
        self.assertIn("Repeated on 758 lines", message)

    def test_the_annotation_carries_the_count(self):
        self.assertIn("repeated on 758 lines", report.format_github([self.REPEATED]))

    def test_the_json_carries_the_count(self):
        payload = json.loads(report.format_json([self.REPEATED], version="0"))
        self.assertEqual(payload["findings"][0]["occurrences"], 758)


class TestTextGroupedByFile(unittest.TestCase):
    SECOND = Finding(
        rule_id="SEC002",
        severity=Severity.HIGH,
        title="A second finding in the same file",
        path="terraform/main.tf",
        line=40,
        evidence="AKIA****XXXX",
    )

    def grouped(self, findings):
        return report.format_text(findings, colour=False, by_file=True)

    def test_the_path_is_printed_once_for_all_of_its_findings(self):
        text = self.grouped([CRITICAL, self.SECOND])
        self.assertEqual(text.count("terraform/main.tf"), 1)
        self.assertIn("line 14", text)
        self.assertIn("line 40", text)

    def test_each_file_still_gets_its_own_heading(self):
        text = self.grouped([CRITICAL, GUESS])
        self.assertIn("terraform/main.tf", text)
        self.assertIn("app.py", text)

    def test_the_finding_says_as_much_as_it_does_ungrouped(self):
        text = self.grouped([CRITICAL])
        self.assertIn("AWS access key id", text)
        self.assertIn("evidence: AKIA****LM3D", text)
        self.assertIn("fix: Deactivate the key in IAM.", text)

    def test_a_guess_still_admits_to_being_one(self):
        self.assertIn("(medium confidence)", self.grouped([GUESS]))

    def test_a_clean_run_reads_the_same_either_way(self):
        self.assertEqual(self.grouped([]), report.format_text([], colour=False))


class TestSummary(unittest.TestCase):
    """--quiet is what a CI log gets, and it is read by somebody deciding."""

    def test_the_counts_survive(self):
        self.assertIn("1 critical", report.format_summary([CRITICAL]))

    def test_the_loudest_rules_come_with_it(self):
        batch = [CRITICAL, CRITICAL, GUESS]
        summary = report.format_summary(batch)
        self.assertIn("Most of it is:", summary)
        self.assertIn("SEC001", summary)
        self.assertIn("SEC100", summary)

    def test_one_rule_alone_needs_no_breakdown(self):
        self.assertNotIn("Most of it is", report.format_summary([CRITICAL]))

    def test_a_clean_run_says_only_that(self):
        summary = report.format_summary([], notes=["Scanned 4 file(s)."])
        self.assertIn("not proof of safety", summary)
        self.assertNotIn("Most of it is", summary)

    def test_the_notes_still_come_last(self):
        summary = report.format_summary([CRITICAL, GUESS], notes=["Scanned 4 file(s)."])
        self.assertTrue(summary.rstrip().endswith("Scanned 4 file(s)."))


class TestJson(unittest.TestCase):
    def test_every_finding_carries_a_fingerprint_and_confidence(self):
        payload = json.loads(report.format_json([CRITICAL, GUESS], version="0.2.0"))
        self.assertEqual(payload["finding_count"], 2)
        for record in payload["findings"]:
            self.assertIn("fingerprint", record)
            self.assertIn("confidence", record)


class TestSarif(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(report.format_sarif([CRITICAL, GUESS], version="0.2.0"))
        self.run = self.document["runs"][0]

    def test_shape_matches_the_schema_github_expects(self):
        self.assertEqual(self.document["version"], "2.1.0")
        self.assertEqual(self.run["tool"]["driver"]["name"], "repo-sentinel")
        self.assertEqual(len(self.run["results"]), 2)

    def test_rules_are_described_once_and_referenced_by_index(self):
        described = self.run["tool"]["driver"]["rules"]
        self.assertEqual([rule["id"] for rule in described], ["SEC001", "SEC100"])
        for result in self.run["results"]:
            self.assertEqual(described[result["ruleIndex"]]["id"], result["ruleId"])

    def test_only_rules_that_fired_are_described(self):
        self.assertLess(len(self.run["tool"]["driver"]["rules"]), len(rules.RULES))

    def test_the_weakness_class_travels_as_a_tag(self):
        tags = self.run["tool"]["driver"]["rules"][0]["properties"]["tags"]
        self.assertIn("CWE-798", tags)

    def test_severity_is_expressed_the_way_github_reads_it(self):
        first = self.run["tool"]["driver"]["rules"][0]
        self.assertEqual(first["defaultConfiguration"]["level"], "error")
        self.assertEqual(first["properties"]["security-severity"], "9.0")

    def test_each_rule_links_to_the_paragraph_explaining_it(self):
        # The Security tab shows a rule with nowhere to go unless the SARIF
        # says where the documentation is.
        described = self.run["tool"]["driver"]["rules"][0]
        self.assertTrue(described["helpUri"].endswith("/docs/RULES.md#secrets"))

    def test_fingerprints_survive_a_reformatted_file(self):
        moved = json.loads(
            report.format_sarif([Finding(**{**CRITICAL.__dict__, "line": 400})], version="0.2.0")
        )
        self.assertEqual(
            moved["runs"][0]["results"][0]["partialFingerprints"],
            self.run["results"][0]["partialFingerprints"],
        )

    def test_a_clean_run_is_still_a_valid_document(self):
        empty = json.loads(report.format_sarif([], version="0.2.0"))
        self.assertEqual(empty["runs"][0]["results"], [])
        self.assertEqual(empty["runs"][0]["tool"]["driver"]["rules"], [])


class TestSarifInvocation(unittest.TestCase):
    """A Security tab with no alerts should not hide an unread tree."""

    def invocation(self, scan=None):
        payload = json.loads(report.format_sarif([CRITICAL], version="0", scan=scan))
        return payload["runs"][0]["invocations"][0]

    def test_a_run_that_read_everything_says_only_that_it_worked(self):
        invocation = self.invocation({"unreadable": [], "oversized": []})
        self.assertTrue(invocation["executionSuccessful"])
        self.assertNotIn("toolExecutionNotifications", invocation)

    def test_what_could_not_be_read_becomes_a_notification(self):
        invocation = self.invocation({"unreadable": ["locked"], "oversized": ["dump.json"]})
        texts = [
            notification["message"]["text"]
            for notification in invocation["toolExecutionNotifications"]
        ]
        self.assertIn("locked could not be opened and was not scanned.", texts)
        self.assertIn("dump.json was larger than the size limit and was not scanned.", texts)

    def test_a_long_list_is_summarised_rather_than_listed(self):
        paths = [f"f{index}.py" for index in range(50)]
        notifications = self.invocation({"unreadable": paths})["toolExecutionNotifications"]
        self.assertEqual(len(notifications), report.SARIF_NOTIFICATION_LIMIT + 1)
        self.assertIn("30 further path(s)", notifications[-1]["message"]["text"])

    def test_the_document_is_still_valid_without_any_scan_facts(self):
        self.assertEqual(self.invocation(), {"executionSuccessful": True})


class TestMarkdown(unittest.TestCase):
    def setUp(self):
        self.text = report.format_markdown([CRITICAL, GUESS])

    def test_a_table_row_per_finding(self):
        self.assertIn("| `SEC001` | `terraform/main.tf:14` |", self.text)
        self.assertIn("| `SEC100` | `app.py:2` |", self.text)

    def test_the_heading_carries_the_summary(self):
        self.assertTrue(self.text.startswith("### repo-sentinel: 2 finding(s)"))

    def test_confidence_is_shown_only_when_it_is_not_certain(self):
        self.assertEqual(self.text.count("confidence"), 1)

    def test_fixes_appear_once_per_rule_not_once_per_finding(self):
        doubled = report.format_markdown([CRITICAL, CRITICAL])
        self.assertEqual(doubled.count("Deactivate the key in IAM."), 1)

    def test_a_pipe_in_a_title_cannot_break_the_table(self):
        awkward = Finding(
            rule_id="WF003",
            severity=Severity.CRITICAL,
            title="Untrusted input a | b interpolated",
            path="a.yml",
            line=1,
        )
        row = report.format_markdown([awkward]).splitlines()[3]
        self.assertEqual(row.count("|"), 5)

    def test_a_long_report_is_truncated_rather_than_endless(self):
        many = [CRITICAL] * 120
        text = report.format_markdown(many, limit=10)
        self.assertIn("...and 110 more", text)
        self.assertLess(text.count("terraform/main.tf"), 12)

    def test_a_clean_run_still_says_something(self):
        self.assertIn("not proof of safety", report.format_markdown([]))

    def test_notes_are_kept(self):
        self.assertIn("_3 accepted._", report.format_markdown([CRITICAL], notes=["3 accepted."]))


class TestGitHubAnnotations(unittest.TestCase):
    def test_one_workflow_command_per_finding(self):
        lines = report.format_github([CRITICAL, GUESS]).splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("::error file=terraform/main.tf,line=14,"))
        self.assertTrue(lines[1].startswith("::error file=app.py,line=2,"))

    def test_severity_maps_to_an_annotation_level(self):
        levels = [
            report.format_github([Finding("R", severity, "t", "a.py", 1)]).split(" ")[0]
            for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
        ]
        self.assertEqual(levels, ["::error", "::error", "::warning", "::notice"])

    def test_the_message_carries_the_fix(self):
        self.assertIn("Deactivate the key in IAM.", report.format_github([CRITICAL]))

    def test_structural_characters_are_escaped(self):
        # A workflow command is line-oriented: a colon or a newline in the
        # wrong place ends the annotation early and the rest becomes log noise.
        awkward = Finding(
            rule_id="WF003",
            severity=Severity.CRITICAL,
            title="Untrusted input in run: block",
            path="a b,c.yml",
            line=1,
            remediation="Line one\nline two",
        )
        line = report.format_github([awkward])
        self.assertEqual(len(line.splitlines()), 1)
        self.assertIn("file=a b%2Cc.yml", line)
        self.assertIn("%0A", line)

    def test_a_clean_run_still_says_something(self):
        self.assertIn("::notice::", report.format_github([]))

    def test_notes_become_notices(self):
        self.assertIn("::notice::3 accepted.", report.format_github([CRITICAL], notes=["3 accepted."]))


class TestRuleDetail(unittest.TestCase):
    """A pattern that narrows to one rule prints the card, not the row."""

    def card(self, pattern="WF011"):
        return report.format_rule_catalogue(pattern)

    def test_it_says_which_files_the_rule_even_looks_at(self):
        self.assertIn(".github/workflows", self.card())

    def test_it_says_how_to_silence_the_rule_in_both_scopes(self):
        card = self.card()
        self.assertIn("# repo-sentinel: ignore[WF011]", card)
        self.assertIn("--disable WF011", card)

    def test_it_links_the_weakness_and_the_documentation(self):
        card = self.card()
        self.assertIn("cwe.mitre.org/data/definitions/668", card)
        self.assertIn("docs/RULES.md#github-actions-workflows", card)

    def test_a_rule_with_no_weakness_class_simply_omits_it(self):
        self.assertNotIn("CWE", self.card("SEC900"))

    def test_a_pattern_matching_several_rules_still_lists_them(self):
        listing = report.format_rule_catalogue("kubernetes")
        self.assertIn("K8S001", listing)
        self.assertNotIn("--disable", listing)

    def test_the_json_carries_the_families_of_the_rules_it_lists(self):
        # A consumer grouping by category otherwise invents its own labels,
        # and invents different ones from the documentation's.
        payload = json.loads(report.format_rule_catalogue("kubernetes", as_json=True))
        family = payload["families"]["kubernetes"]
        self.assertIn("apiVersion", family["reads"])
        self.assertEqual(family["documentation"], "docs/RULES.md#kubernetes")

    def test_only_the_families_in_play_are_described(self):
        # "terraform" also matches a secret rule whose summary mentions it,
        # which is the pattern doing its job; what matters is that families
        # nothing matched are absent.
        payload = json.loads(report.format_rule_catalogue("terraform", as_json=True))
        self.assertIn("terraform", payload["families"])
        self.assertNotIn("kubernetes", payload["families"])

    def test_json_output_is_the_same_shape_for_one_rule_as_for_many(self):
        payload = json.loads(report.format_rule_catalogue("WF011", as_json=True))
        self.assertEqual(len(payload["rules"]), 1)


class TestJunit(unittest.TestCase):
    """The format every CI except GitHub already knows how to draw."""

    def parse(self, findings, **kwargs):
        import xml.etree.ElementTree as ElementTree

        return ElementTree.fromstring(report.format_junit(findings, **kwargs))

    def test_it_is_well_formed_xml_with_one_case_per_finding(self):
        root = self.parse([CRITICAL, GUESS])
        cases = root.findall("./testsuite/testcase")
        self.assertEqual(len(cases), 2)
        self.assertEqual(root.get("failures"), "2")

    def test_a_case_carries_the_severity_the_evidence_and_the_fix(self):
        failure = self.parse([CRITICAL]).find("./testsuite/testcase/failure")
        self.assertEqual(failure.get("type"), "critical")
        self.assertIn("AKIA****LM3D", failure.text)
        self.assertIn("Deactivate the key in IAM.", failure.text)

    def test_the_family_is_the_classname_so_a_ci_can_group_by_it(self):
        case = self.parse([CRITICAL]).find("./testsuite/testcase")
        self.assertEqual(case.get("classname"), "repo-sentinel.secrets")

    def test_a_clean_run_is_one_passing_case_not_an_empty_suite(self):
        root = self.parse([])
        cases = root.findall("./testsuite/testcase")
        self.assertEqual(len(cases), 1)
        self.assertEqual(root.get("failures"), "0")
        self.assertIsNone(cases[0].find("failure"))

    def test_notes_survive_as_properties(self):
        root = self.parse([], notes=["3 finding(s) accepted by the baseline."])
        values = [node.get("value") for node in root.findall("./testsuite/properties/property")]
        self.assertEqual(values, ["3 finding(s) accepted by the baseline."])

    def test_awkward_characters_do_not_break_the_document(self):
        awkward = Finding(
            rule_id="WF003",
            severity=Severity.CRITICAL,
            title='Untrusted input in run: <block> & "quoted"',
            path="a&b.yml",
            line=1,
            remediation="Use env: instead of <interpolation>.",
        )
        case = self.parse([awkward]).find("./testsuite/testcase")
        self.assertIn("a&b.yml", case.get("name"))
        self.assertIn("<interpolation>", case.find("failure").text)


class TestAwkwardContent(unittest.TestCase):
    """Evidence comes out of files, and files contain anything at all."""

    def finding(self, **kwargs):
        fields = dict(
            rule_id="SEC100",
            severity=Severity.HIGH,
            title="High-entropy value",
            path="a.py",
            line=3,
            evidence="e",
        )
        fields.update(kwargs)
        return Finding(**fields)

    def test_a_control_character_does_not_break_the_junit_document(self):
        import xml.etree.ElementTree as ElementTree

        # XML 1.0 cannot carry these at all -- not escaped, not in CDATA -- and
        # a report that fails to load says nothing about the repository.
        awkward = self.finding(title="title \x01 here", path="a\x0bb.py", evidence="xx\x00yy")
        ElementTree.fromstring(report.format_junit([awkward]))

    def test_every_kind_of_line_break_stays_inside_the_markdown_cell(self):
        for break_ in ("\n", "\r", "\r\n", "\u2028"):
            with self.subTest(break_=repr(break_)):
                awkward = self.finding(title=f"two{break_}lines")
                rows = report.format_markdown([awkward]).splitlines()
                self.assertEqual(len([row for row in rows if row.startswith("| ")]), 3)

    def test_a_pipe_in_a_value_does_not_add_a_column(self):
        row = [
            line
            for line in report.format_markdown([self.finding(title="a | b")]).splitlines()
            if "SEC100" in line
        ][0]
        self.assertEqual(row.count("|") - row.count("\\|"), 5)


class TestCatalogueOutput(unittest.TestCase):
    def test_text_lists_every_rule_under_its_category(self):
        text = report.format_rule_catalogue()
        self.assertIn("secrets:", text)
        self.assertIn("dockerfiles:", text)
        for rule_id in rules.RULES:
            self.assertIn(rule_id, text)

    def test_a_pattern_can_name_a_family_an_id_or_a_word(self):
        # One argument, three meanings: somebody typing "rules kubernetes"
        # should not have to learn which of the three it was.
        for pattern, expected in (("kubernetes", "K8S001"), ("SEC02", "SEC020"), ("bucket", "CF002")):
            with self.subTest(pattern=pattern):
                self.assertIn(expected, report.format_rule_catalogue(pattern))

    def test_a_pattern_excludes_what_it_does_not_match(self):
        text = report.format_rule_catalogue("dockerfiles")
        self.assertIn("DK001", text)
        self.assertNotIn("SEC001", text)
        self.assertIn(f"of {len(rules.RULES)}", text)

    def test_a_pattern_matching_nothing_suggests_what_might(self):
        text = report.format_rule_catalogue("nonsense")
        self.assertIn("No rule matches", text)
        self.assertIn("kubernetes", text)

    def test_the_json_form_is_filtered_too(self):
        payload = json.loads(report.format_rule_catalogue("terraform", as_json=True))
        self.assertTrue(payload["rules"])
        # A word matches the summary as well as the family, deliberately: the
        # Terraform Cloud token rule is a secret rule and is exactly what
        # somebody searching for "terraform" wants to see.
        for rule in payload["rules"]:
            with self.subTest(rule=rule["id"]):
                self.assertIn("terraform", (rule["category"] + " " + rule["summary"]).lower())
        self.assertIn("terraform", {rule["category"] for rule in payload["rules"]})

    def test_json_is_machine_readable(self):
        payload = json.loads(report.format_rule_catalogue(as_json=True))
        self.assertEqual(len(payload["rules"]), len(rules.RULES))
        self.assertEqual(payload["rules"][0]["id"], "SEC001")
        self.assertEqual(payload["rules"][0]["cwe"], "CWE-798")


if __name__ == "__main__":
    unittest.main()
