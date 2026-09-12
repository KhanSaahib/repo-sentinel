"""Three idioms in application code, read per language."""

import unittest

from repo_sentinel.findings import Confidence, Severity
from repo_sentinel.scanners import appcode


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


def scan(path, text):
    return appcode.scan_source(path, text)


class TestHints(unittest.TestCase):
    """A hint a rule's own match does not contain disables it, silently."""

    CASES = {
        "verify=False": "app.py",
        "ssl._create_unverified_context()": "app.py",
        "check_hostname=False": "app.py",
        "rejectUnauthorized: false": "a.js",
        "NODE_TLS_REJECT_UNAUTHORIZED=0": "a.js",
        "InsecureSkipVerify: true": "main.go",
        "curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);": "a.php",
        "OpenSSL::SSL::VERIFY_NONE": "a.rb",
        "DEBUG = True": "settings.py",
        "app.run(debug=True)": "app.py",
        "yaml.load(body)": "app.py",
        'unserialize($_POST["x"])': "a.php",
        "hashlib.md5(password)": "app.py",
        'system("ls " . $_GET["d"]);': "a.php",
        'subprocess.run(f"tar {name}", shell=True)': "app.py",
        "exec(`git log ${branch}`)": "a.js",
        "token = Math.random()": "a.js",
    }

    def test_every_rule_fires_on_a_line_carrying_its_own_shape(self):
        # The gate rejects a file that mentions none of a rule's words, so a
        # wrong word means the rule never runs and nothing says so.
        fired = set()
        for line, path in self.CASES.items():
            findings = appcode.scan_source(path, line + "\n")
            self.assertTrue(findings, line)
            fired.update(finding.rule_id for finding in findings)
        self.assertEqual(fired, {rule.rule_id for rule in appcode._RULES})

    def test_every_rule_has_hints(self):
        for rule in appcode._RULES:
            with self.subTest(rule=rule.rule_id, pattern=rule.pattern.pattern[:40]):
                self.assertTrue(rule.hints)


class TestWhichFilesAreRead(unittest.TestCase):
    def test_the_languages_the_rules_know(self):
        for path in ("a.py", "a.js", "a.ts", "a.tsx", "a.go", "a.php", "a.rb"):
            with self.subTest(path=path):
                self.assertTrue(appcode.is_source_path(path))

    def test_a_bundle_is_machine_output_and_is_skipped(self):
        self.assertFalse(appcode.is_source_path("dist/app.min.js"))
        self.assertFalse(appcode.is_source_path("vendor/jquery-min.js"))

    def test_a_file_in_another_language_is_left_alone(self):
        self.assertFalse(appcode.is_source_path("Main.java"))
        self.assertFalse(appcode.is_source_path("README.md"))


class TestVerificationOff(unittest.TestCase):
    def test_python_requests(self):
        findings = scan("app.py", "r = requests.get(url, verify=False)\n")
        self.assertIn("AP001", rule_ids(findings))
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_python_unverified_context(self):
        text = "ctx = ssl._create_unverified_context()\n"
        self.assertIn("AP001", rule_ids(scan("app.py", text)))

    def test_node_reject_unauthorized(self):
        text = "const agent = new https.Agent({ rejectUnauthorized: false });\n"
        self.assertIn("AP001", rule_ids(scan("client.js", text)))

    def test_go_insecure_skip_verify(self):
        text = "cfg := &tls.Config{InsecureSkipVerify: true}\n"
        self.assertIn("AP001", rule_ids(scan("main.go", text)))

    def test_php_curl_option(self):
        text = "curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);\n"
        self.assertIn("AP001", rule_ids(scan("api.php", text)))

    def test_ruby_verify_none(self):
        text = "http.verify_mode = OpenSSL::SSL::VERIFY_NONE\n"
        self.assertIn("AP001", rule_ids(scan("client.rb", text)))

    def test_an_idiom_is_read_only_in_its_own_language(self):
        # "verify=False" is a Python spelling. In a Go file it is a keyword
        # argument that does not exist, so reporting it would be a guess.
        self.assertEqual(scan("main.go", "verify=False\n"), [])

    def test_verification_left_on_is_not_a_finding(self):
        self.assertEqual(scan("app.py", "requests.get(url, verify=True)\n"), [])
        self.assertEqual(scan("client.js", "{ rejectUnauthorized: true }\n"), [])


class TestDebugMode(unittest.TestCase):
    def test_django_settings(self):
        findings = scan("settings.py", "DEBUG = True\n")
        self.assertIn("AP002", rule_ids(findings))
        self.assertEqual(findings[0].confidence, Confidence.MEDIUM)

    def test_flask_runner(self):
        self.assertIn("AP002", rule_ids(scan("app.py", "app.run(host='0.0.0.0', debug=True)\n")))

    def test_reading_the_value_from_the_environment_is_the_fix(self):
        text = 'DEBUG = os.environ.get("DEBUG", "") == "1"\n'
        self.assertEqual(scan("settings.py", text), [])

    def test_another_variable_that_merely_ends_in_debug(self):
        self.assertEqual(scan("app.py", "SQL_DEBUG = True\n"), [])


class TestPredictableCredentials(unittest.TestCase):
    def test_a_token_from_math_random(self):
        text = "const token = Math.random().toString(36);\n"
        findings = scan("auth.js", text)
        self.assertIn("AP003", rule_ids(findings))
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_a_reset_code_from_the_python_random_module(self):
        text = 'reset_code = "".join(random.choice(digits) for _ in range(6))\n'
        self.assertIn("AP003", rule_ids(scan("accounts.py", text)))

    def test_a_generator_used_for_something_that_is_not_a_credential(self):
        # The rule is gated on the name for a reason: these generators pick a
        # colour far more often than they pick a token.
        self.assertEqual(scan("ui.js", "const jitter = Math.random() * 100;\n"), [])

    def test_the_cryptographic_source_is_not_reported(self):
        text = "token = secrets.token_urlsafe(32)\n"
        self.assertEqual(scan("auth.py", text), [])


class TestUnsafeDeserialisation(unittest.TestCase):
    def test_yaml_load_without_a_loader(self):
        findings = scan("app.py", "data = yaml.load(body)\n")
        finding = next(f for f in findings if f.rule_id == "AP004")
        self.assertEqual(finding.severity, Severity.HIGH)

    def test_a_loader_makes_the_call_a_decision(self):
        text = "data = yaml.load(body, Loader=yaml.SafeLoader)\n"
        self.assertNotIn("AP004", rule_ids(scan("app.py", text)))

    def test_safe_load_is_the_fix(self):
        self.assertEqual(scan("app.py", "data = yaml.safe_load(body)\n"), [])

    def test_php_unserialising_a_superglobal(self):
        text = '$o = unserialize($_POST["data"]);\n'
        self.assertIn("AP004", rule_ids(scan("index.php", text)))

    def test_php_unserialising_something_it_wrote_itself(self):
        text = "$o = unserialize($cached);\n"
        self.assertNotIn("AP004", rule_ids(scan("index.php", text)))


class TestPasswordHashing(unittest.TestCase):
    def test_a_password_through_a_fast_digest(self):
        for line in (
            "digest = hashlib.md5(password.encode()).hexdigest()\n",
            "$h = sha1($passwd);\n",
            "const h = sha256(password)\n",
        ):
            with self.subTest(line=line.strip()):
                path = "app.py" if "hashlib" in line else ("a.php" if "$" in line else "a.js")
                self.assertIn("AP005", rule_ids(scan(path, line)))

    def test_a_checksum_of_something_that_is_not_a_password(self):
        self.assertEqual(scan("app.py", "digest = hashlib.sha256(file_bytes).hexdigest()\n"), [])

    def test_a_slow_hash_is_the_fix(self):
        self.assertEqual(scan("app.py", "digest = bcrypt.hashpw(password, salt)\n"), [])


class TestShellFromInterpolation(unittest.TestCase):
    """AP006: the injection class, in the language rather than the pipeline."""

    def test_a_request_inside_a_php_command_is_critical(self):
        findings = scan("index.php", 'system("ls " . $_GET["dir"]);\n')
        finding = next(f for f in findings if f.rule_id == "AP006")
        self.assertEqual(finding.severity, Severity.CRITICAL)

    def test_a_fixed_php_command_is_not(self):
        self.assertEqual(scan("index.php", 'system("ls /tmp");\n'), [])

    def test_a_python_call_with_a_shell_and_an_f_string(self):
        findings = scan("app.py", 'subprocess.run(f"tar -xf {name}", shell=True)\n')
        finding = next(f for f in findings if f.rule_id == "AP006")
        self.assertEqual(finding.confidence, Confidence.MEDIUM)

    def test_a_list_of_arguments_is_the_fix(self):
        self.assertEqual(scan("app.py", 'subprocess.run(["tar", "-xf", name])\n'), [])

    def test_a_shell_with_nothing_interpolated_into_it(self):
        self.assertEqual(scan("app.py", 'subprocess.run("ls -la", shell=True)\n'), [])

    def test_node_exec_with_a_template_literal(self):
        self.assertIn("AP006", rule_ids(scan("a.js", "exec(`git log ${branch}`)\n")))

    def test_exec_file_takes_its_arguments_separately(self):
        self.assertEqual(scan("a.js", 'execFile("git", ["log", branch])\n'), [])


class TestFixtureTrees(unittest.TestCase):
    """An end-to-end suite talking to a self-signed server is the ordinary case."""

    CODE = "cfg := &tls.Config{InsecureSkipVerify: true}\n"

    def test_the_same_line_is_weaker_under_a_test_tree(self):
        shipped = scan("internal/client/main.go", self.CODE)[0]
        tested = scan("test/e2e/admission/admission_test.go", self.CODE)[0]
        self.assertLess(tested.confidence, shipped.confidence)

    def test_it_is_weakened_rather_than_dropped(self):
        # The idiom copied out of a test into the client it exercises is
        # exactly how it ships.
        self.assertIn("AP001", rule_ids(scan("test/e2e/admission_test.go", self.CODE)))


class TestSuppressionAndScope(unittest.TestCase):
    def test_a_marker_silences_the_line(self):
        text = "requests.get(url, verify=False)  # repo-sentinel: ignore[AP001]\n"
        self.assertEqual(scan("app.py", text), [])

    def test_scan_files_filters_by_language(self):
        files = [
            ("app.py", "requests.get(url, verify=False)\n"),
            ("notes.md", "requests.get(url, verify=False)\n"),
        ]
        findings = appcode.scan_files(files)
        self.assertEqual([finding.path for finding in findings], ["app.py"])

    def test_a_whole_file_marker_is_obeyed(self):
        text = "# repo-sentinel: ignore-file\nrequests.get(url, verify=False)\n"
        self.assertEqual(scan("app.py", text), [])

    def test_a_match_the_length_of_a_minified_line_is_not_reported(self):
        # A bundle that escaped the name check: one line, thousands of
        # characters, and an idiom nobody in this repository typed.
        text = "const token = " + "x" * 500 + "Math.random()\n"
        self.assertEqual(scan("app.js", text), [])

    def test_a_file_with_none_of_the_hints_costs_nothing(self):
        # The cheap substring gate in front of the patterns: a file that
        # mentions none of them never runs one.
        self.assertEqual(scan("app.py", "x = 1\n" * 500), [])


if __name__ == "__main__":
    unittest.main()
