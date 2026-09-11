"""Dockerfile rules: base images, root, network trust, and baked credentials."""

import unittest

from repo_sentinel.findings import Severity
from repo_sentinel.scanners import dockerfiles


def rule_ids(findings):
    return {finding.rule_id for finding in findings}


def scan(text, path="Dockerfile"):
    return dockerfiles.scan_dockerfile(path, text)


class TestPathRecognition(unittest.TestCase):
    def test_recognises_the_usual_spellings(self):
        for path in (
            "Dockerfile",
            "docker/Dockerfile",
            "Dockerfile.prod",
            "build/api.dockerfile",
            "Containerfile",
        ):
            with self.subTest(path=path):
                self.assertTrue(dockerfiles.is_dockerfile_path(path))

    def test_ignores_everything_else(self):
        for path in ("docker-compose.yml", "dockerfiles.md", "src/docker.py"):
            with self.subTest(path=path):
                self.assertFalse(dockerfiles.is_dockerfile_path(path))


class TestBaseImages(unittest.TestCase):
    def test_digest_pinned_image_is_accepted(self):
        text = "FROM alpine:3.19@sha256:" + "a" * 64 + "\nUSER app\n"
        self.assertNotIn("DK001", rule_ids(scan(text)))

    def test_latest_is_worse_than_a_specific_tag(self):
        floating = scan("FROM debian:latest\nUSER app\n")
        pinned = scan("FROM debian:12.5\nUSER app\n")
        self.assertEqual(next(iter(floating)).severity, Severity.MEDIUM)
        self.assertEqual(next(iter(pinned)).severity, Severity.LOW)

    def test_an_interpolated_tag_is_chosen_by_a_build_argument(self):
        text = "ARG VARIANT=17\nFROM debian:${VARIANT}\nUSER app\n"
        self.assertEqual(scan(text), [])

    def test_scratch_is_not_an_image_to_pin(self):
        self.assertEqual(scan("FROM scratch\nCOPY app /app\n"), [])


class TestFinalUser(unittest.TestCase):
    def test_missing_user_is_reported(self):
        self.assertIn("DK002", rule_ids(scan("FROM debian:12@sha256:" + "b" * 64 + "\n")))

    def test_explicit_root_is_reported(self):
        findings = scan("FROM debian:12@sha256:" + "c" * 64 + "\nUSER root\n")
        self.assertIn("DK002", rule_ids(findings))

    def test_only_the_final_stage_is_judged(self):
        # The build stage is thrown away; demanding a user there is the kind of
        # finding that gets the whole tool switched off.
        text = (
            "FROM golang:1.22@sha256:" + "d" * 64 + " AS build\n"
            "RUN go build ./...\n"
            "FROM gcr.io/distroless/static@sha256:" + "e" * 64 + "\n"
            "USER nonroot\n"
        )
        self.assertNotIn("DK002", rule_ids(scan(text)))


class TestNetworkTrust(unittest.TestCase):
    def test_flags_pipe_to_shell_across_a_continuation(self):
        text = (
            "FROM debian:12@sha256:" + "f" * 64 + "\n"
            "RUN curl -sSL https://example.invalid/install.sh | \\\n"
            "    bash\n"
            "USER app\n"
        )
        findings = scan(text)
        self.assertIn("DK003", rule_ids(findings))
        # Reported where the instruction starts, not where the pipe landed.
        self.assertEqual(next(f.line for f in findings if f.rule_id == "DK003"), 2)

    def test_flags_disabled_certificate_verification(self):
        text = "FROM debian:12@sha256:" + "0" * 64 + "\nRUN curl -k https://x/y\nUSER app\n"
        self.assertIn("DK006", rule_ids(scan(text)))

    def test_accepts_a_verified_download(self):
        text = (
            "FROM debian:12@sha256:" + "1" * 64 + "\n"
            "RUN curl -sSLo pkg.tgz https://example.invalid/pkg.tgz \\\n"
            " && echo 'abc123  pkg.tgz' | sha256sum -c -\n"
            "USER app\n"
        )
        self.assertEqual(rule_ids(scan(text)), set())

    def test_flags_add_from_a_url(self):
        text = "FROM debian:12@sha256:" + "2" * 64 + "\nADD https://x/y.tgz /opt/\nUSER app\n"
        self.assertIn("DK005", rule_ids(scan(text)))

    def test_local_copy_is_fine(self):
        text = "FROM debian:12@sha256:" + "3" * 64 + "\nADD ./dist /opt/\nUSER app\n"
        self.assertNotIn("DK005", rule_ids(scan(text)))


class TestBakedCredentials(unittest.TestCase):
    def test_flags_a_credential_in_an_arg(self):
        text = "FROM debian:12@sha256:" + "4" * 64 + "\nARG NPM_TOKEN=Xk92mQp7Lz4TvB8nRw1Y\nUSER app\n"
        findings = scan(text)
        self.assertIn("DK004", rule_ids(findings))
        self.assertNotIn("Xk92mQp7Lz4TvB8nRw1Y", findings[0].evidence)

    def test_ignores_ordinary_configuration(self):
        text = "FROM debian:12@sha256:" + "5" * 64 + "\nENV APP_ENV=production PORT=8080\nUSER app\n"
        self.assertNotIn("DK004", rule_ids(scan(text)))

    def test_ignores_a_placeholder(self):
        text = "FROM debian:12@sha256:" + "6" * 64 + "\nENV API_KEY=changeme\nUSER app\n"
        self.assertNotIn("DK004", rule_ids(scan(text)))


class TestSuppression(unittest.TestCase):
    def test_file_marker_silences_the_dockerfile(self):
        text = "# repo-sentinel: ignore-file\nFROM debian:latest\n"
        self.assertEqual(scan(text), [])

    def test_line_marker_silences_one_instruction(self):
        text = (
            "FROM debian:12@sha256:" + "7" * 64 + "\n"
            "ADD https://x/y.tgz /opt/  # repo-sentinel: ignore\n"
            "USER app\n"
        )
        self.assertNotIn("DK005", rule_ids(scan(text)))


if __name__ == "__main__":
    unittest.main()
