# Roadmap

The backlog for repo-sentinel, roughly in priority order. Work moves top-down.
Tick an item when it lands on `main` with tests and a green CI run.

Anything here can be reordered, rewritten, or dropped if it turns out to be a
bad idea. A crossed-out item with a note explaining why it was wrong is a better
outcome than a feature nobody wanted.

## Detection quality

- [x] Allowlist documented public example credentials (`AKIAIOSFODNN7EXAMPLE`,
      RFC test JWTs) so the scanner stops flagging documentation
- [x] Respect `.gitignore` when walking a repository, nested files included,
      with `--no-gitignore` to audit what was hidden
- [x] File-level and block-level suppression, not just per-line
      (`ignore-file`, `ignore-start` / `ignore-end`). The file-level marker is
      only honoured in the first 20 lines, so a document that merely mentions
      it does not go unscanned; an unterminated block is reported as SEC900
- [x] Baseline file: record accepted findings so CI only fails on new ones
      (`--write-baseline`, `--baseline`). Fingerprints hash already-redacted
      evidence and omit line numbers, so the file is safe to commit and
      survives reformatting
- [x] ~~Track the entropy floor separately per rule~~ — per *rule* was the wrong
      axis. The threshold does not depend on which rule found the value; it
      depends on the value's own alphabet and length, which is what
      `heuristics.entropy_floor` now measures. One rule scanning both a hex
      token and a base64 blob needs both floors
- [x] Detect secrets in `.env`, `.npmrc`, `.pypirc` and `docker-compose.yml`
      value positions, where there is no quoted assignment to match (SEC101)
- [x] More provider rules: Azure storage keys, Google OAuth client secrets,
      SendGrid, Twilio, npm, PyPI, Docker Hub, Hugging Face, Slack webhooks,
      and credentials embedded in connection strings
- [x] Confidence score per finding, separate from severity, with
      `--min-confidence` to gate on it
- [ ] GCP service account JSON as a whole document, not just the private key
      line inside it
- [ ] Multi-line detection generally: the scanner is line-by-line, so a PEM body
      or a wrapped JSON credential is only caught by its first line
- [ ] Verify a candidate is not already public (git history vs. working tree),
      and report first-seen commit
- [ ] Optional live validation (`--verify`) that asks the provider whether a
      token is still active. Off by default and probably always: it turns a
      static scan into an outbound request carrying a credential

## Workflow and CI analysis

- [x] Per-job `permissions:` analysis rather than the current file-level check
- [x] Warn when a job has `permissions: write-all` (WF005)
- [x] Flag secrets passed to a third-party action (WF007)
- [x] Flag workflows triggered by `workflow_run` that check out the triggering
      run's head (WF008)
- [x] Detect self-hosted runners (WF006). Whether the repository is public is
      not knowable offline, so the finding says what it saw and why it matters
- [ ] Detect `actions/checkout` with `persist-credentials: true` (the default)
      followed by a step that runs untrusted code
- [ ] Warn on `contents: write` without an obvious need — needs a notion of
      "obvious need" that does not just move the noise somewhere else
- [ ] Reusable workflow calls (`uses:` at job level) pinned to a mutable ref
- [ ] `GITHUB_TOKEN` or a secret written into an output, where it survives into
      the calling workflow's logs

## Beyond GitHub Actions

- [x] Dockerfile checks: running as root, `curl | sh`, unpinned base images,
      secrets in `ARG`/`ENV`, `ADD` from a URL, disabled TLS verification
- [ ] Terraform checks: public S3 buckets, `0.0.0.0/0` security group ingress,
      unencrypted storage
- [ ] Kubernetes manifests: privileged containers, hostPath mounts, missing
      resource limits
- [ ] `docker-compose.yml` beyond secrets: privileged services, host network,
      Docker socket mounts

## Output and integration

- [x] SARIF output so findings appear in the GitHub Security tab, with stable
      partial fingerprints so code scanning tracks a finding across edits
- [x] Pre-commit hook definition
- [x] GitHub Action wrapper in this repository
- [x] `repo-sentinel rules` to print the catalogue, in text or JSON
- [ ] `--diff` mode: scan only files changed against a base ref, for fast PR
      runs. Needs git, which every other part of this tool avoids shelling out
      to; the honest version is a `--paths-from` flag that reads a file list
- [ ] Publish to PyPI so `pipx run repo-sentinel` works
- [ ] `--quiet` for CI logs that only need the summary line
- [ ] Group findings by file in text output when there are many

## Engineering health

- [x] A corpus that trips every rule, asserted in both directions against the
      catalogue, so a new rule cannot ship undocumented and a deleted one
      cannot leave its entry behind
- [x] CONTRIBUTING.md
- [ ] Coverage measurement in CI with a floor
- [ ] Property-based tests for the entropy and redaction functions
- [ ] Benchmark against a large repository; the walk should stay under a second
      for 10k files. Measured today over the Python 3.14 standard library: 631
      files, ~305k lines, 3.4s. Most of it is one combined regex per line, so
      the win to find is a cheaper way to reject a line outright
- [ ] Type annotations checked with mypy in CI
- [ ] Issue templates
- [ ] Enable CodeQL default setup and branch protection on `main`
