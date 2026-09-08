# Roadmap

The backlog for repo-sentinel, roughly in priority order. Work moves top-down.
Tick an item when it lands on `main` with tests and a green CI run.

Anything here can be reordered, rewritten, or dropped if it turns out to be a
bad idea. A crossed-out item with a note explaining why it was wrong is a better
outcome than a feature nobody wanted.

## Detection quality

- [ ] Allowlist documented public example credentials (`AKIAIOSFODNN7EXAMPLE`,
      RFC test JWTs) so the scanner stops flagging documentation
- [ ] Respect `.gitignore` when walking a repository
- [ ] File-level and block-level suppression, not just per-line
      (`# repo-sentinel: ignore-file`, `ignore-start` / `ignore-end`)
- [ ] Baseline file: record accepted findings so CI only fails on new ones
- [ ] Track the entropy floor separately per rule; 3.2 is too low for base64
      blobs and too high for short hex tokens
- [ ] Detect secrets in `.env`, `.npmrc`, `.pypirc` and `docker-compose.yml`
      value positions, where there is no quoted assignment to match
- [ ] More provider rules: Azure storage keys, GCP service account JSON,
      SendGrid, Twilio, npm tokens, PyPI tokens, Docker Hub tokens
- [ ] Confidence score per finding, separate from severity
- [ ] Verify a candidate is not already public (git history vs. working tree),
      and report first-seen commit

## Workflow and CI analysis

- [ ] Detect `actions/checkout` with `persist-credentials: true` (the default)
      followed by a step that runs untrusted code
- [ ] Flag `secrets.GITHUB_TOKEN` passed to a third-party action
- [ ] Flag workflows triggered by `workflow_run` that check out the triggering
      run's head
- [ ] Detect self-hosted runners on public repositories
- [ ] Per-job `permissions:` analysis rather than the current file-level check
- [ ] Warn when a job has `permissions: write-all` or `contents: write` without
      an obvious need

## Beyond GitHub Actions

- [ ] Dockerfile checks: running as root, `curl | sh`, unpinned base images,
      secrets in `ARG`/`ENV`
- [ ] Terraform checks: public S3 buckets, `0.0.0.0/0` security group ingress,
      unencrypted storage
- [ ] Kubernetes manifests: privileged containers, hostPath mounts, missing
      resource limits

## Output and integration

- [ ] SARIF output so findings appear in the GitHub Security tab
- [ ] `--diff` mode: scan only files changed against a base ref, for fast PR runs
- [ ] Pre-commit hook definition
- [ ] Publish to PyPI so `pipx run repo-sentinel` works
- [ ] GitHub Action wrapper in this repository
- [ ] `--quiet` and `--verbose` levels; make text output narrower than 80 columns

## Engineering health

- [ ] Coverage measurement in CI with a floor
- [ ] Property-based tests for the entropy and redaction functions
- [ ] Benchmark against a large repository; the walk should stay under a second
      for 10k files
- [ ] Type annotations checked with mypy in CI
- [ ] CONTRIBUTING.md and issue templates
- [ ] Enable CodeQL default setup and branch protection on `main`
