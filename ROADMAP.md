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
- [x] GCP service account JSON as a whole document, not just the private key
      line inside it (SEC021), and any provider credential hidden inside base64
      (SEC022)
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
- [x] Detect `actions/checkout` with `persist-credentials: true` (the default)
      under a privileged trigger (WF009). Scoping it to `pull_request_target`
      and `workflow_run` is what keeps it from being ignored everywhere else
- [ ] Warn on `contents: write` without an obvious need — needs a notion of
      "obvious need" that does not just move the noise somewhere else
- [ ] Reusable workflow calls (`uses:` at job level) pinned to a mutable ref
- [x] `GITHUB_TOKEN` or a secret written into an output, where it survives into
      the calling workflow's logs (WF010)

## Beyond GitHub Actions

- [x] GitLab CI: script injection from outsider-supplied variables, floating
      job images, pipe-to-shell, and CI_DEBUG_TRACE
- [ ] CircleCI and Jenkinsfiles, the two remaining CI systems people actually
      have. A Jenkinsfile is Groovy, which this tool has no business parsing;
      the honest scope there is its shell steps and nothing else

- [x] Dockerfile checks: running as root, `curl | sh`, unpinned base images,
      secrets in `ARG`/`ENV`, `ADD` from a URL, disabled TLS verification
- [x] Terraform checks: public S3 buckets, `0.0.0.0/0` security group ingress,
      unencrypted storage, wildcard policies, public databases, plain state
- [x] Kubernetes manifests: privileged containers, hostPath mounts, missing
      resource limits, host namespaces, capabilities, and secrets in manifests
- [x] `docker-compose.yml` beyond secrets: privileged services, host network,
      Docker socket mounts, and ports published on every interface

## Output and integration

- [x] SARIF output so findings appear in the GitHub Security tab, with stable
      partial fingerprints so code scanning tracks a finding across edits
- [x] Pre-commit hook definition
- [x] GitHub Action wrapper in this repository
- [x] `repo-sentinel rules` to print the catalogue, in text or JSON
- [x] ~~`--diff` mode~~ — shipped as `--paths-from`, which reads the file list
      from stdin or a file rather than shelling out to git. `git diff
      --name-only origin/main | repo-sentinel scan . --paths-from -` is the
      same feature without the dependency on git's CLI being where we think
- [x] A project config file (`.repo-sentinel.json`) for defaults, with
      per-rule and per-family disabling
- [x] Rule-scoped suppression markers, so an exemption stays as narrow as the
      reason for it and does not silently cover rules added later
- [x] Per-path rule configuration: "K8S004 is fine in examples/, not in
      deploy/". A `paths` table of glob to disabled rules, and nothing else --
      the shape stops short of a policy language on purpose
- [x] Markdown output for a pull request comment
- [x] `repo-sentinel init`, for the first five minutes with the tool
- [ ] Publish to PyPI so `pipx run repo-sentinel` works. The release workflow
      is written and waits on one thing only: registering this repository as a
      trusted publisher in the PyPI project settings, which needs an account
      rather than a commit
- [x] `--quiet` for CI logs that only need the summary line, and `--sort path`
      for reading a report top to bottom
- [x] ~~Group findings by file in text output~~ — `--sort path` answers the same
      need without a second output shape to maintain, and keeps every line in
      the clickable `path:line` form

## Engineering health

- [x] A corpus that trips every rule, asserted in both directions against the
      catalogue, so a new rule cannot ship undocumented and a deleted one
      cannot leave its entry behind
- [x] CONTRIBUTING.md
- [x] README tables asserted against the rule catalogue, so documentation
      cannot fall behind the rules
- [x] Findings about a file's name rather than its contents, so binary key
      material stops being invisible (FN001-FN003)
- [ ] Multi-line PEM bodies: a private key is caught by its header line, so a
      body pasted without one is missed
- [x] Helm templates, where `{{ .Values.x }}` makes every structural rule guess.
      Solved by splitting the Kubernetes rules into those that read a value the
      chart contains, which run, and those that reason from a value's absence,
      which cannot and do not
- [x] Coverage measurement in CI with a floor, measured by a standard
      library tool so the suite needs nothing installed either
- [x] Property-based tests for the entropy and redaction functions, plus seeded
      fuzzing of both hand-written parsers and a time bound on hostile input
- [x] ~~Benchmark against a large repository~~ — measured and acted on. The
      Python 3.14 standard library went from 5.1s to 1.5s and Prometheus (39 MB,
      1,679 files) from not finishing in five minutes to 5.8s, via a quadratic
      YAML parse and a cheap gate in front of the provider patterns. The suite
      has scaling guards for both. Still short of "10k files in a second", and
      the remaining cost is one regex per line, which is where a pure-Python
      scanner ends up
- [ ] Type annotations checked with mypy in CI
- [ ] Issue templates
- [ ] Enable CodeQL default setup and branch protection on `main`
