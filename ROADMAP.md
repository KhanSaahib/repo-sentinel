# Roadmap

The backlog for repo-sentinel, roughly in priority order. Work moves top-down.
Tick an item when it lands on `main` with tests and a green CI run.

Anything here can be reordered, rewritten, or dropped if it turns out to be a
bad idea. A crossed-out item with a note explaining why it was wrong is a
better outcome than a feature nobody wanted.

## Detection quality

- [x] Allowlist documented public example credentials so the scanner stops
      flagging documentation
- [x] Respect `.gitignore` when walking a repository, nested files included,
      with `--no-gitignore` to audit what was hidden
- [x] File-level, block-level and rule-scoped suppression, each counted in the
      summary so silence is never free
- [x] Baseline file with fingerprints that omit line numbers, plus
      `--prune-baseline` for entries that match nothing
- [x] ~~Track the entropy floor separately per rule~~ — per *rule* was the wrong
      axis. The threshold depends on the value's own alphabet and length, which
      is what `heuristics.entropy_floor` measures
- [x] Secrets in value positions (`.env`, `.npmrc`, `.pypirc`, Compose), where
      there is no quoted assignment to match
- [x] Confidence as an axis of its own, weighed by where the file sits, with
      `--min-confidence` to gate on it
- [x] GCP service account JSON as a whole document (SEC021), and credentials
      hidden inside base64 (SEC022)
- [ ] Multi-line detection generally: the scanner is line-by-line, so a PEM body
      or a wrapped JSON credential is only caught by its first line
- [ ] Report the *shape* of a near miss: a value that failed the entropy floor
      by a hair next to a credential-shaped name is worth a low-confidence
      finding, and today it is silent
- [ ] Verify a candidate is not already public (git history vs. working tree),
      and report the first-seen commit
- [ ] ~~Optional live validation (`--verify`)~~ — off by default and probably
      always: it turns a static scan into an outbound request carrying the
      credential it is unsure about

## Workflow and CI analysis

- [x] Per-job `permissions:` analysis, `write-all`, secrets passed to a
      third-party action, `workflow_run` checking out the triggering head,
      self-hosted runners, and a token that outlives its step
- [x] GitLab, Azure Pipelines, CircleCI and Jenkins, each with its own
      injection vocabulary and its own quoting rules
- [ ] Reusable workflow calls (`uses:` at job level) pinned to a mutable ref
- [ ] Warn on `contents: write` without an obvious need — needs a notion of
      "obvious need" that does not just move the noise somewhere else
- [ ] Composite actions in the repository itself (`action.yml`), which are
      workflows in all but trigger

## Beyond GitHub Actions

- [x] Dockerfiles, Compose, Terraform, CloudFormation, Kubernetes, Ansible,
      dependency manifests, shell scripts and Makefiles
- [ ] Helm `values.yaml` read against its chart's templates, so a value that
      lands in a `securityContext` is judged as one
- [ ] Kustomize overlays, where the patch and the base disagree
- [ ] systemd units and cron files: the other two places a repository decides
      what runs as root

## Output and integration

- [x] SARIF with stable partial fingerprints, CWE tags and help URLs
- [x] Pre-commit hook, GitHub Action wrapper, `rules` command, `init` command
- [x] `--paths-from FILE` for per-PR runs, `--format markdown` for a PR comment,
      `--format github` for annotations
- [x] `--quiet`, `--sort`, `--disable`, per-path configuration
- [ ] `--explain RULE`: the catalogue entry, the reasoning, the remediation and
      the CWE in one place, so a reviewer does not have to open the docs
- [ ] Group findings by file in text output when there are many
- [ ] Publish to PyPI so `pipx run repo-sentinel` works — the release workflow
      is written and uses trusted publishing; it needs the project registered

## Engineering health

- [x] A corpus that trips every rule, asserted four ways against the catalogue,
      the scanners, the docs and the severity ceiling
- [x] Coverage measurement in CI with a floor, using the standard library
- [x] Property-based and seeded-fuzz tests over all three readers, with time
      bounds and scaling guards for the shapes that were quadratic
- [x] Type annotations checked with mypy in CI
- [x] Issue templates, CONTRIBUTING.md, SECURITY.md
- [x] Benchmark against large repositories: the Python standard library went
      5.1s → 1.3s, Prometheus a five-minute timeout → 3.7s
- [ ] A fixed corpus of real repositories pinned by commit, so a heuristic
      change can be measured rather than argued about
- [ ] Enable CodeQL default setup and branch protection on `main`
