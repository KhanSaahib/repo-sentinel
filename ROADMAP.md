# Roadmap

The backlog for bluerayscan, roughly in priority order. Work moves top-down.
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
- [x] Multi-line detection, in the one shape that was actually costing
      findings: a value written on the lines beneath its name, which is how
      YAML carries anything long. A PEM body is still read from its header
      line, which is the line that identifies it
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
- [x] ~~Reusable workflow calls (`uses:` at job level) pinned to a mutable
      ref~~ -- already covered: WF001 reads any `uses:`, with or without the
      list dash. WF011 is the part that was actually missing, and it is about
      the secrets, not the ref
- [x] Warn on `contents: write` without an obvious need (WF013). The notion of
      "obvious need" turned out to be: anything that could be writing counts,
      including a local composite action and a reusable workflow, because the
      reader cannot see inside either. One finding across twenty-one
      repositories, and it is real
- [x] Composite actions in the repository itself (`action.yml`), which are
      workflows in all but trigger. WF012 is the rule that only makes sense
      there: an action cannot tell a safe input from a dangerous one

## Beyond GitHub Actions

- [x] Dockerfiles, Compose, Terraform, CloudFormation, Kubernetes, Ansible,
      dependency manifests, shell scripts and Makefiles
- [x] Helm `values.yaml` -- read where a `Chart.yaml` sits beside it, for the
      settings that carry their meaning wherever they are written. Reading it
      *against the templates* is still open, and would answer the question
      this cannot: whether the chart passes the value through at all
- [x] Kustomize overlays: the manifests a kustomization patches in are read,
      with the line numbers shifted so a finding points at the patched line
- [x] ~~systemd units and cron files as a family~~ -- they did not need one.
      A unit is an INI file and a crontab is assignments, so both became
      value-position formats for the rules that already read those
- [x] More application-code idioms, measured against nineteen repositories:
      AP004 (unsafe deserialisation), AP005 (a password through a fast digest)
      and AP006 (a shell command built by interpolation). The family is seven
      rules and reads five languages
- [x] A seventh: AP007, a JWT accepted with the "none" algorithm. It has
      exactly one meaning in each of the three languages it is read in, which
      is the bar -- an idiom with one meaning, read only where it has that
      meaning, which is what keeps this family seven rules rather than thirty.
      Fires no times across the twenty-one pinned repositories, which is the
      expected result
- [ ] An eighth, on the same terms. Candidates that have not cleared the bar:
      hardcoded JWT signing secrets, DEBUG in frameworks other than Django and
      Flask, weak TLS versions, permissive CORS (`*` is only a problem with
      credentials, which the line does not say), and PyJWT's unverified decode
      with no second decode after it -- measured at twenty-one findings across
      the pinned repositories, every sampled one of them the honest two-step,
      so telling them apart needs to see the decode that follows

## Output and integration

- [x] SARIF with stable partial fingerprints, CWE tags and help URLs
- [x] JUnit XML, which GitLab, Azure and Jenkins render without a plugin
- [x] Pre-commit hook, GitHub Action wrapper, `rules` command, `init` command
- [x] `--paths-from FILE` for per-PR runs, `--format markdown` for a PR comment,
      `--format github` for annotations
- [x] `--quiet`, `--sort`, `--disable`, per-path configuration
- [x] `--fail-on none`, so a reporting job need not borrow its CI's word for
      "do not stop here"
- [x] Every skip counted and named: unreadable paths, files over the size
      limit, suppression markers -- in the sentence, in the JSON, and in the
      SARIF invocation
- [x] ~~`--explain RULE`~~ -- a flag was the wrong shape. `rules WF011` already
      names one rule; it now prints the card instead of the row, which is what
      the flag would have done and one fewer thing to know
- [x] Group findings by file in text output, under `--sort path`
- [x] Publish to PyPI so `pipx run bluerayscan` works, using trusted
      publishing with no long-lived upload token

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
- [x] A fixed corpus of real repositories pinned by commit, so a heuristic
      change can be measured rather than argued about (`tools/corpus.json`,
      `measure.py --fetch/--save/--compare`)
- [ ] Enable CodeQL default setup and branch protection on `main`
