# repo-sentinel

A small command line auditor that reads a repository the way a security
reviewer skims it: looking for credentials that should never have been
committed, and for build configuration that hands the keys to whoever opens a
pull request.

**No runtime dependencies.** Standard library only, on Python 3.9 and up. A tool
you run against your supply chain should not enlarge it.

## Install

```bash
git clone https://github.com/KhanSaahib/repo-sentinel.git
cd repo-sentinel
pip install .
```

Or run it straight from a checkout, with no install at all:

```bash
PYTHONPATH=src python -m repo_sentinel scan .
```

## Use

```bash
repo-sentinel scan .                          # scan the working directory
repo-sentinel scan ../other-project           # scan somewhere else
repo-sentinel rules                           # what does this thing check for?

repo-sentinel scan . --format json            # machine-readable output
repo-sentinel scan . --format sarif --output results.sarif
repo-sentinel scan . --min-severity high      # only show what matters most
repo-sentinel scan . --min-confidence high    # only show what it is sure of
repo-sentinel scan . --fail-on critical       # relax the CI gate
repo-sentinel scan . --exclude 'fixtures'     # skip a directory (repeatable)
repo-sentinel scan . --no-gitignore           # also scan git-ignored files
repo-sentinel scan . --no-example-allowlist   # include documented example keys

repo-sentinel scan . --write-baseline         # accept what is already there
repo-sentinel scan . --baseline               # fail only on what is new
```

Exit codes: `0` clean, `1` findings at or above `--fail-on` (default `medium`),
`2` usage error, unreadable baseline, or unwritable output. That makes it a
one-line CI gate:

```yaml
- run: pipx run repo-sentinel scan . --fail-on high
```

Sample output:

```
CRITICAL SEC001  terraform/main.tf:14
    AWS access key id
    evidence: AKIA************LM3D
    fix: Deactivate the key in IAM, then rotate it. Deleting the commit is not enough.

HIGH SEC101  .env.staging:7  (medium confidence)
    High-entropy value position assigned to 'DATABASE_PASSWORD'
    evidence: Tv8n************Lz4T
    fix: Move the value to an environment variable or secret store.

MEDIUM WF001  .github/workflows/release.yml:22
    Action 'actions/checkout@v4' is pinned to a mutable tag
    evidence: - uses: actions/checkout@v4
    fix: Tags can be moved to point at new code. Pin to a full commit SHA and let Dependabot propose upgrades.

3 finding(s): 1 critical, 1 high, 1 medium
Scanned 412 file(s) in 0.31s.
```

That last line is not decoration. A run that scanned nothing looks exactly like
a clean repository, and "no findings" from a mistyped path is the most
dangerous answer this tool can give.

## Severity and confidence

Every finding carries both, because they answer different questions and
collapsing them into one number loses both.

**Severity** is what it costs you if the finding is real: a live AWS key is
critical whether the rule was certain or guessing. **Confidence** is how sure
the rule is that it found a real instance. A documented token shape — a GitHub
PAT, a Stripe live key — is high confidence; a high-entropy string next to a
variable named `api_key` is a heuristic, and says so.

The split is what makes the tool tunable without making it useless. A pipeline
that wants a hard gate can run `--fail-on high --min-confidence high` and be
woken only for things the scanner can defend, while a human audit runs with
neither flag and reads everything.

## What gets scanned

The walk skips binaries, files over 2 MB, and a built-in list of generated or
vendored directories (`.git`, `node_modules`, `.venv`, `dist`, `target`, …).

It also honours `.gitignore`, including nested ones, which each govern their own
subtree. The rules implemented are negation with `!`, anchoring with a leading or
embedded `/`, directory-only patterns ending in `/`, the `*`, `?` and `[...]`
wildcards, and `**` for arbitrary depth; across the ignore files in scope, the
last matching pattern wins. Not implemented: `.git/info/exclude`, the global
`core.excludesFile`, and git's rule that an already-tracked file stays tracked
however it is ignored — all three would mean shelling out to git.

This is a deliberate narrowing of scope, and it cuts both ways. A secret in an
ignored file was never committed, so reporting it is a false positive, and the
noise from a local `.env` is what makes people stop reading the output. But an
ignore rule is also the easiest way to hide something from this tool, whether by
accident or on purpose. Audit what the scanner was told not to look at:

```bash
repo-sentinel scan . --no-gitignore
```

## What it checks

`repo-sentinel rules` prints the whole catalogue, with `--format json` if you
want to diff it between releases. The tables below are the same list, annotated.

### Secrets

| Rule | Finds | Severity | Confidence |
| --- | --- | --- | --- |
| SEC001 | AWS access key id | critical | high |
| SEC002 | GitHub personal access token | critical | high |
| SEC003 | GitHub fine-grained token | critical | high |
| SEC004 | Private key block | critical | high |
| SEC005 | Stripe live secret key | critical | high |
| SEC006 | Slack token | high | high |
| SEC007 | Google API key | high | high |
| SEC008 | OpenAI-style API key | high | high |
| SEC009 | JSON Web Token | medium | high |
| SEC010 | Stripe test key | low | high |
| SEC011 | Azure storage account key | critical | high |
| SEC012 | Google OAuth client secret | critical | high |
| SEC013 | SendGrid API key | critical | high |
| SEC014 | Twilio API key SID | high | medium |
| SEC015 | npm access token | critical | high |
| SEC016 | PyPI upload token | critical | high |
| SEC017 | Docker Hub access token | critical | high |
| SEC018 | Slack incoming webhook URL | high | high |
| SEC019 | Hugging Face access token | high | high |
| SEC020 | Credentials embedded in a URL | high | medium |
| SEC100 | High-entropy value in a quoted assignment | high | medium |
| SEC101 | High-entropy value in an unquoted config value | high | medium |
| SEC900 | Suppression block opened and never closed | medium | high |

SEC900 is not a class of secret; it reports a suppression block that was opened
and never closed. See [Suppressing a false positive](#suppressing-a-false-positive).

SEC001–SEC020 match on documented token structure. Two of them are looser than
the rest and say so through their confidence: SEC014 is a two-letter prefix in
front of 32 hex characters, and SEC020 is any `scheme://user:password@host`.

#### The entropy rules

SEC100 and SEC101 are the heuristics. They fire when a name that promises a
credential (`password`, `api_key`, `client_secret`, …) is assigned a value that
looks generated rather than written. SEC100 reads quoted assignments in source
code; SEC101 reads the formats that write credentials bare — `.env`, `.npmrc`,
`.pypirc`, INI files, YAML — where there is no quoting to key on, and where the
file's own syntax has to stand in for it.

One consequence worth knowing: a real `.env` is usually git-ignored, so SEC101
will not see it unless you pass `--no-gitignore`. Where it earns its keep by
default is the committed cousins — `.env.example` with a real value left in it,
a `docker-compose.yml` with a database password inline, an `.npmrc` carrying a
publish token.

"Looks generated" is a moving bar rather than a fixed one, because the maximum
entropy a string can carry depends on its alphabet and its length. A 12-character
hex token tops out at 3.58 bits per character and a 200-character base64 blob at
6, so a single global threshold is simultaneously too strict for the first and
too lax for the second. What generalises is the ratio: a generated credential
lands near the ceiling of what its alphabet and length allow, and a hand-written
value does not. The floor is 75% of that ceiling.

Placeholders are filtered before entropy is measured at all — `your-password-here`,
`${DB_PASSWORD}`, `xxxxxxxx`, `changeme` — and so is structure that is not a
credential: paths, URLs without a password in them, version constraints, dotted
identifiers, timestamps.

Every reported value is redacted to its first and last four characters. Findings
end up in CI logs and issue threads, so the scanner must never be the thing that
leaks the credential it just found.

#### Documented example credentials

A README that quotes an AWS tutorial contains a string shaped exactly like a
live access key id, and structure alone cannot tell the two apart. Rather than
make every project bury its documentation under ignore markers, the scanner
stays quiet about credentials that are public by design:

| Mechanism | Example |
| --- | --- |
| Values published verbatim by a vendor or RFC | `AKIAIOSFODNN7EXAMPLE`, the AWS docs secret key, the jwt.io default token |
| AWS's reserved `EXAMPLE` suffix | any `AKIA…EXAMPLE` / `ASIA…EXAMPLE` identifier, any 40-character `…EXAMPLEKEY` secret |
| RFC 2606 reserved domains in JWT claims | the RFC 7519 sample tokens, which issue against `http://example.com/is_root` |

Only the third mechanism inspects content: a JWT's header and payload are
base64url-decoded (never signature-verified) and checked for `example.com` and
its siblings, which exist so documentation can name a host that cannot resolve.
A token that fails to decode is reported, not allowlisted.

Pass `--no-example-allowlist` to see these findings anyway — useful when
auditing what the scanner chose not to tell you.

### GitHub Actions workflows

| Rule | Finds | Severity |
| --- | --- | --- |
| WF001 | Action pinned to a mutable tag, or not pinned at all | medium |
| WF002 | Job inherits the default `GITHUB_TOKEN` permissions | medium |
| WF003 | Attacker-controlled context interpolated into a `run:` block | critical |
| WF004 | `pull_request_target` checking out untrusted code | critical |
| WF005 | `GITHUB_TOKEN` granted `write-all` | high |
| WF006 | Job runs on a self-hosted runner | medium |
| WF007 | Secret passed as an input to a third-party action | medium |
| WF008 | `workflow_run` checking out untrusted code | critical |

WF003 is the script-injection class: `${{ github.event.issue.title }}` inside a
`run:` step is substituted into the shell command *before* the shell runs, so an
issue title containing `$(...)` executes on the runner. The fix is always to
route the value through an `env:` block and reference it as `"$VAR"`.

WF004 and WF008 are the same mistake through two doors. Both `pull_request_target`
and `workflow_run` run from the base branch with the repository's secrets
available; checking out the head commit that triggered them puts a fork's code
inside that trust boundary.

WF002 is asked per job rather than per file. A job that declares its own
`permissions:` block is already explicit, and warning about it because the file
has no top-level block is the kind of finding that teaches people to skip the
output. WF007 is asked per step, and only for actions outside the `actions/` and
`github/` namespaces: an action can read every input it is given, so handing one
a secret extends that secret's blast radius to that action's supply chain. It is
often necessary and often fine — hence medium — but it should be a decision.

Workflow checks are pattern-based rather than YAML-aware, a deliberate
consequence of the zero-dependency rule. What the scanner does parse is
structure: jobs and steps are split apart by indentation, because "does this job
declare permissions" and "is this secret handed to a third party" are questions
about a block, not about a line. Unusual formatting can still slip past, so treat
a clean report as encouraging, not as proof.

### Dockerfiles

| Rule | Finds | Severity |
| --- | --- | --- |
| DK001 | Base image not pinned to a digest | medium (low for a specific tag) |
| DK002 | Final image runs as root | medium |
| DK003 | Build step pipes a download into a shell | high |
| DK004 | Credential baked into an image layer | high |
| DK005 | `ADD` fetches a remote URL without verification | medium |
| DK006 | Build step disables transport security | medium |

Two details matter more than the list. Backslash continuations are joined before
the rules run, so a `RUN` command split over eight lines is judged as the one
command it is. And build stages are tracked, so DK002 is only asked of the stage
that actually becomes the image — demanding an unprivileged user in a throwaway
compiler stage is how a whole tool gets switched off.

DK004 is worth stating plainly: every `ENV` and `ARG` value survives in the image
metadata, so `docker history` reads them back out of any published image, and
deleting the value in a later layer does not remove it from the earlier one.

## Baselines

A scanner introduced to a repository that has been running for years reports its
entire history at once, and a build that has been red since Tuesday tells nobody
anything. Record what is already there, then fail only on what arrives after:

```bash
repo-sentinel scan . --write-baseline      # writes .repo-sentinel-baseline.json
git add .repo-sentinel-baseline.json
repo-sentinel scan . --baseline            # exits 0; new findings still fail
```

Two properties make the file safe to commit. It never contains a secret —
entries hold a hash of the already-redacted evidence, along with the rule and
the path, so there is nothing to recover. And it does not pin line numbers, so
reformatting a file does not resurrect its accepted findings, while moving a
secret to another file does not keep it accepted.

Every run reports how many findings the baseline is holding, and every entry
that matched nothing this time is reported as stale — usually because the
finding was genuinely fixed. That is how a baseline shrinks instead of
calcifying. It is a list of debts, not a list of exemptions.

An unreadable or corrupt baseline is an error, not an empty baseline. Failing
open would mean a truncated file silently accepts everything.

## Reporting to the GitHub Security tab

`--format sarif` emits SARIF 2.1.0, which GitHub's code scanning ingests and
turns into annotations on the pull request that introduced the line:

```yaml
- run: repo-sentinel scan . --format sarif --output repo-sentinel.sarif
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@<sha>
  with:
    sarif_file: repo-sentinel.sarif
```

The job needs `security-events: write`, and `continue-on-error` on the scan step
so that a finding does not stop the run before it has published anything — put
the actual gate in a separate job. This repository's own
[CI](.github/workflows/ci.yml) does exactly that.

Each result carries a `partialFingerprint`, so code scanning follows a finding
across the reformattings and line moves that would otherwise close it and
immediately reopen it as new.

## Suppressing a false positive

Three scopes, in increasing blast radius. All three work in any file the scanner
reads, workflows and Dockerfiles included, and none of them cares what the
comment syntax is.

One line:

```python
sample_token = "Xk92mQp7Lz4TvB8nRw1Y"  # repo-sentinel: ignore
```

A block, for a generated section or a fixture full of invented keys. Both
markers are themselves suppressed, along with everything between them:

```python
# repo-sentinel: ignore-start
FAKE_KEYS = {"aws": "...", "stripe": "..."}
# repo-sentinel: ignore-end
```

A whole file, with `repo-sentinel: ignore-file` — but **only in the first 20
lines**. Below that it is just a mention, which is why this README still gets
scanned despite the line you are reading. Without that rule, any file that
described the directive would silently stop being scanned, and a scanner a
sentence about it can switch off is worse than no scanner. Keeping the directive
in the header also means you can see that a file is unscanned without reading to
the bottom of it.

A block that is opened and never closed silences everything after it, so it is
reported as SEC900 rather than trusted. Close the block, or say `ignore-file` and
mean it.

Reach for a baseline instead when the finding is real but not yet fixed. A
suppression marker says "this is not a problem"; a baseline says "this is a
problem I have not got to". Recording the second as the first is how a repository
forgets.

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

CI runs the suite on Python 3.9, 3.11 and 3.13, scans this repository with the
tool itself, and publishes the result to the Security tab.

The test suite includes a corpus that trips **every** rule in the catalogue, and
asserts in both directions: no scanner may emit a rule the catalogue does not
describe, and no catalogue entry may describe a rule nothing can emit. Adding a
rule without documenting it fails the build, and so does leaving an entry behind
after deleting one.

See [CONTRIBUTING.md](CONTRIBUTING.md) for how a new rule earns its place.

## Security

See [SECURITY.md](SECURITY.md). If you find a vulnerability, please report it
privately rather than opening a public issue.

## License

MIT. See [LICENSE](LICENSE).
