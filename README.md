# repo-sentinel

A small command line auditor that reads a repository the way a security
reviewer skims it: looking for credentials that should never have been
committed, and for the configuration that quietly hands out more access than
anyone intended -- a workflow an outside contributor can hijack, a container
that runs as root, a security group open to the internet, a Compose service
that publishes your database on every interface.

**No runtime dependencies.** Standard library only, on Python 3.9 and up. A tool
you run against your supply chain should not enlarge it.

## Install

```bash
git clone https://github.com/KhanSaahib/repo-sentinel.git
cd repo-sentinel
pip install .
```

Or from a tag, without a checkout:

```bash
pip install git+https://github.com/KhanSaahib/repo-sentinel@v0.3.0
```

Or run it straight from a checkout, with no install at all:

```bash
PYTHONPATH=src python -m repo_sentinel scan .
```

## Use

Start here:

```bash
repo-sentinel init .
```

That scans the repository, tells you what is in it, records the findings at or
above `high` as a baseline so your first pipeline run is green, writes a
`.repo-sentinel.json`, and prints the CI snippet for whichever CI system the
repository already has. Nothing is overwritten without `--force`.

Then, day to day:

```bash
repo-sentinel scan .                          # scan the working directory
repo-sentinel scan ../other-project           # scan somewhere else
repo-sentinel rules                           # what does this thing check for?
repo-sentinel init .                          # set a repository up

repo-sentinel scan . --format json            # machine-readable output
repo-sentinel scan . --format sarif --output results.sarif
repo-sentinel scan . --format markdown         # a pull request comment
repo-sentinel scan . --min-severity high      # only show what matters most
repo-sentinel scan . --min-confidence high    # only show what it is sure of
repo-sentinel scan . --fail-on critical       # relax the CI gate
repo-sentinel scan . --exclude 'fixtures'     # skip a directory (repeatable)
repo-sentinel scan . --no-gitignore           # also scan git-ignored files
repo-sentinel scan . --no-example-allowlist   # include documented example keys

repo-sentinel scan . --write-baseline         # accept what is already there
repo-sentinel scan . --baseline               # fail only on what is new

repo-sentinel scan . --disable K8S004         # switch off a rule or family
repo-sentinel scan . --quiet                  # just the summary line
repo-sentinel scan . --sort path              # read a report, rather than triage it
git diff --name-only origin/main | repo-sentinel scan . --paths-from -
```

That last line is the fast per-pull-request run: the scan is restricted to the
files the branch touched. A listed path that no longer exists is skipped, since
a diff lists deletions too, and a listed path that `.gitignore` covers is
scanned anyway -- you named it.

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

Seventy-one rules across eight families. [docs/RULES.md](docs/RULES.md) is the
full list, with a paragraph on each family explaining what it is looking for
and why; `repo-sentinel rules` prints the same catalogue from the tool.

| Family | Rules | Looks at |
| --- | --- | --- |
| [Secrets](docs/RULES.md#secrets) | SEC001–SEC022, SEC100–SEC101 | Credentials in any text file, including inside base64 |
| [File names](docs/RULES.md#file-names) | FN001–FN003 | Key material and credential files, which have no text to read |
| [GitHub Actions](docs/RULES.md#github-actions-workflows) | WF001–WF010 | Script injection, token scope, privileged triggers |
| [GitLab CI](docs/RULES.md#gitlab-ci) | GL001–GL004 | The same injection class, and debug tracing |
| [Dockerfiles](docs/RULES.md#dockerfiles) | DK001–DK006 | Base images, root, pipe-to-shell, layer secrets |
| [Docker Compose](docs/RULES.md#docker-compose) | DC001–DC006 | Privilege, host mounts, ports on every interface |
| [Terraform](docs/RULES.md#terraform) | TF001–TF007 | Open ingress, public storage, wildcard policies |
| [Kubernetes](docs/RULES.md#kubernetes) | K8S001–K8S010 | Container escape routes, secrets in manifests |

Three things are worth knowing before you read the list.

**Structure, not lines.** The workflow, Terraform, Kubernetes, Compose and
GitLab rules read block structure, through two small standard-library readers.
It is the difference between `privileged: true` under `securityContext`, which
is critical, and the same line under `annotations`, which is nothing.

**Recognition by content.** Kubernetes manifests are found by `apiVersion` plus
`kind`, Compose files by their `services` map, GitLab pipelines by name or by
shape. Not by directory: a workflow file that happens to live in `k8s/` is not
a workload.

**Honest edges.** None of this evaluates Terraform, renders a chart, or runs a
pipeline. A value arriving through a variable is invisible, and the rules say
so rather than implying coverage they do not have.

## Project defaults

Every project that adopts a scanner ends up with a preferred invocation. Putting
it in a `Makefile` means the pre-commit hook, the pipeline and whoever runs the
tool by hand all disagree. Put it in `.repo-sentinel.json` beside the tree
instead:

```json
{
  "fail_on": "high",
  "min_confidence": "medium",
  "exclude": ["vendor", "testdata"],
  "disable": ["K8S004", "DC006"]
}
```

The settings are `exclude`, `fail_on`, `min_severity`, `min_confidence`,
`baseline`, `sort`, `disable`, `gitignore` and `example_allowlist`. An unknown
key is an error rather than a shrug: a typo in a security tool's configuration
means a project believes it configured something it did not.

Everything here is a *default*. Anything on the command line wins, so a config
file can never stop someone auditing their own repository more strictly than the
project usually does.

Rules can also be switched off for one subtree rather than everywhere, which is
usually what is actually wanted -- a vendored chart, an examples directory, a
fixtures tree:

```json
{
  "paths": {
    "examples/**": { "disable": ["K8S*"] },
    "charts/vendor/**": { "disable": ["*"] }
  }
}
```

The globs are the `.gitignore` dialect, matched by the same code, so
`examples/`, `charts/vendor/**` and `*.tf` mean here exactly what they mean
there. Inventing a second glob dialect for one config key is how a tool ends up
with two subtly different answers to "does this path match".

`disable` takes rule ids or family prefixes (`DC*`), and `--disable` does the
same ad hoc. A disabled rule is still counted in the output -- *"3 finding(s)
hidden by disabled rules"* -- because silence nobody can see is the failure mode
this whole tool exists to avoid. An id that matches no rule is called out too:
that typo leaves the rule switched on, which is the safe direction but not the
one you meant.

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

## Posting the result onto a pull request

`--format markdown` writes a table meant to be pasted into a comment, where the
people arguing about the change are already looking:

```yaml
- id: scan
  run: repo-sentinel scan . --format markdown --output report.md
  continue-on-error: true
- uses: actions/github-script@<sha>
  with:
    script: |
      const body = require("fs").readFileSync("report.md", "utf8");
      github.rest.issues.createComment({ ...context.repo, issue_number: context.issue.number, body });
```

The table carries what triage needs -- how bad, which rule, where -- and the
fixes go underneath in a collapsed block, once per rule rather than once per
finding. Long reports are truncated with a count: a comment that needs scrolling
past four hundred rows is one nobody reads.

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

All three can name the rules they mean, in brackets:

```yaml
image: nginx:latest  # repo-sentinel: ignore[K8S008]
```

Prefer this to the blunt form. A line exempted from everything stays exempt when
a later release adds a rule that would have caught something real there, and the
comment no longer records why the exemption exists. Family prefixes work too
(`ignore[K8S*]`), and so do lists (`ignore[SEC100, DK002]`); the syntax is the
same one `disable` uses in the config file.

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

CI runs the suite on Python 3.9, 3.11 and 3.13, holds a line-coverage floor,
scans this repository with the tool itself, and publishes the result to the
Security tab.

```bash
python3 tools/coverage.py --show-missing
```

The coverage tool is standard library only, like everything else here. Writing
one is a strange thing to do when a good one exists; the reason is that the
promise "this pulls nothing into your environment" should hold for the tests
too, so a contributor with no network can still check the floor.

The test suite includes a corpus that trips **every** rule in the catalogue, and
asserts in three directions: no scanner may emit a rule the catalogue does not
describe, no catalogue entry may describe a rule nothing can emit, and no rule
may be missing from [docs/RULES.md](docs/RULES.md). Adding a rule without
documenting it fails the build, and so does leaving an entry behind after
deleting one.

See [CONTRIBUTING.md](CONTRIBUTING.md) for how a new rule earns its place.

## Security

See [SECURITY.md](SECURITY.md). If you find a vulnerability, please report it
privately rather than opening a public issue.

## License

MIT. See [LICENSE](LICENSE).
