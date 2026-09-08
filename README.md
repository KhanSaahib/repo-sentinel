# repo-sentinel

A small command line auditor that reads a repository the way a security reviewer
skims it: looking for credentials that should never have been committed, and CI
configuration that hands the keys to whoever opens a pull request.

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
repo-sentinel scan . --format json            # machine-readable output
repo-sentinel scan . --min-severity high      # only show what matters most
repo-sentinel scan . --fail-on critical       # relax the CI gate
repo-sentinel scan . --exclude 'fixtures'     # skip a directory (repeatable)
```

Exit codes: `0` clean, `1` findings at or above `--fail-on` (default `medium`),
`2` usage error. That makes it a one-line CI gate:

```yaml
- run: pipx run repo-sentinel scan . --fail-on high
```

Sample output:

```
CRITICAL SEC001  terraform/main.tf:14
    AWS access key id
    evidence: AKIA************MPLE
    fix: Deactivate the key in IAM, then rotate it. Deleting the commit is not enough.

MEDIUM WF001  .github/workflows/release.yml:22
    Action 'actions/checkout@v4' is pinned to a mutable tag
    evidence: - uses: actions/checkout@v4
    fix: Tags can be moved to point at new code. Pin to a full commit SHA and let Dependabot propose upgrades.

2 finding(s): 1 critical, 1 medium
```

## What it checks

### Secrets

| Rule | Finds | Severity |
| --- | --- | --- |
| SEC001 | AWS access key id | critical |
| SEC002 | GitHub personal access token | critical |
| SEC003 | GitHub fine-grained token | critical |
| SEC004 | Private key block | critical |
| SEC005 | Stripe live secret key | critical |
| SEC006 | Slack token | high |
| SEC007 | Google API key | high |
| SEC008 | OpenAI-style API key | high |
| SEC009 | JSON Web Token | medium |
| SEC010 | Stripe test key | low |
| SEC100 | High-entropy value assigned to a secret-shaped variable name | high |

SEC001–SEC010 match on documented token structure, so they are high confidence.
SEC100 is the heuristic one: it fires only when a variable named like a
credential (`password`, `api_key`, `client_secret`, …) is assigned a quoted
string of at least 12 characters that clears a Shannon-entropy floor of 3.2 and
does not look like a placeholder. `your-password-here`, `${DB_PASSWORD}`,
`xxxxxxxx` and friends are filtered out.

Every reported value is redacted to its first and last four characters. Findings
end up in CI logs and issue threads, so the scanner must never be the thing that
leaks the credential it just found.

### GitHub Actions workflows

| Rule | Finds | Severity |
| --- | --- | --- |
| WF001 | Action pinned to a mutable tag, or not pinned at all | medium |
| WF002 | No top-level `permissions:` block | medium |
| WF003 | Attacker-controlled context interpolated into a `run:` block | critical |
| WF004 | `pull_request_target` checking out untrusted code | critical |

WF003 is the script-injection class: `${{ github.event.issue.title }}` inside a
`run:` step is substituted into the shell command *before* the shell runs, so an
issue title containing `$(...)` executes on the runner. The fix is always to
route the value through an `env:` block and reference it as `"$VAR"`.

WF004 catches the pattern where `pull_request_target` — which runs with full
repository secrets — is combined with a checkout of the pull request head,
letting a fork run its own code with those secrets.

Workflow checks are pattern-based rather than YAML-aware, a deliberate
consequence of the zero-dependency rule. Unusual formatting can slip past, so
treat a clean report as encouraging, not as proof.

## Suppressing a false positive

Put the marker on the offending line:

```python
sample_token = "Xk92mQp7Lz4TvB8nRw1Y"  # repo-sentinel: ignore
```

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

CI runs the suite on Python 3.9, 3.11 and 3.13, and then scans this repository
with the tool itself.

## Security

See [SECURITY.md](SECURITY.md). If you find a vulnerability, please report it
privately rather than opening a public issue.

## License

MIT. See [LICENSE](LICENSE).
