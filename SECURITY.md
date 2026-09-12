# Security Policy

## Supported versions

This project is pre-1.0. Only the latest commit on `main` is supported.

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/KhanSaahib/bluerayscan/security/advisories/new)
rather than opening a public issue.

Include what you can: affected version or commit, reproduction steps, and what
an attacker gains. Expect an initial response within seven days.

Please do not test against systems you do not own.

## Threat model

bluerayscan reads files and writes a report. It makes no network calls, runs
no code it finds, starts no subprocesses, and has no runtime dependencies.
`bluerayscan history` reads a diff on standard input rather than running git,
for that reason. The realistic risks are:

- **Leaking through the report.** Findings are pasted into CI logs and issues.
  Every matched value is redacted to its first and last four characters before
  it is ever printed, and short values are masked entirely.
- **False confidence.** Workflow analysis is pattern-based rather than
  YAML-aware, and secret detection cannot recognise a credential format it has
  never seen. A clean report means the known checks passed. It is not proof that
  a repository is safe.
- **The baseline file.** `--baseline` records accepted findings in a file meant
  to be committed. Entries hold a hash of already-redacted evidence plus the
  rule id and path, never the value itself, so publishing one reveals nothing a
  reader could turn back into a credential. It does disclose that a repository
  has an accepted finding of a given class in a given file.
- **Untrusted input.** Scanned files are attacker-controlled by definition —
  anyone can open a pull request. All matching is done with bounded regular
  expressions against text read as UTF-8 with replacement; no scanned content is
  evaluated, deserialised, or executed.

## How this repository is hardened

- Zero runtime dependencies, so there is no transitive supply chain to trust.
- GitHub Actions are pinned to full commit SHAs, not mutable tags.
- Workflows declare `permissions: contents: read` and check out with
  `persist-credentials: false`.
- Dependabot proposes action updates weekly so pins are refreshed deliberately.
- CI scans this repository with the tool itself on every push and pull request,
  and publishes the result to the Security tab from a separate job that holds
  `security-events: write` and nothing else.
- The tool writes to disk only where explicitly told to: `--output` and
  `--write-baseline`. Every other run is read-only.
