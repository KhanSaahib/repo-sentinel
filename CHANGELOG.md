# Changelog

All notable changes to repo-sentinel. This project follows [semantic
versioning](https://semver.org/); until 1.0 the minor number carries breaking
changes.

## 0.2.0

The theme of this release is that a scanner is only useful if people keep
reading its output. Most of what follows is either a new class of finding or a
way to stop reporting the ones that were never worth reporting.

### Added

- **Dockerfile scanning** (DK001–DK006): unpinned base images, containers that
  end up running as root, `curl | sh` build steps, credentials baked into image
  layers, `ADD` from a URL, and disabled TLS verification. Continuations are
  joined before the rules run, and build stages are tracked so only the stage
  that becomes the image is asked about `USER`.
- **Ten more secret rules** (SEC011–SEC020): Azure storage account keys, Google
  OAuth client secrets, SendGrid, Twilio, npm, PyPI, Docker Hub, Hugging Face,
  Slack incoming webhooks, and credentials embedded in connection strings.
- **SEC101**, the entropy rule for file formats that write credentials bare —
  `.env`, `.npmrc`, `.pypirc`, INI files, YAML — where there is no quoting to
  key on.
- **Four more workflow rules**: `write-all` permissions (WF005), self-hosted
  runners (WF006), secrets handed to third-party actions (WF007), and
  `workflow_run` checking out the triggering run's head (WF008).
- **Confidence**, carried separately from severity on every finding, with
  `--min-confidence` to gate on it. Severity is what a finding costs if it is
  real; confidence is how sure the rule is that it is.
- **Baselines**: `--write-baseline` records the current findings as accepted and
  `--baseline` fails only on what arrives afterwards. The file holds hashes of
  already-redacted evidence and no line numbers, so it is safe to commit and
  survives reformatting. Stale entries are reported so the file shrinks.
- **SARIF output** (`--format sarif`) with stable partial fingerprints, plus
  `--output FILE`, so findings land in the GitHub Security tab as annotations.
- **`repo-sentinel rules`**, which prints the whole rule catalogue in text or
  JSON without needing something to find.
- A **GitHub Action** (`action.yml`) and a **pre-commit hook**
  (`.pre-commit-hooks.yaml`).

### Changed

- **The entropy floor moves with the value.** A single global threshold of 3.2
  was simultaneously too strict for short hex tokens, which cannot exceed 3.58
  bits per character, and too lax for long base64 blobs, which reach 6. The
  floor is now 75% of the ceiling a value's own alphabet and length allow.
- **WF002 is asked per job**, not per file. A job that declares its own
  `permissions:` block is no longer reported because the file has no top-level
  one.
- **WF004 is asked per step.** A `ref:` line now only counts when it sits in a
  checkout step or names an untrusted context outright, rather than any `ref:`
  anywhere in the file.
- Text output shows how many files were scanned. A run that scanned nothing
  looked exactly like a clean repository.
- Findings sort by confidence within a severity band, so the certain ones come
  first.

### Fixed

- `authors`, `author`, `authorized_keys` and `authenticate` are no longer read
  as credential names. The bare substring `auth` was matching them; this false
  positive fired on this project's own `pyproject.toml`.
- Paths, URLs without a password in them, version constraints, timestamps,
  dotted identifiers and JSON containers are no longer treated as high-entropy
  credentials.

### Internal

- Scanning moved out of the CLI into `engine`, formatting into `report`, and the
  shared judgement calls into `heuristics`, so the CLI is argument handling and
  nothing else.
- A test corpus trips every rule in the catalogue, and the suite asserts in both
  directions: no scanner may emit an undocumented rule, and no catalogue entry
  may describe a rule nothing emits.

## 0.1.0

Initial release: secret detection by provider pattern and by entropy, GitHub
Actions workflow checks, `.gitignore`-aware discovery, an allowlist for
documented example credentials, and line, block and file suppression markers.
