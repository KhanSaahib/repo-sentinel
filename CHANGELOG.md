# Changelog

All notable changes to repo-sentinel. This project follows [semantic
versioning](https://semver.org/); until 1.0 the minor number carries breaking
changes.

## 0.3.0

0.2.0 was about the output people read. This one is about how much of a
repository the tool can read at all: it grew from two file formats to six.

### Added

- **Terraform** (TF001–TF006): security groups open to the internet, public
  storage, encryption switched off, wildcard IAM policies, public database
  endpoints, and unencrypted remote state. Built on a small HCL reader that
  knows blocks, so `cidr_blocks` in an `egress` block is correctly not a
  finding and `encrypted = false` in a `root_block_device` is reported where it
  actually sits.
- **Kubernetes** (K8S001–K8S008): privileged containers, host namespaces,
  hostPath mounts, capabilities added after the drop, declared root, absent
  resource limits, floating image tags, and credentials inside `Secret`
  manifests -- decoded from base64 and identified by the secret rules.
  Manifests are recognised by content (`apiVersion` plus `kind`), not by path.
- **Docker Compose** (DC001–DC006): privileged services, bind mounts that grant
  the host, shared host namespaces, confinement removed, sensitive ports
  published on every interface, and floating image tags.
- **SEC021**, a Google service account key file, which no single line reveals.
- **SEC022**, a provider credential hidden inside base64 -- kubeconfigs, CI
  variables, Helm values.
- **WF009**, a checkout that leaves the job token in `.git/config` under a
  privileged trigger, and **WF010**, a secret written to `$GITHUB_OUTPUT` or
  `$GITHUB_ENV` where it outlives the step.
- **`--paths-from FILE`** (`-` for stdin) to scan only the files a pull request
  touched, **`--quiet`** for the summary alone, and **`--sort path`** for
  reading a report rather than triaging it.
- **`repo-sentinel init`**, which scans a repository, records what is already
  there as a baseline so the first pipeline run is green, writes a config, and
  prints the CI snippet for whichever CI system the repository already has.
- **Per-path configuration**: a `paths` table switches rules off under one glob
  rather than everywhere, using the `.gitignore` dialect matched by the same
  code that reads `.gitignore`.
- **Scanning is roughly three times faster**: a cheap gate in front of the
  provider patterns rejects four fifths of lines before the expensive pass
  runs. With the quadratic YAML fix, the Python standard library went from 5.1s
  to 1.5s and Prometheus from not finishing in five minutes to 5.8s.
- **Confidence is weighed by where a file sits**, and the two places are
  weighed differently. In documentation every secret finding drops one step,
  documented token shapes included, because a credential in prose is usually an
  example -- Grafana's manual holds two dozen service account tokens and none
  is real. In a fixture tree only the guessing rules drop, because the classic
  way a real key reaches a repository is a test that once talked to a real
  service. Nothing is silenced either way.
- **Twelve more provider rules** (SEC023–SEC034): GitLab personal access and
  runner registration tokens, DigitalOcean, Shopify, Databricks, Doppler,
  Grafana, Telegram, Postman, Linear, Atlassian and Square. All documented
  shapes, so all high confidence.
- **FN004**: files that hold secrets as a byproduct rather than by purpose --
  Terraform state (which records every value Terraform read, in plain text), a
  state backup, a `.kubeconfig`, a shell or database client history.
- **Dependency manifests** (SC001–SC004): a registry over plain HTTP,
  certificate verification switched off, a dependency on a branch somebody can
  move, and an install-time script that downloads code and runs it. Covers
  `package.json`, `.npmrc`, `requirements*.txt`, `pip.conf`, `Gemfile` and
  `pom.xml` -- the question of where the rest of the build comes from, which
  every other family leaves unasked.
- **`--prune-baseline`**, which removes the entries that match nothing and
  accepts nothing new -- the safe half of re-running `--write-baseline`.
- **`--no-suppression`**, which reads the `repo-sentinel: ignore` markers but
  does not obey them, and a count of marker lines in every run's summary
  whether or not they were obeyed.
- **JSON is read wherever YAML is**: CloudFormation templates, Kubernetes
  manifests, `package.json` and `composer.json`, through a small reader that
  keeps line numbers and produces the same nodes as the YAML one. No rule
  changed to gain this.
- **Composer** joins the dependency manifests, with its own install-time
  lifecycle scripts.
- **CircleCI** (CC001–CC004): the same injection a fourth time, plus orbs
  pinned to `@volatile` or `@dev:`, which the registry is documented to move.
  What the four CI scanners share now lives in one module: finding the shell
  lines in a step, and the list of fields that cannot carry an injection --
  which was learned on GitHub Actions and then learned again, identically, on
  Azure.
- **Azure Pipelines** (AZ001–AZ004): `$(Build.SourceVersionMessage)` expanded
  into a command -- the third CI system and the third appearance of the same
  bug -- plus self-hosted pools, floating container images, and `system.debug`.
- **Ansible** (AN001–AN003): certificate verification switched off, a
  world-writable file mode, a fetch over plain HTTP. Narrow on purpose, because
  Ansible's idioms make most "insecure" patterns ambiguous and these three are
  wrong wherever they appear. Playbooks are recognised by vocabulary, and
  findings name the task they belong to, including inside a `block`.
- **CloudFormation** (CF001–CF005): open security groups, public buckets,
  encryption switched off, wildcard policies, public databases. The Terraform
  rules in AWS's other vocabulary, since the mistakes do not care which tool
  describes them. Both YAML and JSON templates, through readers that produce
  the same nodes, so the rules never learn which they are looking at.
- **K8S009 and K8S010**, the RBAC pair: a Role or ClusterRole granting every
  verb on every resource, and a binding whose subject is `system:anonymous`,
  `system:unauthenticated` or `system:authenticated` -- the last of which is
  every service account in the cluster.
- **TF001 covers every cloud**, not only AWS: `azurerm_network_security_rule`
  (where "anywhere" is `*` or the service tag `Internet`), nested
  `security_rule` blocks, and `google_compute_firewall`, alongside the four
  spellings AWS has accumulated for a security group rule.
- **TF007**: a service told to accept unencrypted connections --
  `enable_https_traffic_only = false`, a TLS floor of 1.0.
- **GitLab CI** (GL001–GL004): the injection class WF003 covers, in the other
  CI system -- `$CI_COMMIT_TITLE` and its siblings carry text a fork wrote --
  plus floating job images, pipe-to-shell build steps, and `CI_DEBUG_TRACE`,
  which disables variable masking and writes every secret into the job log.
  Pipelines are recognised by name or by shape, since `include:` lets a
  fragment live anywhere.
- **Helm chart support.** Template expressions are replaced with a placeholder
  and control lines blanked, line for line, so the Kubernetes rules that read a
  value the chart contains run over charts. The two rules that reason from a
  value's absence are skipped there, since the values file supplies it.
- **File-name rules** (FN001–FN003): a committed `id_rsa`, a `.p12` or `.jks`
  keystore, an `.npmrc` or `.env` that exists to hold a credential. The walk now
  reports every path it reaches, readable or not, which closes a blind spot:
  binary key material was being skipped before any rule saw it.
- **`--format github`**, workflow commands that become annotations on the pull
  request diff. SARIF needs `security-events: write`, which a fork's pull
  request does not have; annotations need no permission at all.
- **`--format markdown`**, a table meant to be posted as a pull request comment,
  with fixes collapsed underneath once per rule and long reports truncated.
- **`.repo-sentinel.json`**, a project config file supplying defaults for the
  scan flags, plus `disable` for rules a project has decided not to run and
  `--disable` for doing it ad hoc. Disabled findings are counted in the output
  rather than silently dropped. Unknown settings are an error; unknown rule ids
  are reported, since that typo leaves the rule switched on.
- **Rule-scoped suppression markers**: `# repo-sentinel: ignore[K8S008]`, on any
  of the three scopes, with family prefixes and lists. An unqualified marker
  stays exempt from rules that did not exist when it was written; a qualified
  one keeps the exemption as narrow as its reason.
- A **YAML subset reader** and an **HCL block reader**, both standard library
  only, both explicit about what they do not parse.

### Changed

- Findings that share a path, a line and a redacted value are collapsed to one:
  scanners overlap on purpose, reports should not. The most severe wins, and on
  a tie the format-specific rule does.
- Shared security facts -- which ports are worth shouting about, which host
  paths grant the host, which capabilities are a synonym for root -- moved into
  one module, so three scanners cannot drift into disagreeing about them.

### Fixed

- **The YAML reader kept trailing comments inside values.** `privileged: true
  # a note` was not `true`, so the rule reading it quietly found nothing --
  the worst way for a scanner to be wrong, and invisible from the output. Every
  YAML-based family was affected.
- **A suppression marker on a Dockerfile instruction broke the instruction.**
  Docker has no inline comments, so the marker became part of the image
  reference and the rule found nothing to parse: suppression by accident rather
  than by decision.
- **The YAML sequence parser was quadratic.** Parsing `- key: value` rebuilt the
  remaining token list for every item, so a 40,000-line rules file took minutes:
  scanning the Prometheus repository did not finish in five. It now takes 13
  seconds. The fix splits the dash from the mapping when tokenising, which also
  deleted the branch that was doing the copying.
- **Ten false positives, each measured against a public repository** rather than
  imagined: `.npmrc` files holding `ignore-scripts=true`, a committed `.env` of
  documented defaults, `"$$(cat /run/secrets/db-password)"` in a Compose
  healthcheck, and `"GITHUB_TOKEN_${org^^}"` in a shell script. Also
  `AZURE_FEDERATED_TOKEN_FILE` (the name of an environment variable) and
  `testdata/secret_key` (a path). From a Helm chart repository: YAML anchors
  and aliases (`&externalAuthorization`), label selectors containing `!=`,
  filenames on the right of a key called `secret`, template service account
  files whose `private_key` is empty, and `${{ github.event.pull_request.number }}`
  in a `run:` step -- a pull request number is an integer, and GitHub picks it.
- In the YAML reader, a colon only opens a mapping when whitespace follows it.
  Without that, `- 5432:5432` parses as a mapping and a Compose port list turns
  into nonsense.
- A quoted type expression (`tuple[int, str, int]`) is no longer read as a
  high-entropy credential. That one fired on this project's own source.
- A base64 run that yields a credential is no longer also reported by the
  entropy rules for being long and random.

### Internal

- The corpus test now asserts in three directions rather than two: every rule
  must also appear in the README's tables, so the documentation cannot fall
  behind the catalogue.

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
