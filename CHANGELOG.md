# Changelog

All notable changes to repo-sentinel. This project follows [semantic
versioning](https://semver.org/); until 1.0 the minor number carries breaking
changes.

## 0.3.0

0.2.0 was about the output people read. This one is about how much of a
repository the tool can read at all: two file formats became sixteen, and the
last of them is the first that reads code rather than configuration.

### Added

- **Terraform** (TF001–TF008): security groups open to the internet, public
  storage, encryption switched off, wildcard IAM policies, public database
  endpoints, and unencrypted remote state. Built on a small HCL reader that
  knows blocks, so `cidr_blocks` in an `egress` block is correctly not a
  finding and `encrypted = false` in a `root_block_device` is reported where it
  actually sits.
- **Kubernetes** (K8S001–K8S012): privileged containers, host namespaces,
  hostPath mounts, capabilities added after the drop, declared root, absent
  resource limits, floating image tags, credentials inside `Secret` manifests
  -- decoded from base64 and identified by the secret rules -- RBAC wildcards,
  bindings to everybody, host ports, and confinement switched off by name.
  Manifests are recognised by content (`apiVersion` plus `kind`), not by path,
  and a chart's values are read where a `Chart.yaml` sits beside them.
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
- **Twenty-five more provider rules** (SEC023–SEC047): GitLab personal access and
  runner registration tokens, DigitalOcean, Shopify, Databricks, Doppler,
  Grafana, Telegram, Postman, Linear, Atlassian, Square, Slack app tokens,
  Discord, Mailgun, Mailchimp, New Relic, Sentry DSNs, Asana, Dropbox, Figma,
  Airtable, JFrog Artifactory, Terraform Cloud and Firebase Cloud Messaging.
  All documented shapes, so all high confidence bar the Sentry DSN, which is
  semi-public by design.
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
- **Shell scripts and Makefiles** (SH001–SH003): `curl | sh`, certificate
  verification switched off, and world-writable modes -- found where they
  actually live rather than inside a Dockerfile or a pipeline. Files are
  recognised by extension, by name, or by shebang. The pipe-to-shell pattern,
  which five scanners had each copied, now lives in one place; they had already
  drifted, and only one of them knew about zsh.
- **Jenkins** (JK001–JK003): the shell steps of a Jenkinsfile, as far as is
  honest without parsing Groovy. JK001 turns on Groovy's quoting, which decides
  whether an interpolation is a bug at all: `sh "echo ${env.BRANCH_NAME}"` is
  substituted by Groovy before the shell sees it, and `sh 'echo $BRANCH_NAME'`
  is expanded by the shell and never parsed as code.
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
- **CloudFormation** (CF001–CF006): open security groups, public buckets,
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

- **A config file in a documentation tree drops a step of confidence.** The
  secrets scanner already weighed prose this way; the config families now do
  too, for the reason that a pipeline under `docs/` is a snippet in a tutorial
  and nothing schedules it. Measured on Dagger, which ships one Azure and one
  GitLab example per released version: the same two files were reported thirty
  times over.

- **Application code** (AP001–AP003), the first family that reads code rather
  than configuration: certificate verification switched off (six spellings,
  across Python, JavaScript, Go, PHP and Ruby), a web framework left in debug
  mode, and a credential generated from `Math.random()` or `random.choice()`.
  Each idiom is read only in the language it means something in, bundles are
  skipped, and a fixture tree drops a step of confidence -- a test against a
  self-signed server is the ordinary reason any of them appears.

- **Composite actions are scanned too.** `action.yml` is a workflow fragment by
  another name, and its steps run inside whichever repository calls it, so the
  pinning and injection rules apply there with a wider reach. **WF012** is the
  new one: an input interpolated into a `run:` block. An action cannot tell a
  safe input from a dangerous one -- `inputs.tag` is whatever the caller
  passed -- and one caller will eventually pass an issue title. Reported once
  per input, because the fix is one `env:` entry however many times the script
  mentions it.

- **No fixture is written as a credential any more**, and a test asserts it:
  the scanner runs over its own test sources and fails if a documented token
  shape appears as a single literal. Assembling the shape puts the identical
  string in front of the rule and nothing in front of anybody else's scanner.
- **WF013**: `contents: write` granted to a job that never writes. The token is
  minted per run with whatever the workflow asked for, so the grant is only as
  dangerous as the code it is handed to -- and a job that builds and tests,
  holding write access it does not use, is one injection away from pushing a
  commit. Everything that could be writing counts as writing, including a local
  composite action and a reusable workflow, because the reader cannot see
  inside either. Across nineteen repositories it fires once, and that one is
  real.
- **WF011**: a reusable workflow in another repository called with
  `secrets: inherit`. There is no way to inherit *some* secrets -- the callee
  receives the whole store -- so the cross-repository form is a standing grant
  of every credential the repository holds. Medium confidence when the call is
  pinned to a SHA, which at least fixes the code that will read them.

- **SC003 reads a Gemfile too**, where the source is a keyword rather than a
  URL: `github: "acme/x"` installs whatever that default branch holds. Found
  one in Discourse's own Gemfile.
- **`pyproject.toml` and `Cargo.toml` are read**, by table rather than by line:
  a URL in `[[tool.poetry.source]]` or `[source.mirror]` is a package source
  and one in `[project.urls]` is a link in a README. SC003 asks there whether a
  `git` dependency carries a `rev` or a `tag`; without one it installs whatever
  the default branch holds at build time. No TOML parser behind it -- `tomllib`
  arrived in 3.11 and this runs on 3.9.
- **FN004 is weighed in a fixture tree**, like the rest of its family: a
  `.tfstate` under `testdata/` is a fixture, and Terraform's own repository has
  162 of them. Still reported, because a real state file does end up in a test
  directory. Terraform at `--min-confidence medium`: 180 findings → 17.
- **A fixture's URL is not a package source.** `git = "[ROOTURL]/git-package"`
  is what Cargo's test suite writes, eleven times.
- **AP006**: a shell command built from an interpolated value. PHP's
  superglobals make it unambiguous and critical -- the request is inside the
  command line -- while a Python call with `shell=True` and an f-string, or
  Node's `exec()` with a template literal, are shapes rather than proofs and
  say so in their confidence. The fix is the same either way: stop using a
  shell.
- **AP004 and AP005**: untrusted data deserialised into objects
  (`yaml.load()` without a `Loader`, PHP's `unserialize()` on a superglobal),
  and a password put through a digest built for speed. The second is medium
  confidence because the idiom has two legitimate homes -- a breach-list check
  and a compatibility hasher -- and across nineteen repositories it found three
  instances, all of which were one of those two and all of which are password
  handling worth reading.
- **SH004**: a password handed to a command as an argument. `curl -u
  admin:hunter2`, `mysql -phunter2`, `sshpass -p`, `PGPASSWORD=`. Two problems
  in one line: the credential is in the file, and it is in the process table of
  whichever machine runs the script, where every other user can read it. A value
  that arrives at run time is not a leak, so anything interpolated is skipped.
- **A systemd unit and a crontab are value-position formats.** A unit is an
  INI file that runs as root, and the place a credential lands in one is
  `Environment=DB_PASSWORD=…` -- an assignment wrapped in an assignment, where
  the name that matters is the inner one.
- **A `.example` file is weighed like documentation.** A file whose name says
  template exists to be copied and filled in, and it is where a placeholder
  lives. Weakened, not silenced: a real key does get left in the file people
  copy.
- **A `classpath:` reference is not a private key.** Spring configuration says
  where a key file is -- `private-key: classpath:server.key` -- and spring-boot
  writes that a dozen times.
- **Seven token shapes from the last two years** (SEC048–SEC054): HashiCorp
  Vault service tokens, Supabase service role keys, PlanetScale database
  tokens, Tailscale auth keys, Sentry auth tokens, Groq and Replicate keys.
  Four of them are critical because they reach the data or the network
  directly; the rest are billed by the token.
- **A committed password database is a finding on its name**: `.kdbx`,
  `.kdb`, `.psafe3`, `.opvault`, `.agilekeychain`. Encrypted, so not critical;
  offline once committed, so not low -- unlimited guesses at one master
  password, with everything its owner keeps behind it.
- **A kustomization's inline patches are read**, which to the file's own parse
  are strings. An overlay exists to change what the base said, and what it
  changes is often the security context.
- **A chart's values file is read**, where a `Chart.yaml` sits beside it.
  `privileged: true` under a `securityContext` means the same thing in values
  as in a manifest, and that is where most Kubernetes settings actually live --
  a manifest in a chart is a template with `{{ .Values.securityContext }}` in
  it. Six settings, all at medium confidence, since the chart should pass them
  through and this reader has not read the template that does.
- **A CustomResourceDefinition is no longer read as a workload.** It carries
  an OpenAPI schema, and a schema names every field these rules look for --
  `hostPath`, `privileged`, `capabilities` -- as keys. The Grafana operator
  produced three critical findings that way, each of them a schema saying the
  field exists.
- **K8S012**: seccomp or AppArmor switched off by name -- `seccompProfile:
  Unconfined`, or the AppArmor annotation set to `unconfined`. Neither changes
  behaviour on a cluster with no Pod Security Standard, which is the reason the
  written-down version is worth reading: somebody needed it for one syscall,
  and it removes the filter from all of them.
- **TF008 and CF006**: a policy that names every principal. TF004 says the principal may
  do anything; this says anybody may be the principal -- `identifiers = ["*"]`,
  or `"Principal": "*"` in a JSON policy. On a role's trust policy that is any
  AWS account assuming the role. Found one in terragoat's Elasticsearch module
  that nothing had reported before.
- **WF001 grades itself by who can move the tag.** Somebody else's action
  changing under you is the rule; `actions/checkout@v4` is GitHub changing
  GitHub on a runner GitHub gave you, and is reported at low. Dagger at
  `--min-severity medium`: 122 findings → 98; Discourse 161 → 127.
- **`--fail-on none`**: report everything, fail on nothing. The job that
  uploads SARIF or posts the comment must not stop at the first finding, and
  every CI has its own word for that -- continue-on-error, allow_failure,
  continueOnError, catchError. Saying it in the command means the gate and the
  report differ by one readable flag. A usage error still exits 2.
- **`--quiet` says what the findings are, not only how many.** The three
  loudest rules come with the summary line, because a CI log is read by
  somebody deciding whether to look further, and a hundred findings that are
  all one rule is a decision to make once. It is the same block `init` prints.
- **`init` says what the findings *are***, not only how many: the three rules
  doing most of the talking, with their summaries and a pointer at
  `repo-sentinel rules <id>`. A hundred findings that are all one rule is a
  decision to make once, and the baseline it just recorded is mostly that rule.
- **`init` knows five CI systems, not two.** The snippet it prints is for the
  one the repository already has -- Azure, CircleCI and Jenkins included, each
  wired to draw the JUnit report. Suggesting GitHub Actions to a project that
  runs GitLab is how a getting-started section gets skipped.
- **`--format junit`**, which GitLab, Azure Pipelines and Jenkins all render
  natively as a list of failures with a message and a body. SARIF is the better
  format and GitHub is the only place it goes; this is for the other three, and
  it needs no plugin and no permission. A clean run is one passing case rather
  than an empty suite, because an empty report renders as a broken job.

- **`rules --format json` describes the families too**: what each one reads
  and where its section is, for the rules in the listing.
- **`rules <one rule>` prints a card rather than a row**: what the rule reads,
  which weakness it claims, how to silence it here and how to switch it off
  everywhere, and where the long version lives. A pattern that matches several
  rules still lists them, and the JSON shape does not change.

- **`--sort path` groups the text report by file**: the path is printed once
  and its findings sit under it. Sorting by path means reading a report rather
  than triaging one, and repeating the path on every line pushes the part that
  differs off to the right.

- **A CWE identifier per rule**, surfaced in `rules --format json` and in the
  SARIF tags. Five CI systems share CWE-78; "unpinned" is CWE-1357 whether it
  is an action, an orb, a base image or a dependency.

### Changed

- Findings that share a path, a line and a redacted value are collapsed to one:
  scanners overlap on purpose, reports should not. The most severe wins, and on
  a tie the format-specific rule does.
- Shared security facts -- which ports are worth shouting about, which host
  paths grant the host, which capabilities are a synonym for root -- moved into
  one module, so three scanners cannot drift into disagreeing about them.

### Fixed

- **WF002 reports a file once when no job declares permissions**, rather than
  once per job. The fix is a single top-level block however many jobs there
  are; a file where some jobs are explicit and others are not is still reported
  per job, because there the fix genuinely is per job.
- **Each application-code rule checks for its own word first.** A TypeScript
  monorepo is mostly files that mention "debug" and nothing else, and running
  the other thirteen patterns over each of them was the largest single cost in
  a scan: n8n 82s → 57s, with the corpus reporting identical findings.
- **A third gate in front of the entropy rules**: both need a name carrying
  one of a dozen credential words, and looking for the word first is far
  cheaper than running a pattern with a greedy class in front of its
  alternation. authentik 17.6s → 15.2s, with the corpus reporting identical
  findings.
- **The same credential repeated in one file is one finding**, counted rather
  than listed: the report says "and on 757 more lines", the JSON carries an
  `occurrences` field, and the finding points at the first one. One key is one
  key to rotate. Findings without a subject are untouched -- five unpinned
  actions in a workflow are five separate pins to write.
- **Entropy is measured on ASCII only.** Text in another script has high
  entropy per character because its alphabet is large, which is not randomness.
  Discourse's translated interface alone produced 1,600 findings.
- **Eight more false-positive classes from Discourse**: a Ruby `#{...}` or I18n
  `%{...}` interpolation, a constant path (`DiscourseAi::Tokenizer::Mistral`),
  a Redis key prefix, a hyphenated label in any language, a modular crypt
  identifier (`$pbkdf2-sha256$i=64000,l=32$`), an environment variable name
  with a leading underscore, a full sentence, and -- a parsing bug rather than
  a heuristic -- an escaped quote inside a quoted value, which cut a translated
  string in half and measured the half.
- **A name that labels a credential no longer counts as one.**
  `credentialType` names a kind, `secretName` names a Kubernetes Secret,
  `tokenPattern` is a regular expression -- none of them holds the thing
  itself, and n8n writes the first of those seven hundred times. The quoted
  rule now asks the same question the unquoted one always did.
- **A password hash is not a password.** `$2a$10$...`, `$argon2id$...`,
  `$pbkdf2-sha256$...`: the output of hashing one, which is the one thing that
  cannot be used as one, and what a fixture assigns to a key called `password`.
- **A documented shape with invented bytes is no longer a credential.**
  `sk-aaaaaaaaaaaa`, `xoxb-...-xxxxxxxxxxxx`, anything containing `CHANGE_ME`:
  a repeated character, a counted-out run of eight, or a word a human typed.
  Three questions with no plausible false answer, and
  `--no-example-allowlist` still reports them. n8n at `--min-confidence
  medium`: 249 findings → 219. The test fixtures that were written this way --
  `"a" * 28`, `abcdefghij0123456789` -- now look generated, which is what they
  were always meant to represent.
- **A PEM header with no key under it is no longer a private key.** When the
  `-----END-----` marker sits on the same line, what is between them is the
  key, and `\n${'FAKEKEYMATERIAL'}\n` is not one -- which is what a test of a
  redactor and a document about the format both look like. n8n writes that
  forty-three times. A header with the body on the lines below is untouched.
- **A square bracket is a code fragment too.** Laravel builds a command line
  out of a configuration array -- `'--password='.$connection['password']` --
  and the value the entropy rule saw was the middle of that expression.
- **Four more false-positive classes from n8n**: a template binding
  (`!areAllCredentialsSet`), a nullish-coalescing expression, a string being
  concatenated, and a sentinel constant beginning with a double underscore.
  n8n: 990 findings → 537, with the two deliberately vulnerable repositories
  unchanged.
- **Six more, measured against authentik**, whose OAuth and SAML code is made
  of identifiers that end in the word "password": URNs
  (`urn:oasis:names:tc:SAML:1.0:am:password`), space-separated response types
  (`code id_token token`), media types (`dpop+id_token`), snake_case dotted
  identifiers, and the `#/components/schemas/...` references an OpenAPI schema
  contains tens of thousands of. Google's published reCAPTCHA test pair joins
  the example allowlist: it is documented so that automated login tests pass,
  so every project with one has a copy.
- **Five more false-positive classes, measured against Dagger.** A value that
  says where the credential lives rather than what it is (`env:NPM_TOKEN`,
  `vault:secret/data/ci`); a string type annotation in a generated client
  (`"Secret | None"`); a fragment of Go picked up between two string literals
  (`+fmt.Sprintf(`); a constant whose *name* ends in "secret"
  (`git.authheadersecret`); and a shell line continuation left attached to the
  value, which defeated every filter that asks what shape a value has.
- **`pool: Azure Pipelines` is the pool Microsoft runs**, not a self-hosted
  one, and AZ002 said otherwise -- so the rule was loudest in exactly the place
  it was most wrong, since "Azure Pipelines" is what every tutorial writes. The
  legacy `Hosted *` names and a `vmImage:` beside the pool name are hosted too.
- **A workflow annotation could be split in two by a vertical tab** or any of
  the other characters something treats as a line break, leaving a corrupt
  command behind it. Found by a property test that now runs every format over
  findings built from the characters a real file can contain.
- **SARIF reports what the run could not read**, as `toolExecutionNotifications`
  on the invocation. A Security tab showing no alerts because nothing was
  scanned looks exactly like one showing no alerts because everything is fine.
- **`--format json` carries a `scan` object**: files read, duration, what was
  skipped as unreadable or oversized, and the suppression counts. The text
  report has always said this in a sentence; a pipeline cannot read a sentence,
  and one that cannot tell "no findings" from "nothing was read" is exactly
  what the sentence exists to prevent.
- **A file skipped for its size is now counted and named**, with
  `--max-file-size` (and a `max_file_size` config key) to raise the 2 MB limit.
  A 3 MB `.env` was skipped silently, which is precisely the answer this tool
  exists to avoid giving.
- **A control character in a file could make the JUnit report unparseable**,
  and a lone carriage return could end a Markdown table row early. Both came
  from the same place -- evidence is a piece of a file, and a file with a stray
  control byte in it is not binary enough to be skipped.
- **A path that does not exist scanned clean.** `repo-sentinel scan tests/fixtues`
  walked nothing, found nothing and said "no findings" -- the one answer this
  tool must never give for a tree it did not read. It is an error now.
- **An unreadable file is named the way the report names everything else.** A
  dangling symlink -- the common case, and kubernetes-goat has one -- was
  reported by absolute path, in a sentence otherwise full of relative ones.
- **A tree that could not be opened said nothing about it.** The count of
  unreadable paths was attached only to the line reporting how many files were
  scanned, and a locked directory scans zero files: the run that most needed
  the warning was the one that did not print it. An unreadable root is also
  named by the path given rather than by its path relative to itself, which is
  the empty string.
- **The YAML reader kept trailing comments inside values.** `privileged: true
  # a note` was not `true`, so the rule reading it quietly found nothing --
  the worst way for a scanner to be wrong, and invisible from the output. Every
  YAML-based family was affected.
- **A suppression marker on a Dockerfile instruction broke the instruction.**
  Docker has no inline comments, so the marker became part of the image
  reference and the rule found nothing to parse: suppression by accident rather
  than by decision.
- **A byte-order mark made a file invisible.** Editors on Windows write one,
  and a leading `\ufeff` turns `apiVersion` into a key no rule is looking for:
  the manifest was reported clean rather than reported unscanned. Files are
  decoded as `utf-8-sig` now.
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
