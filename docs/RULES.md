# Rules

Every check repo-sentinel makes, what it is looking for, and why that thing is
worth a build failure. `repo-sentinel rules` prints the same list from the tool
itself, with `--format json` if you want to diff it between releases.

The test suite asserts that this file, the rule catalogue in `rules.py` and the
scanners all agree: a rule missing from any of the three fails the build.

For what the severity and confidence columns mean, see
[Severity and confidence](../README.md#severity-and-confidence) in the README.

Every rule also names the weakness it reports, as a CWE identifier:
`repo-sentinel rules --format json` carries it, and the SARIF output puts it in
each rule's tags so the Security tab can group by it. It is a claim rather than
a decoration -- five CI systems share CWE-78, and "unpinned" is CWE-1357
whether it is an action, an orb, a base image or a dependency. SEC900 has no
CWE, because it reports a mistake in this tool's own configuration rather than
a weakness in anybody's software.

## Secrets

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
| SEC021 | Google service account key file | critical | high |
| SEC022 | Provider credential hidden inside base64 | up to critical, as the rule it decodes to | high |
| SEC023 | GitLab personal access token | critical | high |
| SEC024 | GitLab runner registration token | critical | high |
| SEC025 | DigitalOcean personal access token | critical | high |
| SEC026 | Shopify access token | critical | high |
| SEC027 | Databricks personal access token | critical | high |
| SEC028 | Doppler service token | critical | high |
| SEC029 | Grafana service account token | high | high |
| SEC030 | Telegram bot token | high | high |
| SEC031 | Postman API key | high | high |
| SEC032 | Linear API key | high | high |
| SEC033 | Atlassian API token | high | high |
| SEC034 | Square access token | critical | high |
| SEC035 | Slack app-level token | high | high |
| SEC036 | Discord bot token | critical | high |
| SEC037 | Mailgun API key | high | high |
| SEC038 | Mailchimp API key | high | high |
| SEC039 | New Relic API key | high | high |
| SEC040 | Sentry DSN | medium | medium |
| SEC041 | Asana personal access token | high | high |
| SEC042 | Dropbox access token | critical | high |
| SEC043 | Figma personal access token | high | high |
| SEC044 | Airtable personal access token | high | high |
| SEC045 | JFrog Artifactory token | critical | high |
| SEC046 | Terraform Cloud API token | critical | high |
| SEC047 | Firebase Cloud Messaging server key | high | high |
| SEC048 | HashiCorp Vault service token | critical | high |
| SEC049 | Supabase service role key | critical | high |
| SEC050 | PlanetScale database token | critical | high |
| SEC051 | Tailscale auth key | critical | high |
| SEC052 | Sentry authentication token | high | high |
| SEC053 | Groq API key | high | high |
| SEC054 | Replicate API token | high | high |
| SEC100 | High-entropy value in a quoted assignment | high | medium |
| SEC101 | High-entropy value in an unquoted config value | high | medium |
| SEC900 | Suppression block opened and never closed | medium | high |

SEC900 is not a class of secret; it reports a suppression block that was opened
and never closed. See [Suppressing a false positive](#suppressing-a-false-positive).

SEC001–SEC054 match on documented token structure. A token to a secrets
manager (SEC028) is rated as what it opens rather than as one credential, and
a payment token (SEC034) as what it can move, and a Terraform Cloud token
(SEC046) as the state it can read -- which holds every secret a plan touched. Two of them are looser than
the rest and say so through their confidence: SEC014 is a two-letter prefix in
front of 32 hex characters, and SEC020 is any `scheme://user:password@host`.

Every provider rule also asks whether the bytes were generated or typed. A
documented shape is what makes these rules certain, and it is also what makes
them fire on every fixture that needs a well-formed key: `sk-aaaaaaaa...`,
`xoxb-...-xxxxxxxxxxxx`, `...CHANGE_ME`. A repeated character, a counted-out
run of eight, or a word somebody typed are the three questions with no
plausible false answer, and `--no-example-allowlist` reports them anyway --
that flag exists to show what the scanner chose not to say.

SEC004 asks one further question, because a PEM header is quoted far more
often than it is committed: when the `-----END-----` marker is on the *same*
line, the thing between the two is the key, and a dozen characters of
placeholder is not one. A header with the body on the lines below it is the
ordinary case and is always reported -- the rule reads one line at a time, so
"cannot see the body" has to mean "assume it is real".

SEC021 and SEC022 are the two rules a line-at-a-time scanner cannot express.
SEC021 reports a Google service account key file -- `"type": "service_account"`
plus a private key field, neither of which means anything alone and no single
line of which sees both. SEC022 decodes base64 runs and hands the result to the
provider rules: encoding is not encryption, but it is enough to hide a
credential from every rule that reads the line it sits on, which is most of
what a kubeconfig or a CI variable is made of. Only the documented token shapes
are applied to decoded text, never entropy -- decoded base64 is random-looking
by construction, so entropy there would fire on every certificate in the tree.

### The entropy rules

SEC100 and SEC101 are the heuristics. They fire when a name that promises a
credential (`password`, `api_key`, `client_secret`, …) is assigned a value that
looks generated rather than written. SEC100 reads quoted assignments in source
code; SEC101 reads the formats that write credentials bare — `.env`, `.npmrc`,
`.pypirc`, INI files, YAML, a crontab, and a systemd unit — where there is no
quoting to key on, and where the file's own syntax has to stand in for it. A
unit wraps its assignment in one of its own (`Environment=DB_PASSWORD=…`), and
the name that matters is the inner one.

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

A finding is weighed by where it was made, and the two places are weighed
differently because the mistakes people make in them differ.

In **documentation** (`docs/`, `*.md`, `*.rst`) every secret finding drops one
step of confidence, documented token shapes included. A file whose *name* says
template -- `.env.example`, `config.sample.yml`, `values.template.yaml`,
`app.conf.dist` -- is documentation with a different extension and is weighed
the same way: it exists to be copied and filled in. n8n's says
`sk-ant-api03-REPLACE_ME`. A credential written into
prose is usually an example, which is what prose is for: Grafana's own manual
contains two dozen service account tokens and not one of them is real. Nothing
is silenced -- a live key does get pasted into a README -- but
`--min-confidence high` stops hearing about them.

In a **fixture tree** (`testdata/`, `fixtures/`, `spec/`, `*_test.*`) only the
rules that were already guessing drop. Entropy is worth less there because
invented credentials are the point of a fixture. A documented token shape is
not worth less, because the classic way a real key reaches a repository is a
test that once talked to a real service.

That is a deliberate trade and it has a cost: a project whose tests need TLS
commits a key per case, and Spring Boot has a hundred and twenty-six of them.
They are real private keys, so SEC004 says so; what makes that liveable is the
baseline -- `repo-sentinel init` records them once and every later run is about
new ones -- or a per-path rule in the config, which is the honest way to say
"not here":

```json
{ "paths": { "**/src/test/resources/**": { "disable": ["SEC004"] } } }
```

Entropy is measured on ASCII only. Credentials travel through headers, URLs
and environment variables that are ASCII, and text in another script is not --
its entropy per character is high because its alphabet is large, which has
nothing to do with randomness. Discourse's translated interface produced 1,600
findings before this rule existed: "password", forty times per locale.

A name that *labels* a credential is not a name that holds one, and both rules
check: `credentialType` names a kind of credential, `secretName` names a
Kubernetes Secret, `tokenPattern` is a regular expression. n8n assigns a
credential type to a key called `credentialType` seven hundred times.

A password *hash* is filtered too. `$2a$10$...`, `$argon2id$...` and their
relatives are the output of hashing a password, which is the one thing that
cannot be used as one -- and they are what a test fixture assigns to a key
called `password`.

Placeholders are filtered before entropy is measured at all — `your-password-here`,
`${DB_PASSWORD}`, `xxxxxxxx`, `changeme` — and so is structure that is not a
credential: paths, URLs without a password in them, version constraints, dotted
identifiers, timestamps.

Every reported value is redacted to its first and last four characters. Findings
end up in CI logs and issue threads, so the scanner must never be the thing that
leaks the credential it just found.

### Documented example credentials

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

## File names

| Rule | Finds | Severity |
| --- | --- | --- |
| FN001 | A file that is private key material by name | critical for `id_rsa`, high for a keystore |
| FN002 | A key-shaped file nothing could read | medium |
| FN003 | A file whose purpose is to hold a credential | medium, high for a password database |
| FN004 | A file that records secrets as a side effect | critical for Terraform state |

Every other rule here reads text, which makes them all blind to the files that
have none. A committed `id_rsa` has no line to match; a `.p12`, a `.jks`, a
`.pfx` are binary and skipped before any rule sees them. These are among the
worst things a repository can contain and the easiest for a scanner to miss, so
the walk reports every path it reaches, readable or not, and these three rules
work from the names.

They claim less than the others, and all three prefer contents to names
wherever contents exist. `.pem` and `.key` are private keys about as often as
they are certificates, so FN002 fires only when the file could *not* be read --
if it is text, SEC004 has already looked inside, and its answer is better than a
guess about the extension.

FN003 splits the same way. `.netrc`, `.pgpass`, `.my.cnf`, `.dockercfg`,
`credentials` and `kubeconfig` have no legitimate committed form, so the name is
the finding. `.npmrc`, `.pypirc`, `.env` and `terraform.tfvars` are judged on
what is in them: an `.npmrc` saying `ignore-scripts=true` is not a leak, and a
committed `.env` of documented defaults is a template. Both of those were real
false positives, measured against a public repository of Compose examples.

A password database -- `.kdbx`, `.psafe3`, a 1Password vault -- is the same rule
at high severity. The file is encrypted, which is why it is not critical, and
it is offline once committed, which is why it is not low: unlimited guesses at
one master password, with every credential its owner has behind it.

Files under `fixtures/` or `testdata/` are reported at low confidence rather
than not at all. And `.example`, `.sample`, `.template` and `.dist` suffixes are
skipped everywhere: a repository documenting the shape of its `.env` is doing
the right thing.

## Dependencies

| Rule | Finds | Severity |
| --- | --- | --- |
| SC001 | Packages fetched over plain HTTP | high |
| SC002 | Install-time script downloads code and runs it | high |
| SC003 | Dependency comes from a source that can move | medium |
| SC004 | Package manager skips certificate verification | high |

Every other family asks what a repository contains. This one asks where the
rest of it comes from, which is what a dependency manifest answers and nobody
reads. A registry over plain HTTP, verification switched off to get past one
broken certificate, a dependency on a branch somebody can move, an install
script that downloads code and runs it: four ordinary-looking lines that each
hand the contents of your build to somebody else.

SC002 is scoped to the lifecycle scripts a package manager runs without being
asked -- npm's `preinstall`, `install`, `postinstall`, `prepare`, and
Composer's `post-install-cmd` and friends -- because `npm install` or `composer
install` is enough to execute them, on every machine and every CI runner. The
same command inside `build` is a different proposition and is not reported.

Covered: `package.json`, `composer.json`, `.npmrc`, `requirements*.txt`,
`pip.conf`, `Gemfile`, `pom.xml`, `pyproject.toml`, `Cargo.toml`. SC001 reads
the JSON manifests structurally, because there the field is available and it
decides: `publishConfig.registry` is somewhere packages come from, and
`repository`, `homepage` and `bugs` are metadata npm has never downloaded
anything from. The two TOML manifests are read by table for the same reason --
a URL in `[[tool.poetry.source]]` is a package source and one in
`[project.urls]` is a link in a README -- with no TOML parser behind it, since
`tomllib` arrived in 3.11 and this runs on 3.9. In those two, SC003 asks
whether a `git` dependency carries a `rev` or a `tag`: without one it installs
whatever the default branch holds at build time. It asks the same of a
`Gemfile`, where the source is a keyword rather than a URL -- `github:`,
`git:`, `gist:` -- and where `ref:` and `tag:` are the two spellings that pin
it. `branch:` is not one of them. The checks are shallow on purpose -- this is not a resolver, and it
does not know what a version means -- because these four mistakes are visible
in the text.

## GitHub Actions workflows

| Rule | Finds | Severity |
| --- | --- | --- |
| WF001 | Action pinned to a mutable tag, or not pinned at all | medium for a third party, low for `actions/` and `github/` |
| WF002 | Job inherits the default `GITHUB_TOKEN` permissions | medium |
| WF003 | Attacker-controlled context interpolated into a `run:` block | critical |
| WF004 | `pull_request_target` checking out untrusted code | critical |
| WF005 | `GITHUB_TOKEN` granted `write-all` | high |
| WF006 | Job runs on a self-hosted runner | medium |
| WF007 | Secret passed as an input to a third-party action | medium |
| WF008 | `workflow_run` checking out untrusted code | critical |
| WF009 | Checkout leaves a usable token in `.git/config` | high |
| WF010 | Secret written to a job output or environment | high |
| WF011 | Every secret passed to a workflow in another repository | high |
| WF012 | Composite action interpolates an input into a shell command | medium |

WF001 grades itself by who can move the reference. A tag on somebody else's
action is code you do not control changing under you, which is the rule; a tag
on `actions/checkout` is GitHub changing GitHub, on a runner GitHub already
gave you, and that one is reported at low. Both are still reported -- pinning
everything is the advice, and an organisation that pins one and not the other
has decided rather than forgotten -- but a workflow with eleven first-party
tags in it should not read like eleven problems.

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
output. When *no* job declares them, the file gets one finding rather than one
per job: the fix there is a single top-level block, and four copies of a
one-line instruction teach the same lesson. WF007 is asked per step, for actions outside the `actions/` and `github/`
namespaces **that are not pinned to a commit SHA**. An action reads every input
it is given, so handing one a secret extends that secret's blast radius to the
action's supply chain — which is often necessary, since pushing an image needs a
registry password. What the rule actually asks is whether the recipient can
change under you: a commit SHA is code somebody chose and can review, a tag is
whatever its owner moves it to tomorrow. WF001 says the tag is mutable; WF007
says what is being trusted to it.

WF009 is scoped on purpose. `actions/checkout` leaves the job's token in the
working copy unless told otherwise, which is tolerable on a workflow that only
runs your own code and is not tolerable under `pull_request_target` or
`workflow_run` -- triggers that exist precisely to run in a context an outsider
influenced. Reporting every checkout in the world would get the rule switched
off. WF010 catches a secret written to `$GITHUB_OUTPUT` or `$GITHUB_ENV`, where
it outlives the step, reaches later jobs and calling workflows, and stops being
covered by log masking the moment it is transformed.

WF011 is about `secrets: inherit` on a reusable workflow call. There is no way
to inherit *some* secrets: the callee receives the whole store, including the
credentials it has nothing to do with. Calling a workflow in your own repository
that way is a convenience, and the rule stays quiet about it. Calling one in
somebody else's repository that way is a standing grant of every credential the
repository holds, redeemable whenever that repository changes -- so the rule is
scoped to the cross-repository case, and drops to medium confidence when the
call is pinned to a commit SHA, which at least fixes the code that will read
them.

WF012 is the injection rule again, from the other side. The family also reads
`action.yml` -- a composite action is a workflow fragment by another name, and
its steps run inside whichever repository calls it, so an unpinned `uses:` or an
interpolated `github.event` field there is the same mistake with a wider reach.
What an action cannot do is tell a safe input from a dangerous one: `inputs.tag`
is whatever the caller passed, and one caller will eventually pass an issue
title. Hence medium and medium -- most inputs are a version number, the mistake
is the caller's to make, and the prevention is still the action's to write. Only
composite actions are read; a JavaScript or container action keeps its risk in
code this scanner is not looking at.

Workflow checks are pattern-based rather than YAML-aware, a deliberate
consequence of the zero-dependency rule. What the scanner does parse is
structure: jobs and steps are split apart by indentation, because "does this job
declare permissions" and "is this secret handed to a third party" are questions
about a block, not about a line. Unusual formatting can still slip past, so treat
a clean report as encouraging, not as proof.

## Dockerfiles

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

## GitLab CI

| Rule | Finds | Severity |
| --- | --- | --- |
| GL001 | Pipeline image tag can point elsewhere tomorrow | medium |
| GL002 | Outsider-supplied variable interpolated into a script | critical |
| GL003 | Job pipes a download into a shell | high |
| GL004 | `CI_DEBUG_TRACE` writes every variable to the job log | high |

GL002 is WF003's twin. GitLab substitutes its predefined variables into the
shell exactly as Actions substitutes its contexts, and several of them carry
text an outsider wrote: `$CI_COMMIT_TITLE`, `$CI_MERGE_REQUEST_DESCRIPTION`,
`$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`. `echo "Building $CI_COMMIT_TITLE"` runs
whatever a fork put in that title.

GL004 catches the switch that turns off variable masking: with `CI_DEBUG_TRACE`
on, every variable the job can see -- masked ones included -- is written to a
log that is often readable by anyone who can see the project.

Pipelines are recognised by name (`.gitlab-ci.yml`) or by shape, since
`include:` lets a fragment live in any file under any name. Hidden `.template`
jobs are scanned too: GitLab does not run them directly, but everything that
`extends` one runs its script, so reporting the injection where it is written
beats reporting it in each of the five jobs that inherited it.

## Azure Pipelines

| Rule | Finds | Severity |
| --- | --- | --- |
| AZ001 | Outsider-supplied variable expanded into a command | critical |
| AZ002 | Pipeline runs on a self-hosted pool | medium |
| AZ003 | Pipeline container image can point elsewhere tomorrow | medium |
| AZ004 | `system.debug` writes every variable to the job log | high |

The third CI system and the third appearance of the same bug. Azure expands
`$(Build.SourceVersionMessage)` into the shell before the shell runs, exactly
as Actions expands `${{ github.event.issue.title }}` and GitLab expands
`$CI_COMMIT_TITLE`. AZ001 skips the fields that cannot carry an injection --
a pull request id is a number, a commit id is hex -- for the same reason WF003
does.

AZ004 is GL004's twin: debug logging prints variable values, secret ones
included, into a log that is often readable by anyone who can see the project.

Pipelines are recognised by name or by shape, since a template can live in any
file and be included from anywhere.

## CircleCI

| Rule | Finds | Severity |
| --- | --- | --- |
| CC001 | Outsider-supplied variable expanded into a command | critical |
| CC002 | Orb pinned to a reference the registry moves | high |
| CC003 | Job image can point elsewhere tomorrow | medium |
| CC004 | Step pipes a download into a shell | high |

The fourth CI system, and the same rules the other three needed --
`$CIRCLE_BRANCH` is chosen by whoever opened the pull request, exactly as
`$CI_COMMIT_TITLE` and `${{ github.event.issue.title }}` are.

CC002 is CircleCI's own: `circleci/aws-cli@volatile` and `somebody/orb@dev:branch`
are *documented* as moving references, so the registry hands you whatever was
published last. That is a supply chain you do not control, written down in the
file.

## Jenkins

| Rule | Finds | Severity |
| --- | --- | --- |
| JK001 | Groovy interpolates outsider text into a shell step | critical |
| JK002 | Agent image can point elsewhere tomorrow | medium |
| JK003 | Shell step pipes a download into a shell | high |

A Jenkinsfile is a Groovy program and this tool has no business parsing one.
What it reads is the shell steps, which is where a pipeline's security
decisions live.

JK001 turns on Groovy's quoting, which decides whether an interpolation is a
bug at all. `sh "echo ${env.BRANCH_NAME}"` is interpolated by *Groovy*, before
the shell sees it, so a branch called `$(curl evil)` runs on the agent. `sh
'echo $BRANCH_NAME'` is a single-quoted string Groovy leaves alone, so the
shell expands the variable and never parses the value as code. The two lines
look nearly identical and differ entirely, which is what makes the rule worth
having and what makes a reviewer skim past it.

Everything here is line-based. A pipeline that builds its commands through a
helper function, or a shared library, is invisible to it.

## Shell scripts and Makefiles

| Rule | Finds | Severity |
| --- | --- | --- |
| SH001 | Script downloads code and runs it in one step | high |
| SH002 | Script disables certificate verification | medium |
| SH003 | Script makes something world-writable | medium |
| SH004 | Password handed to a command as an argument | high |

Every other family finds `curl \| sh` inside something -- a Dockerfile, a
pipeline, a package manifest. This one finds it where it usually lives: in the
script those things point at, which nobody re-reads once it works.

SH004 is two problems in one line. `curl -u admin:hunter2`, `mysql -phunter2`,
`sshpass -p hunter2`, `PGPASSWORD=hunter2 psql`: the credential is in the file,
which is this scanner's usual business, and it is also in the process table of
whichever machine runs the script, where every other user on that machine can
read it while it runs. Each of these tools documents a file or an environment
variable to use instead, which is why the flag exists to be found. A value that
arrives at run time is not a leak, so anything interpolated is skipped.

Files are recognised by extension, by name (`Makefile`), or by shebang, which
matters because a setup script with no extension is still a shell script and is
exactly what a repository accumulates. Continuations are joined before the
rules run, so a command split over four lines is judged as one and reported at
the line it starts on. Comments are skipped -- a commented-out `curl | sh` is
somebody's note about the thing they decided not to do.

## Application code

| Rule | Finds | Severity |
| --- | --- | --- |
| AP001 | Certificate verification switched off in code | high |
| AP002 | Web framework debug mode enabled | medium |
| AP003 | Credential generated by a predictable random source | high |
| AP004 | Untrusted data deserialised into objects | high |
| AP005 | Password hashed with a digest built for speed | medium |
| AP006 | Shell command built from an interpolated value | critical for a request, otherwise high |

Every other family reads configuration. This one reads code, which is a
different proposition: configuration says what a system *is*, and code says
what it does. A line-at-a-time reader can honestly answer questions about
idioms and not about behaviour, so there are three rules, each a well-known
idiom with a well-known meaning, and each written per language rather than
guessed at across all of them. Python, JavaScript and TypeScript, Go, PHP and
Ruby; `.min.js` and its relatives are skipped, because a bundle is machine
output and never chose any of its idioms.

What the three have in common is that they are *deliberate*. Nobody disables
certificate verification by accident: it is typed to get past a failure, with
an intention to put it back that nothing afterwards records. AP001 knows the
six spellings -- `verify=False`, `_create_unverified_context`,
`rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`,
`InsecureSkipVerify: true`, `CURLOPT_SSL_VERIFYPEER` set false, and
`VERIFY_NONE`.

AP002 is Django's `DEBUG = True` and Flask's `debug=True`, both of which put a
traceback, the local variables and often the settings object in front of
whoever caused the error. Medium confidence: a settings module that reads the
value from the environment is the ordinary case and this is the one that does
not.

AP003 asks a narrower question than "is this generator weak". `Math.random()`
picks a colour far more often than it picks a token, so the rule fires only
where the *name* promises a credential -- `token`, `secret`, `otp`, `salt`,
`session_id`, `reset_code`. Given a few outputs from these generators, the rest
follow.

AP004 is two idioms with one meaning. `yaml.load()` without a `Loader` builds
whatever the document names, which is remote code execution if the document
came from anywhere but the repository -- PyYAML made `SafeLoader` the default
in 6.0, so a call written the old way is either old or deliberate. PHP's
`unserialize()` on a superglobal is the same thing without the ambiguity: the
request chooses which classes are built and which destructors run.

AP005 is a password put through a digest built for speed, which is the whole
attack -- a stolen table of MD5 or SHA-256 password hashes is a few hours of
guessing. It fires only where the argument is named like a password, because
`sha256(file_bytes)` is a checksum and nobody's problem.

Medium confidence, because the idiom has two legitimate homes and the reader
has to tell them apart: checking a password against a breach list uses
`sha1(password)` because that is what the Have I Been Pwned API takes, and a
compatibility hasher reproduces whatever the system being migrated from used.
Measured across nineteen repositories, the rule fired three times and every one
of those was one of these two -- which is still three pieces of password
handling worth a reader's attention.

AP006 is the injection class again, in the language rather than the pipeline.
PHP's superglobals make it unambiguous -- `system("ls " . $_GET["dir"])` has the
request inside the command line, and that is critical. The other two are shapes
rather than proofs: a `subprocess` call with `shell=True` and an interpolated
string, and Node's `exec()` with a template literal in it. Both are reported at
medium confidence and high severity, because the value being interpolated may
well be a constant -- and the fix is the same either way, which is to stop using
a shell: pass a list of arguments, or call `execFile`.

Measured on n8n, that shape appears thirty-seven times, mostly a branch name or
a process id going into a build script. None of those is exploitable today and
every one of them is one refactor away from taking a value from somewhere else,
which is exactly what medium confidence is for: `--min-confidence high` does not
show them, and a review reading everything does.

A finding in a fixture tree drops a step of confidence, for the same reason the
secrets rules do it: a test that talks to a server with a self-signed
certificate is the ordinary reason any of these idioms appears, and an
end-to-end suite is mostly that. Measured on ingress-nginx, sixteen findings,
every one of them under `test/e2e`. Weakened rather than dropped -- the idiom
copied out of a test into the client it exercises is exactly how it ships.

The limits are the usual ones and they are real. There is no parser here: a
construct spread over several lines is invisible, a helper called
`insecure_session()` is invisible, and a value arriving through a variable is
invisible. A clean report from this family means "none of these idioms
appears", which is a smaller claim than "this code verifies certificates".

## Terraform

| Rule | Finds | Severity |
| --- | --- | --- |
| TF001 | Security group admits `0.0.0.0/0` | critical to an admin port, otherwise high |
| TF002 | Storage granted to the public or to every account | high |
| TF003 | Encryption at rest explicitly switched off | medium |
| TF004 | Policy allows every action on every resource | high |
| TF005 | Managed database given a public endpoint | high |
| TF006 | Terraform state stored without encryption | medium |
| TF007 | Service accepts unencrypted connections | high |
| TF008 | Policy names every principal, or every account | high |

These read block structure rather than lines, through a small HCL reader that
knows a line ending in `{` opens a block and that braces inside strings,
comments and heredocs are not braces at all. The difference is the whole rule:
`cidr_blocks` in an `egress` block is not a finding, `encrypted = false` inside
`root_block_device` is a different finding from the same words at the top of a
resource, and a wildcard action only counts when the statement's effect is
`Allow`. TF001 grades on what the port range exposes, so `0.0.0.0/0` to 22 is
critical and names SSH while `0.0.0.0/0` to 443 is high. TF001 is asked of every cloud, in each one's spelling: AWS security groups and
network ACLs, `azurerm_network_security_rule` (where "anywhere" is written `*`
or the service tag `Internet`), and `google_compute_firewall`. It reads all four
spellings AWS has accumulated: a nested `ingress` block, `aws_security_group_rule`,
`aws_vpc_security_group_ingress_rule`, and `aws_network_acl_rule`, which calls
the attribute `cidr_block` in the singular and marks direction with `egress`.

What none of this can do is evaluate Terraform. A CIDR arriving through a
variable, a `for_each` over a map of rules, a module whose defaults live
somewhere else: all invisible. A clean report means the literal, obvious form
of each mistake is absent.

TF008 is TF004's other half. TF004 says the principal may do anything; TF008
says anybody may be the principal -- `identifiers = ["*"]`, or `"Principal":
"*"` in a JSON policy. On a role's trust policy that is any AWS account
assuming the role; on a bucket or a key policy it is any account using it. Both
spellings are read, and the JSON one is reported at medium confidence for the
same reason TF004's is: it is matched on the raw text of a heredoc the parser
deliberately did not enter.

## Ansible

| Rule | Finds | Severity |
| --- | --- | --- |
| AN001 | Task skips certificate verification | high |
| AN002 | Task sets a world-writable file mode | medium |
| AN003 | Task fetches over plain HTTP | medium |

Ansible is where a decision made once is applied to every host, which cuts both
ways: a task that skips certificate verification skips it fleet-wide, and a
mode of `0777` is world-writable on every machine the play touches.

Three rules, narrow on purpose. Ansible's idioms make most "insecure" patterns
ambiguous -- `become: yes` is how the tool works, and templating a variable
into a shell command is usually fine because the variable came from the
inventory rather than from a stranger. What is left is the small set of things
that are wrong wherever they appear.

Playbooks are recognised by shape, since Ansible imposes no naming convention
worth trusting: a list of mappings carrying plays or tasks, with a vocabulary
check, because a list of mappings is also what a Compose override, a Kustomize
patch and half of CI configuration look like. Findings name the task they
belong to, including inside a `block`.

## CloudFormation

| Rule | Finds | Severity |
| --- | --- | --- |
| CF001 | Security group admits `0.0.0.0/0` | critical to an admin port, otherwise high |
| CF002 | Bucket granted to the public | high |
| CF003 | Encryption at rest explicitly switched off | medium |
| CF004 | Policy allows every action on every resource | high |
| CF005 | Managed database given a public endpoint | high |
| CF006 | Policy names every principal, or every account | high |

These are the Terraform rules in AWS's other vocabulary. The mistakes do not
care which tool describes them -- a security group admitting `0.0.0.0/0` to
port 22 is the same security group in HCL or in YAML -- and a repository using
both should not have to choose which half gets audited.

Both spellings are read. YAML templates go through the YAML reader, JSON ones
through a small JSON reader that keeps line numbers, and both produce the same
nodes -- so the rules never learn which they are looking at. Intrinsic
functions come through as text, which is the behaviour worth having: `CidrIp:
!Ref AllowedRange` is decided at deploy time, so no rule draws a conclusion
from it.

CF006 is TF008 in the other vocabulary, and exists for the same reason the
whole CloudFormation family does: the mistakes are identical and the spelling
is not. `Principal: "*"` and `Principal: {AWS: "*"}` are both anybody; a
Service principal is a named one, and is how half of AWS works.

## Kubernetes

| Rule | Finds | Severity |
| --- | --- | --- |
| K8S001 | Container runs privileged | critical |
| K8S002 | Volume mounts a path from the node | critical for a runtime socket, otherwise high |
| K8S003 | Pod shares a namespace with the node | high |
| K8S004 | Container declares no resource limits | low |
| K8S005 | Container declares that it runs as root | medium |
| K8S006 | Privilege handed back after being dropped | high |
| K8S007 | Credential committed inside a Secret manifest | critical |
| K8S008 | Container image tag can point elsewhere tomorrow | medium |
| K8S009 | Role grants every verb on every resource | critical for a ClusterRole |
| K8S010 | Binding grants to anonymous or all authenticated users | critical |
| K8S011 | Container port bound on the node itself | high for a privileged port |
| K8S012 | Syscall or AppArmor confinement switched off by name | high |

Manifests are found by content, not by filename: a Kubernetes document is one
with `apiVersion` and `kind` at its root, in YAML or in JSON. That beats guessing at `deploy/`,
`k8s/`, `manifests/` and `charts/templates/`, and it means a workflow file that
happens to live in one of them is correctly ignored.

Containers are found by walking for the container list keys rather than by
knowing the shape of each workload kind, so a Pod, a Deployment, a CronJob and
a custom resource that embeds a pod template are all covered by the same rules.

Helm charts are read too. A chart is not YAML -- `{{- if .Values.rbac }}` is a
control line belonging to no mapping, and `{{ .Values.image }}` is a value that
does not exist yet -- so template expressions are replaced with a placeholder
and control lines are blanked, keeping every remaining line at its original
number. What comes out is not the manifest that will be installed; it is the
part of it that is written down. So the rules that read a value the chart
contains still run (`privileged: true` in a chart is `privileged: true` when it
is installed), and the two that conclude something from a value's *absence* --
missing limits, a floating tag -- do not, because the values file supplies both
and neither is in front of us.

K8S009 and K8S010 are the RBAC pair, and they are TF004's cousins. A role with
`verbs: ["*"]` on `resources: ["*"]` is indistinguishable from cluster-admin:
whoever holds it can read every Secret in the cluster and grant themselves the
rest. A binding whose subject is `system:anonymous`, `system:unauthenticated`
or `system:authenticated` hands that to a category of everybody rather than to
a workload -- the last of those is every service account in the cluster, which
surprises people.

K8S007 decodes what it finds. A `Secret` stores values base64-encoded, which is
not encryption but is enough to hide a credential from every rule that reads
lines; when the decoded value is a shape the secret rules recognise, the
finding says which and is critical.

The family also reads a chart's **values file** -- `values.yaml` and its
`values-production.yaml` relatives -- but only where a `Chart.yaml` sits beside
it, because every application repository has a `values.yaml` somewhere. A
values file has no `apiVersion`, no `kind` and no containers, so the manifest
rules never look at it; what it does have is the settings the chart hands to
its templates, and a handful of those carry their meaning with them.
`privileged: true` under a `securityContext` is the container setting wherever
it is written, because that is the only thing a chart can do with a key of that
name. Six settings are read this way -- privileged, allowPrivilegeEscalation,
added capabilities, an Unconfined seccomp profile, the three host namespaces,
and a hostPath volume -- all at medium confidence, since the chart *should*
pass them through and this reader has not read the template that does. A
`hostPath` block with no `path` in it is a configuration section rather than a
volume: Dagger's chart has one whose keys are `dataVolume` and `runVolume`.

A `CustomResourceDefinition` is skipped whole. It carries an OpenAPI schema,
and a schema names every field a resource may have -- `hostPath`,
`privileged`, `capabilities` -- as keys, which is how a CRD comes to look like
the worst workload ever written. Nothing in one runs.

K8S012 reads the two places a manifest can switch confinement off by name: a
`seccompProfile` of `Unconfined`, and the AppArmor annotation set to
`unconfined`. Neither is a change of behaviour on a cluster with no Pod
Security Standard -- unconfined is what you already had -- which is exactly why
the written-down version is worth reporting: somebody needed it, usually for
one syscall, and it removes the filter from all of them. A profile set at pod
level is reported as the pod's, once, rather than again for every container
underneath it.

## Docker Compose

| Rule | Finds | Severity |
| --- | --- | --- |
| DC001 | Service runs privileged | critical |
| DC002 | Service bind-mounts a path that grants the host | critical |
| DC003 | Service shares a host namespace | high |
| DC004 | Capability added or confinement disabled | high |
| DC005 | Sensitive port published on every interface | high |
| DC006 | Service image tag can point elsewhere tomorrow | low |

DC005 is the one people are most often surprised by. `5432:5432` publishes
PostgreSQL on every interface the host has, firewall permitting, and on a cloud
instance that means the internet; `127.0.0.1:5432:5432` is the same line with
the mistake removed. It fires only for ports worth shouting about -- a server on
443 open to the world is the point of it. DC002 is scoped the same way: mounting
the project directory is how everyone develops, so only the paths that grant the
host are reported, the container runtime socket chief among them.

