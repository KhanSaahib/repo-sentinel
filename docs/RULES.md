# Rules

Every check repo-sentinel makes, what it is looking for, and why that thing is
worth a build failure. `repo-sentinel rules` prints the same list from the tool
itself, with `--format json` if you want to diff it between releases.

The test suite asserts that this file, the rule catalogue in `rules.py` and the
scanners all agree: a rule missing from any of the three fails the build.

For what the severity and confidence columns mean, see
[Severity and confidence](../README.md#severity-and-confidence) in the README.

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
| SEC022 | Provider credential hidden inside base64 | varies | high |
| SEC100 | High-entropy value in a quoted assignment | high | medium |
| SEC101 | High-entropy value in an unquoted config value | high | medium |
| SEC900 | Suppression block opened and never closed | medium | high |

SEC900 is not a class of secret; it reports a suppression block that was opened
and never closed. See [Suppressing a false positive](#suppressing-a-false-positive).

SEC001–SEC020 match on documented token structure. Two of them are looser than
the rest and say so through their confidence: SEC014 is a two-letter prefix in
front of 32 hex characters, and SEC020 is any `scheme://user:password@host`.

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
| FN003 | A file whose purpose is to hold a credential | medium |

Every other rule here reads text, which makes them all blind to the files that
have none. A committed `id_rsa` has no line to match; a `.p12`, a `.jks`, a
`.pfx` are binary and skipped before any rule sees them. These are among the
worst things a repository can contain and the easiest for a scanner to miss, so
the walk reports every path it reaches, readable or not, and these three rules
work from the names.

They claim less than the others, and say so through confidence. `.pem` and
`.key` are private keys about as often as they are certificates, so FN002 fires
only when the file could *not* be read -- if it is text, SEC004 has already
looked inside and its answer is better than a guess about the name. Files under
`fixtures/` or `testdata/` are reported at low confidence rather than not at
all. And `.example`, `.sample`, `.template` and `.dist` suffixes are skipped
everywhere: a repository documenting the shape of its `.env` is doing the right
thing.

## GitHub Actions workflows

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
| WF009 | Checkout leaves a usable token in `.git/config` | high |
| WF010 | Secret written to a job output or environment | high |

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

WF009 is scoped on purpose. `actions/checkout` leaves the job's token in the
working copy unless told otherwise, which is tolerable on a workflow that only
runs your own code and is not tolerable under `pull_request_target` or
`workflow_run` -- triggers that exist precisely to run in a context an outsider
influenced. Reporting every checkout in the world would get the rule switched
off. WF010 catches a secret written to `$GITHUB_OUTPUT` or `$GITHUB_ENV`, where
it outlives the step, reaches later jobs and calling workflows, and stops being
covered by log masking the moment it is transformed.

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

## Terraform

| Rule | Finds | Severity |
| --- | --- | --- |
| TF001 | Security group admits `0.0.0.0/0` | critical to an admin port, otherwise high |
| TF002 | Storage granted to the public or to every account | high |
| TF003 | Encryption at rest explicitly switched off | medium |
| TF004 | Policy allows every action on every resource | high |
| TF005 | Managed database given a public endpoint | high |
| TF006 | Terraform state stored without encryption | medium |

These read block structure rather than lines, through a small HCL reader that
knows a line ending in `{` opens a block and that braces inside strings,
comments and heredocs are not braces at all. The difference is the whole rule:
`cidr_blocks` in an `egress` block is not a finding, `encrypted = false` inside
`root_block_device` is a different finding from the same words at the top of a
resource, and a wildcard action only counts when the statement's effect is
`Allow`. TF001 grades on what the port range exposes, so `0.0.0.0/0` to 22 is
critical and names SSH while `0.0.0.0/0` to 443 is high.

What none of this can do is evaluate Terraform. A CIDR arriving through a
variable, a `for_each` over a map of rules, a module whose defaults live
somewhere else: all invisible. A clean report means the literal, obvious form
of each mistake is absent.

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

Manifests are found by content, not by filename: a Kubernetes document is one
with `apiVersion` and `kind` at its root. That beats guessing at `deploy/`,
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

K8S007 decodes what it finds. A `Secret` stores values base64-encoded, which is
not encryption but is enough to hide a credential from every rule that reads
lines; when the decoded value is a shape the secret rules recognise, the
finding says which and is critical.

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

