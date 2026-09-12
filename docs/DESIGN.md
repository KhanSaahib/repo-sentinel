# Design

How the pieces fit, and why they are shaped the way they are. This is for
someone about to change the code; [RULES.md](RULES.md) is for someone about to
read a finding.

## The pipeline

```
discovery.walk ──► Entry(path, text|None)
                        │
                        ├─► scanners.filenames      (names, including binaries)
                        ├─► scanners.secrets        (every text file)
                        └─► the format scanners     (each filters by content)
                                    │
                                    ▼
                              list[Finding]
                                    │
                        engine.collapse ──► sort ──► CLI filters ──► report
```

Four things happen in that order and the order matters:

**The walk yields every path it reaches**, with text where it could read it and
`None` where it could not. Before that, a binary was dropped before any rule
saw it, which made a committed `id_rsa` or `.p12` invisible. A scanner that
only ever sees text cannot report a file that has none.

**Each scanner decides for itself whether a file is its business**, and mostly
by content rather than by path. A Kubernetes manifest is a document with
`apiVersion` and `kind`; a Compose file is one with a `services` map and no
`apiVersion`; a GitLab pipeline is one named `.gitlab-ci.yml` *or* one whose
top-level keys carry scripts. Directory conventions are guesses, and a workflow
file living in `k8s/` is not a workload.

**`engine.collapse` drops the second report of one problem.** Scanners overlap
deliberately -- a credential inside a Kubernetes `Secret` is both a manifest
problem and a secret -- and each rule says something the other cannot. What
collapses is an explicit `subject`: the redacted credential. Nothing else
participates, because two rules can legitimately report the same line for
different reasons, and an earlier version keyed on evidence text quietly ate
findings that way.

The same subject in the same file is then folded across lines and counted.
One credential is one thing to rotate however many times it was pasted, and
Discourse has a presigned URL in a fixture whose access key id appears on 758
lines. Findings *without* a subject are never folded, because there each line
is its own edit: five unpinned actions in one workflow are five pins to write.

**Filtering happens after scanning, never during.** Severity, confidence,
disabled rules and the baseline are all decisions about which findings to
*show*. Keeping them out of the scanners means a rule cannot accidentally
become unreachable, and means every filter can report what it hid.

## The three readers

`hcl`, `yamlish` and `jsonish` exist because most rules ask questions about a
*block*, and a line cannot answer them. `privileged: true` under
`securityContext` is critical and the same line under `annotations` is nothing;
`cidr_blocks` in an `ingress` block is a finding and in `egress` it is normal.

None of them is a parser, and each says so in its module docstring. The rule
they follow is that **unknown structure degrades to a scalar**, never to a wrong
shape: a flow collection, an anchor, a tag comes through as text, so a rule
looking for nesting finds none and stays quiet. Silence is the safe direction
for a parser this small, and it is the only direction that lets the zero
dependency rule survive contact with real files.

Line numbers are carried on every node. A finding that points at the wrong line
of a Helm chart is worse than no finding, which is why template flattening
replaces expressions in place rather than deleting them.

## Severity and confidence

They answer different questions and collapsing them loses both.

*Severity* is what the finding costs if it is real. *Confidence* is how sure
the rule is that it is. A documented token shape is high confidence; entropy
next to a variable named `api_key` is a guess and says so.

Two consequences worth knowing before touching a rule:

- The catalogue's severity is the **worst case**, asserted by a test. A rule
  may grade itself down by context -- TF001 is critical at port 22 and high at
  443 -- but never up past what the catalogue promises.
- Confidence is weighed by **where a file sits**. A rule already at medium
  drops to low in fixture trees and documentation, because a credential in
  `testdata/` or a README is usually invented. The config families are weighed
  the same way for a different reason: a pipeline under `docs/` is a snippet in
  a tutorial, and nothing schedules it. Nothing is silenced either way: a real
  key does get committed to a fixture directory, and repositories do ship the
  manifest they actually apply inside their documentation tree.

If you find yourself lowering a severity because a rule is unreliable, lower
the confidence instead. That is what it is for.

## Five CI systems, one bug

GitHub expands `${{ github.event.issue.title }}`, GitLab expands
`$CI_COMMIT_TITLE`, Azure expands `$(Build.SourceVersionMessage)`, CircleCI
expands `$CIRCLE_BRANCH`, and Groovy expands `${env.BRANCH_NAME}` -- each into
the command line, before the shell parses it, each from a value an outside
contributor writes. The syntax differs; the bug does not.

Jenkins is the one that does not share the machinery, because its pipelines are
Groovy rather than YAML, and it earns its own rule anyway: there the *quoting*
decides whether the interpolation happens at all.

`scanners/ci.py` holds the parts that do not depend on syntax: finding the
shell lines in a step, and the list of fields that cannot carry an injection.
Each scanner keeps its own pattern and vocabulary, because those are exactly
what differ. The reason to share the rest is not brevity -- it is that a fix
found in one system belongs in all of them, and the harmless-fields list was
written for GitHub and then written again, identically, for Azure.

## Configuration, and the one family that is not

Every family but one reads configuration, and that is a deliberate line.
Configuration says what a system *is*, so a reader that understands its shape
can answer a question about it exactly: `privileged: true` under
`securityContext` means one thing and there is nothing else it could mean.

Code says what a system *does*, and answering a question about that needs
something this tool does not have -- a parser, a call graph, and a notion of
which values reach which calls. So the application-code family
(:mod:`scanners.appcode`) asks a smaller question on purpose: does this file
contain one of three idioms whose meaning is fixed, in a language where that
spelling means what it looks like? `verify=False` is a Python spelling; the
same characters in a Go file are a guess, so the rule does not apply there.

That smallness is the point. A clean report from that family means "none of
these idioms appears", and the documentation says so in those words rather
than implying a coverage that would need a compiler.

## Two gates in front of the patterns

Almost no line in a repository contains a credential, and the scanner's cost is
dominated by proving that about each one. So the secret rules run behind two
cheap questions.

The first is one small pattern: does this line have a fourteen-character run of
credential characters, a PEM header, or a URL carrying a password? Four fifths
of lines do not. The second is per rule: does the line contain any of the
literals that rule's shape must include -- `AKIA`, `ghp_`, `xoxb-`? Nine of the
remaining lines in ten do not.

The entropy rules have a gate of their own, and it is the same idea a third
time: both ultimately need a name carrying one of a dozen words, so a flat
alternation of those words runs first. It is cheap because there is nothing in
it to backtrack over, and the patterns it stands in front of are the opposite
-- each has a greedy character class before its alternation, so the engine
retries at every position on a line that was never going to match. Nine lines
in ten of a source tree mention none of the words.

Both are correctness risks as much as speed wins, because a line a gate rejects
is never looked at again, and a hint absent from what a pattern matches
disables that rule silently. The corpus test is what makes them safe: every
rule must fire on a line carrying its own shape, so a bad gate or a bad hint
fails the build rather than quietly removing a rule.

## The catalogue

`rules.py` lists every rule, and the scanners hold the detection logic and the
remediation text. That duplication is deliberate and defended by a test with
three assertions: every rule a scanner emits is in the catalogue, every
catalogue entry is reachable from a scanner, and every rule appears in
`docs/RULES.md`. A corpus in `tests/corpus.py` trips all of them.

The effect is that a rule cannot ship undocumented, a deleted rule cannot leave
its entry behind, and the README's tables cannot describe the release before
last. Adding a rule means touching four places, and the build says which one
you forgot.

## Suppression and configuration

Three scopes of marker -- line, block, file -- each able to name the rules it
means (`# repo-sentinel: ignore[K8S008]`). A configuration file supplies
defaults, including rules disabled globally or under a glob.

Two invariants hold across all of it:

- **The command line always wins.** A config file can never stop somebody
  auditing their own repository more strictly than the project usually does.
- **A gap in the scan is reported, not swallowed.** A directory the process
  cannot open is skipped -- a scanner that dies on one permission error is
  useless in CI -- but the run says how many paths that happened to. "No
  findings" from a tree that was never read is the most dangerous answer this
  tool can give.
- **Silence is always counted, and can always be read past.** A disabled rule,
  a baselined finding, a suppressed line: each is reported as a number in the
  output, and each has a flag that ignores it -- `--disable` is answered by the
  count, the baseline by `--write-baseline`, the markers by `--no-suppression`,
  `.gitignore` by `--no-gitignore`, and the example allowlist by
  `--no-example-allowlist`. Silence nobody can see is the failure this whole
  tool exists to avoid, and a scanner that can be switched off invisibly is
  worse than no scanner.

The unterminated suppression block is the same principle as a rule: SEC900
reports a marker that silences the rest of a file, because otherwise the file
goes quiet and looks clean.

## No dependencies

Not one, at runtime. A tool pointed at your supply chain should not enlarge it,
and the constraint has been good for the design: it is why the scanners read
structure the way a reviewer skims it rather than building trees nobody asked
for, and why the coverage tool in `tools/` is fifty lines of `dis` and
`sys.settrace`.

What it costs is stated where a user can see it: exotic formatting slips past,
JSON CloudFormation templates are not read, and a value arriving through a
variable is invisible. A scanner that implies more coverage than it has is
worse than one that admits its edges.

## Adding a rule

1. Detection in the scanner for that format. Provider patterns are data; the
   structural rules are functions taking a parsed block.
2. An entry in `rules.py`.
3. A fixture in `tests/corpus.py` that trips it.
4. A row in `docs/RULES.md`.
5. Tests for what it should *not* match -- which matters more than the positive
   case, because that is why anyone still has it switched on next quarter.
6. `python3 tools/measure.py` over real repositories before trusting a
   heuristic. Every false positive this project has fixed came from reading
   real output, and not one was imagined in advance.
