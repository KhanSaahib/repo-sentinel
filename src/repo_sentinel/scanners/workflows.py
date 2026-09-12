"""Audit GitHub Actions workflow files for well-known footguns.

These checks are deliberately pattern-based rather than YAML-aware: the whole
tool is standard library only, and a linter that reads the file the way a
reviewer skims it catches the mistakes that actually get shipped. The trade-off
is that exotic formatting can slip past, which is why every rule here reports
what it saw rather than asserting the file is clean.

What the module does insist on is *structure*: jobs and steps are split apart
by indentation before the rules run. Without that, "does this job declare its
own permissions" and "is this secret handed to a third-party action" cannot be
asked at all -- both are questions about a block, not about a line.
"""

from __future__ import annotations

import dataclasses
import posixpath
import re
from collections.abc import Iterable, Iterator

from .. import suppression
from . import ci
from ..findings import Confidence, Finding, Severity

_WORKFLOW_DIR = ".github/workflows"
_WORKFLOW_SUFFIXES = (".yml", ".yaml")
#: A composite action is a workflow fragment by another name: the same steps,
#: the same interpolation, run inside whichever repository calls it.
_ACTION_FILES = ("action.yml", "action.yaml")
_COMPOSITE = re.compile(r"^\s*using:\s*['\"]?composite")
_INPUT_EXPR = re.compile(r"\$\{\{\s*inputs\.(?P<name>[\w-]+)[^}]*\}\}")

_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?(?P<ref>[^\s'\"#]+)")
_SHA_PIN = re.compile(r"^[0-9a-f]{40}$")
_LOCAL_ACTION = re.compile(r"^(?:\./|docker://)")
_RUN_START = re.compile(r"^(?P<indent>\s*)(?:-\s*)?run:\s*(?P<inline>.*)$")
_TOP_LEVEL_PERMISSIONS = re.compile(r"^permissions:")
_PERMISSIONS = re.compile(r"^\s*permissions:\s*(?P<inline>\S*)")
_WRITE_ALL = re.compile(r"^\s*permissions:\s*write-all\s*$")
_PULL_REQUEST_TARGET = re.compile(r"^\s*(?:-\s*)?pull_request_target\b")
_WORKFLOW_RUN = re.compile(r"^\s*(?:-\s*)?workflow_run\b")
_REF = re.compile(r"^\s*ref:\s*(?P<value>\S.*)$")
_RUNS_ON = re.compile(r"^\s*runs-on:.*\bself-hosted\b")
_SECRET_REFERENCE = re.compile(r"\$\{\{\s*secrets\.(?P<name>[A-Za-z_][\w-]*)")
_JOBS_HEADER = re.compile(r"^jobs:\s*$")
_PERSIST_CREDENTIALS = re.compile(r"^\s*persist-credentials:\s*(?P<value>\S+)")
#: Writes that outlive the step: a job output, or the environment of every
#: later step in the job.
_EXPORTS = re.compile(r"\$GITHUB_OUTPUT|\$GITHUB_ENV|::set-output|::set-env")
_BLOCK_KEY = re.compile(r"^(?P<indent>\s+)(?P<name>[A-Za-z_][\w-]*):\s*(?P<inline>.*)$")
_STEP_START = re.compile(r"^(?P<indent>\s*)-\s+\S")
#: A reusable workflow call sits directly under the job, with no list dash:
#: a step's ``uses:`` is a different thing entirely.
_JOB_USES = re.compile(r"^\s*uses:\s*['\"]?(?P<ref>[^\s'\"#]+)")
_SECRETS_INHERIT = re.compile(r"^\s*secrets:\s*inherit\s*$")

#: Action owners whose code already runs with the repository's own trust.
#: Everything else is a third party, however popular.
_FIRST_PARTY_OWNERS = frozenset({"actions", "github"})

#: Fields of an otherwise untrusted context that cannot carry an injection --
#: a pull request number is an integer, a commit sha is forty hex characters,
#: and GitHub decides both. Shared with the other CI scanners, because this
#: lesson was learned here and then learned again, identically, on Azure.
_HARMLESS_FIELDS = ci.HARMLESS_FIELDS

#: Contexts an outside contributor can write to. Interpolating any of these
#: into a shell command hands them the runner.
_UNTRUSTED = re.compile(
    r"""\$\{\{\s*
    (?P<expr>
        github\.head_ref
      | github\.event\.(?:issue|pull_request|comment|review|discussion
                        |head_commit|commits|workflow_run|pages)\b[^}]*
    )
    \s*\}\}""",
    re.VERBOSE,
)

#: Ref expressions that resolve to code the triggering party controls.
_UNTRUSTED_REF = re.compile(
    r"github\.(?:head_ref|event\.(?:pull_request\.head|workflow_run\.head))", re.IGNORECASE
)


def is_workflow_path(path: str) -> bool:
    """True for files GitHub will actually execute as workflows."""
    normalised = path.replace("\\", "/")
    return (
        posixpath.dirname(normalised).endswith(_WORKFLOW_DIR)
        and normalised.endswith(_WORKFLOW_SUFFIXES)
    )


def is_action_path(path: str) -> bool:
    """True for an action definition, wherever in the tree it lives."""
    return posixpath.basename(path.replace("\\", "/")).lower() in _ACTION_FILES


Block = list  # of (line_number, text)


@dataclasses.dataclass(frozen=True)
class Job:
    """One entry under ``jobs:``, with the lines that belong to it."""

    name: str
    line: int
    indent: int
    body: "Block"

    def matches(self, pattern: "re.Pattern[str]") -> bool:
        return any(pattern.match(text) for _, text in self.body)


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip())


def iter_jobs(lines: list[str]) -> Iterator[Job]:
    """Split a workflow into its jobs, by indentation.

    A job runs from its ``name:`` key until the next line indented no further
    than that key. Anything before ``jobs:`` -- triggers, top-level
    ``permissions``, ``env`` -- belongs to no job and is checked separately.
    """
    try:
        start = next(index for index, line in enumerate(lines) if _JOBS_HEADER.match(line))
    except StopIteration:
        return

    index = start + 1
    job_indent = None
    while index < len(lines):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            index += 1
            continue
        indent = _indent_of(line)
        if indent == 0:  # back out to a top-level key: jobs: is over
            return
        header = _BLOCK_KEY.match(line)
        if header is None or (job_indent is not None and indent != job_indent):
            index += 1
            continue
        job_indent = indent
        name, header_line = header.group("name"), index + 1

        body: "Block" = []
        index += 1
        while index < len(lines):
            current = lines[index]
            if current.strip() and _indent_of(current) <= job_indent:
                break
            body.append((index + 1, current))
            index += 1
        yield Job(name, header_line, job_indent, body)


def _iter_steps(body: "Block") -> Iterator["Block"]:
    """Split a job body into its steps, by the indent of the list dashes.

    Only the outermost dash level counts as a step boundary; a nested list
    inside ``with:`` is part of the step it sits in.
    """
    dashes = [
        _indent_of(text) for _, text in body if _STEP_START.match(text)
    ]
    if not dashes:
        return
    step_indent = min(dashes)

    current: Block = []
    for number, text in body:
        if _STEP_START.match(text) and _indent_of(text) == step_indent:
            if current:
                yield current
            current = []
        if current or _STEP_START.match(text):
            current.append((number, text))
    if current:
        yield current


def _step_action(step: "Block") -> "str | None":
    """The action a step uses, or None for a step that runs a command.

    Written once because two rules ask it, and because the obvious inline
    version runs the pattern twice per line -- once to test and once to read.
    """
    for _, text in step:
        match = _USES.match(text)
        if match is not None:
            return match.group("ref")
    return None


def _iter_run_lines(lines: list[str]) -> Iterator[tuple[int, str]]:
    """Yield ``(line_number, text)`` for every line inside a ``run:`` block."""
    index = 0
    while index < len(lines):
        match = _RUN_START.match(lines[index])
        if not match:
            index += 1
            continue

        inline = match.group("inline").strip()
        if inline and not inline.startswith(("|", ">")):
            yield index + 1, lines[index]
            index += 1
            continue

        # Block scalar: everything indented deeper than `run:` belongs to it.
        base_indent = len(match.group("indent"))
        index += 1
        while index < len(lines):
            line = lines[index]
            if line.strip() and (len(line) - len(line.lstrip())) <= base_indent:
                break
            yield index + 1, line
            index += 1


def _action_owner(ref: str) -> str:
    return ref.split("/", 1)[0].lower()


def _check_action_pinning(path: str, lines: list[str]) -> Iterator[Finding]:
    """WF001: an action referenced by anything a third party can move.

    Graded by who can move it. A tag on somebody else's action is code you do
    not control changing under you, which is the whole rule; a tag on
    ``actions/checkout`` is GitHub changing GitHub, on the runner GitHub
    already gave you. Still reported -- pinning everything is the advice, and
    an organisation that pins one and not the other has decided rather than
    forgotten -- but not at the same weight, because a workflow file with
    eleven of these teaches people to skip the eleven.
    """
    for number, line in enumerate(lines, start=1):
        match = _USES.match(line)
        if not match:
            continue
        ref = match.group("ref")
        if _LOCAL_ACTION.match(ref):
            continue
        _, _, version = ref.partition("@")
        first_party = _action_owner(ref) in _FIRST_PARTY_OWNERS
        severity = Severity.LOW if first_party else Severity.MEDIUM
        whose = (
            "GitHub can move this tag; everything else about the runner is "
            "already theirs, so this is the smaller half of the rule. "
            if first_party
            else "Tags can be moved to point at new code, by whoever owns it. "
        )
        if not version:
            yield Finding(
                rule_id="WF001",
                severity=severity,
                title=f"Action {ref!r} has no version reference",
                path=path,
                line=number,
                evidence=line.strip(),
                remediation="Pin the action to a full 40-character commit SHA.",
            )
        elif not _SHA_PIN.match(version):
            yield Finding(
                rule_id="WF001",
                severity=severity,
                title=f"Action {ref!r} is pinned to a mutable tag",
                path=path,
                line=number,
                evidence=line.strip(),
                remediation=(
                    whose + "Pin to a full commit SHA and let Dependabot "
                    "propose upgrades."
                ),
            )


def _check_permissions(path: str, lines: list[str], jobs: list[Job]) -> Iterator[Finding]:
    """WF002 and WF005: how much of the repository the GITHUB_TOKEN can rewrite.

    WF002 is asked per job rather than per file, because a job that declares
    its own ``permissions`` is already explicit and a file-level warning about
    it is just noise. A workflow with no jobs at all still gets one report, so
    that an unparseable file is never silently treated as compliant.

    When *no* job declares permissions the report is one finding for the file,
    because the fix is one top-level block however many jobs there are.
    Measured on authentik: four jobs in a file meant four copies of the same
    one-line instruction, which is how a rule teaches people to skip its
    output. A file where some jobs are explicit and others are not is reported
    per job, because there the fix genuinely is per job.
    """
    for number, line in enumerate(lines, start=1):
        if _WRITE_ALL.match(line):
            yield Finding(
                rule_id="WF005",
                severity=Severity.HIGH,
                title="Workflow grants write-all permissions to the GITHUB_TOKEN",
                path=path,
                line=number,
                evidence=line.strip(),
                remediation=(
                    "write-all includes contents, packages, deployments and more. "
                    "List only the scopes the job uses."
                ),
            )

    if any(_TOP_LEVEL_PERMISSIONS.match(line) for line in lines):
        return

    if not jobs:
        yield _missing_permissions(path, 1, "no top-level 'permissions:' block")
        return

    silent = [job for job in jobs if not job.matches(_PERMISSIONS)]
    if not silent:
        return
    if len(silent) == len(jobs) > 1:
        yield _missing_permissions(
            path,
            silent[0].line,
            f"{len(silent)} jobs inherit the default token permissions",
        )
        return
    for job in silent:
        yield _missing_permissions(
            path, job.line, f"job {job.name!r} inherits the default token permissions"
        )


def _missing_permissions(path: str, line: int, evidence: str) -> Finding:
    return Finding(
        rule_id="WF002",
        severity=Severity.MEDIUM,
        title="Workflow does not declare GITHUB_TOKEN permissions",
        path=path,
        line=line,
        evidence=evidence,
        remediation=(
            "Add a top-level 'permissions: contents: read' block and widen it "
            "per job only where a job needs more."
        ),
    )


def _check_script_injection(path: str, lines: list[str]) -> Iterator[Finding]:
    """WF003: attacker-controlled text substituted into a shell command."""
    for number, line in _iter_run_lines(lines):
        for match in _UNTRUSTED.finditer(line):
            expression = match.group("expr").strip()
            if expression.rsplit(".", 1)[-1] in _HARMLESS_FIELDS:
                continue
            yield Finding(
                rule_id="WF003",
                severity=Severity.CRITICAL,
                title=f"Untrusted input {match.group('expr')} interpolated into a shell command",
                path=path,
                line=number,
                evidence=line.strip(),
                remediation=(
                    "Pass the value through an env: block and reference it as "
                    '"$VAR" so the shell never parses attacker-controlled text.'
                ),
            )


def _check_privileged_checkout(path: str, lines: list[str]) -> Iterator[Finding]:
    """WF004 and WF008: a privileged trigger checking out someone else's code.

    ``pull_request_target`` and ``workflow_run`` both run from the base branch
    with the repository's secrets available. Checking out the head of the pull
    request that triggered them puts a fork's code inside that trust boundary,
    which is the single most exploited GitHub Actions mistake there is.
    """
    triggers = (
        ("WF004", "pull_request_target", _PULL_REQUEST_TARGET),
        ("WF008", "workflow_run", _WORKFLOW_RUN),
    )
    for rule_id, name, pattern in triggers:
        if not any(pattern.match(line) for line in lines):
            continue
        for number, line in _checked_out_refs(lines):
            yield Finding(
                rule_id=rule_id,
                severity=Severity.CRITICAL,
                title=f"{name} checks out untrusted code",
                path=path,
                line=number,
                evidence=line.strip(),
                remediation=(
                    f"{name} runs with repository secrets. Checking out the "
                    "triggering party's head commit lets them execute code with "
                    "those secrets. Check out the base ref, and move any build of "
                    "untrusted code to a pull_request workflow."
                ),
            )
            break


def _checked_out_refs(lines: list[str]) -> Iterator[tuple[int, str]]:
    """Yield ``ref:`` lines that hand a checkout a caller-controlled commit.

    Two ways to qualify: the ref sits in a step that uses ``actions/checkout``,
    or its value names an untrusted context outright. The second case catches
    the checkout actions this list has never heard of.
    """
    checkout_indent: int | None = None
    for number, line in enumerate(lines, start=1):
        match = _USES.match(line)
        if match is not None:
            ref = match.group("ref")
            checkout_indent = _indent_of(line) if ref.startswith("actions/checkout") else None
        ref_match = _REF.match(line)
        if ref_match is None:
            continue
        if _UNTRUSTED_REF.search(ref_match.group("value")):
            yield number, line
        elif checkout_indent is not None and _indent_of(line) > checkout_indent:
            yield number, line


def _check_runners(path: str, lines: list[str]) -> Iterator[Finding]:
    """WF006: a self-hosted runner, which outlives the job that ran on it."""
    for number, line in enumerate(lines, start=1):
        if _RUNS_ON.match(line):
            yield Finding(
                rule_id="WF006",
                severity=Severity.MEDIUM,
                title="Job runs on a self-hosted runner",
                path=path,
                line=number,
                evidence=line.strip(),
                remediation=(
                    "Self-hosted runners keep state between jobs, so anything a "
                    "workflow leaves behind is available to the next one. On a "
                    "public repository, a fork's pull request can reach it. Use "
                    "ephemeral runners, and never pair one with a privileged trigger."
                ),
                confidence=Confidence.MEDIUM,
            )


def _check_secret_handoff(path: str, jobs: list[Job]) -> Iterator[Finding]:
    """WF007: a secret passed to a third-party action that is not pinned.

    An action's inputs are visible to the action's own code, so handing one a
    secret extends that secret's blast radius to the action's supply chain.
    That is often necessary -- pushing an image needs a registry password --
    so what the rule actually asks is whether the recipient can change under
    you. An action pinned to a commit SHA is code somebody chose and can
    review; an action pinned to a tag is whatever its owner moves the tag to
    tomorrow, and handing that a secret is the combination worth reporting.

    Both halves matter: WF001 already says the tag is mutable, and this says
    what is being trusted to it.
    """
    for job in jobs:
        for step in _iter_steps(job.body):
            uses = _step_action(step)
            if uses is None or _LOCAL_ACTION.match(uses):
                continue
            if _action_owner(uses) in _FIRST_PARTY_OWNERS:
                continue
            _, _, version = uses.partition("@")
            if _SHA_PIN.match(version):
                continue
            for number, text in step:
                match = _SECRET_REFERENCE.search(text)
                if match is None:
                    continue
                yield Finding(
                    rule_id="WF007",
                    severity=Severity.MEDIUM,
                    title=(
                        f"Secret {match.group('name')!r} is passed to unpinned "
                        f"third-party action {uses!r}"
                    ),
                    path=path,
                    line=number,
                    evidence=text.strip(),
                    remediation=(
                        "The action reads every input it is given, and its owner "
                        "can move this tag to new code whenever they like. Pin it "
                        "to a commit SHA, review what that commit does with the "
                        "value, and prefer a scoped token over a long-lived secret."
                    ),
                    confidence=Confidence.MEDIUM,
                )
                break


def _check_persisted_credentials(path: str, lines: list[str], jobs: list[Job]) -> Iterator[Finding]:
    """WF009: a checkout that leaves a usable token in ``.git/config``.

    ``actions/checkout`` stores the job's ``GITHUB_TOKEN`` in the repository's
    git config unless told not to, so every later step in the job -- including
    a build script and everything it installs -- can push with it.

    That is a tolerable default on a workflow that only ever runs the
    repository's own code. Under ``pull_request_target`` or ``workflow_run`` it
    is not, because those triggers exist precisely to run in a context an
    outsider influenced, which is why the rule is scoped to them rather than
    reported against every checkout in the world.
    """
    privileged = any(
        pattern.match(line)
        for line in lines
        for pattern in (_PULL_REQUEST_TARGET, _WORKFLOW_RUN)
    )
    if not privileged:
        return

    for job in jobs:
        for step in _iter_steps(job.body):
            uses = _step_action(step)
            if uses is None or not uses.startswith("actions/checkout"):
                continue
            setting = next(
                (
                    (number, _PERSIST_CREDENTIALS.match(text).group("value"))  # type: ignore[union-attr]
                    for number, text in step
                    if _PERSIST_CREDENTIALS.match(text)
                ),
                None,
            )
            if setting is not None and setting[1].strip("\"'").lower() == "false":
                continue
            line = setting[0] if setting is not None else step[0][0]
            yield Finding(
                rule_id="WF009",
                severity=Severity.HIGH,
                title=f"Checkout in job {job.name!r} leaves credentials in .git/config",
                path=path,
                line=line,
                evidence=(
                    "persist-credentials is not disabled under a privileged trigger"
                ),
                remediation=(
                    "Add 'persist-credentials: false' to the checkout step. "
                    "Without it the job's token stays in the working copy, "
                    "where any script the job runs can use it to push."
                ),
            )


def _check_exported_secrets(path: str, lines: list[str]) -> Iterator[Finding]:
    """WF010: a secret written somewhere it outlives the step that knew it.

    ``echo "token=${{ secrets.X }}" >> $GITHUB_OUTPUT`` hands the value to
    every later job that consumes the output, and to the calling workflow if
    this one is reusable. Masking only covers the literal string in logs; it
    does not follow the value into a file, an artifact, or another workflow.
    """
    for number, line in _iter_run_lines(lines):
        if not _EXPORTS.search(line):
            continue
        match = _SECRET_REFERENCE.search(line)
        if match is None:
            continue
        yield Finding(
            rule_id="WF010",
            severity=Severity.HIGH,
            title=f"Secret {match.group('name')!r} is written to a job output or environment",
            path=path,
            line=number,
            evidence=line.strip(),
            remediation=(
                "Keep the secret in the step that needs it, passed through "
                "env:. A value written to GITHUB_OUTPUT or GITHUB_ENV survives "
                "the step, reaches later jobs and calling workflows, and is no "
                "longer covered by log masking once it has been transformed."
            ),
        )


def _check_inherited_secrets(path: str, jobs: list[Job]) -> Iterator[Finding]:
    """WF011: every secret in the repository handed to another repository.

    ``secrets: inherit`` on a reusable workflow call passes the whole secret
    store, not the secrets the callee declares -- there is no way to inherit
    some of them. Pointed at a workflow in the same repository that is a
    convenience; pointed at somebody else's repository it is a standing grant
    of every credential the repository holds, redeemable whenever that
    repository changes.

    Asked per job, because the call and the ``secrets:`` key are siblings
    under the same job and neither line means anything without the other.
    """
    for job in jobs:
        called = None
        inherits = False
        for number, text in job.body:
            if _indent_of(text) != job.indent + 2:
                continue  # a step's uses:, or a key of one
            match = _JOB_USES.match(text)
            if match is not None:
                called = (number, match.group("ref"))
            elif _SECRETS_INHERIT.match(text):
                inherits = True
        if called is None or not inherits:
            continue
        number, ref = called
        if _LOCAL_ACTION.match(ref):
            continue  # same repository: the secrets are already there
        _, _, version = ref.partition("@")
        pinned = bool(_SHA_PIN.match(version))
        yield Finding(
            rule_id="WF011",
            severity=Severity.HIGH,
            title=f"Job {job.name!r} passes every secret to {ref.split('@')[0]!r}",
            path=path,
            line=number,
            evidence=f"uses: {ref} with secrets: inherit",
            remediation=(
                "inherit passes the whole secret store, including the secrets "
                "this workflow has nothing to do with. Name the ones the "
                "called workflow declares instead -- 'secrets:' followed by "
                "each one -- so the grant is as small as the job."
            ),
            confidence=Confidence.MEDIUM if pinned else Confidence.HIGH,
        )


def _check_action_inputs(path: str, lines: list[str]) -> Iterator[Finding]:
    """WF012: a composite action substituting one of its inputs into a shell.

    Inside a workflow, a rule can tell an attacker-controlled context from a
    safe one. Inside an action it cannot: an input is whatever the caller
    passed, and the caller is every repository that uses the action. One of
    them will eventually wire ``github.event.issue.title`` into it, and the
    injection will happen here, in code they did not write and do not read.

    Medium severity and medium confidence, because most inputs are a version
    number and the mistake is the caller's to make. It is still the action's
    to prevent, and the prevention is one ``env:`` block.
    """
    # One finding per input, not per line. A shell script that tests an input,
    # then quotes it, then passes it on mentions it five times, and the fix is
    # still one env: entry -- five copies of that advice is how a rule gets
    # switched off.
    seen: "set[str]" = set()
    for number, line in _iter_run_lines(lines):
        for match in _INPUT_EXPR.finditer(line):
            if match.group("name") in seen:
                continue
            seen.add(match.group("name"))
            yield _input_finding(path, number, line, match.group("name"))


def _input_finding(path: str, number: int, line: str, name: str) -> Finding:
    return Finding(
        rule_id="WF012",
        severity=Severity.MEDIUM,
        title=f"Input {name!r} is interpolated into a run: block",
        path=path,
        line=number,
        evidence=line.strip(),
        remediation=(
            "An action cannot see where its input came from, and one caller "
            "will eventually pass an issue title. Put the value in an env: "
            "block and reference it as \"$VAR\", where the shell reads it as "
            "data rather than as part of the command."
        ),
        confidence=Confidence.MEDIUM,
    )


def scan_action(
    path: str, text: str, marks: "suppression.Suppressions | None" = None
) -> "list[Finding]":
    """Run the rules that survive outside a workflow against an action.yml.

    Only the composite kind: a JavaScript or container action has no steps to
    read, and its risk lives in code this scanner is not looking at. Rules
    about jobs -- permissions, runners, triggers -- have nothing to bind to
    here, because an action has none of those. What is left is what actually
    travels: the actions it calls, and the shell it writes.
    """
    marks = suppression.parse(text) if marks is None else marks
    if marks.whole_file:
        return []
    lines = text.splitlines()
    if not any(_COMPOSITE.match(line) for line in lines):
        return []
    findings = [
        *_check_action_pinning(path, lines),
        *_check_script_injection(path, lines),
        *_check_action_inputs(path, lines),
    ]
    return marks.filter_findings(findings)


def scan_workflow(
    path: str, text: str, marks: "suppression.Suppressions | None" = None
) -> list[Finding]:
    """Run every workflow rule against one workflow file.

    Suppression directives are honoured here too. A workflow is as entitled to
    a documented exception as any other file, and a marker that worked in
    application code but not in ``ci.yml`` would be the kind of inconsistency
    people work around by disabling the whole check.
    """
    marks = suppression.parse(text) if marks is None else marks
    if marks.whole_file:
        return []

    lines = text.splitlines()
    jobs = list(iter_jobs(lines))

    findings = [
        *_check_action_pinning(path, lines),
        *_check_script_injection(path, lines),
        *_check_privileged_checkout(path, lines),
        *_check_permissions(path, lines, jobs),
        *_check_runners(path, lines),
        *_check_secret_handoff(path, jobs),
        *_check_persisted_credentials(path, lines, jobs),
        *_check_exported_secrets(path, lines),
        *_check_inherited_secrets(path, jobs),
    ]
    return marks.filter_findings(findings)


def scan_files(
    files: "Iterable[tuple[str, str]]", *, honour_markers: bool = True
) -> "list[Finding]":
    """Scan ``(path, text)`` pairs: workflows, and the actions beside them."""
    markers = None if honour_markers else suppression.NONE
    findings: "list[Finding]" = []
    for path, text in files:
        if is_workflow_path(path):
            findings.extend(scan_workflow(path, text, markers))
        elif is_action_path(path):
            findings.extend(scan_action(path, text, markers))
    return findings
