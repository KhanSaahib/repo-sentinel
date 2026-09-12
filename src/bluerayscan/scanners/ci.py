"""What every CI system's injection bug has in common.

Four systems, one mistake. GitHub expands ``${{ github.event.issue.title }}``,
GitLab expands ``$CI_COMMIT_TITLE``, Azure expands
``$(Build.SourceVersionMessage)`` and CircleCI expands ``$CIRCLE_BRANCH`` --
each of them into the command line, before the shell parses it, and each of
them from a value an outside contributor can write. The syntax differs; the bug
does not.

So the parts that do not depend on syntax live here: finding the shell lines in
a step, and deciding whether a matched variable is one that can actually carry
an injection. Each scanner keeps its own pattern and its own vocabulary,
because those are exactly what differ.

The reason to share the rest is not brevity. It is that a fix found in one
system belongs in all of them: the list of fields that cannot carry an
injection was written for GitHub, found again in Azure, and would have been
written a third time by the next person to read only one file.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

from .. import yamlish


def script_lines(
    step: "yamlish.Node", keys: "Iterable[str]"
) -> "Iterator[tuple[int, str]]":
    """Yield ``(line, text)`` for every shell line a step carries.

    A step writes its commands as a scalar, a block scalar, or a list of them,
    depending on the system and the author's mood. All three are the same
    question to a rule that wants to know what the shell will see.
    """
    for key in keys:
        section = step.get(key)
        if section is None:
            continue
        if section.is_list:
            for entry in section.entries():
                if entry.text:
                    yield entry.line, entry.text
        elif section.text:
            yield section.line, section.text


def untrusted_matches(
    text: str, pattern: "re.Pattern[str]", harmless: "Iterable[str]" = ()
) -> "Iterator[re.Match[str]]":
    """Matches of an untrusted-variable pattern, minus the ones that cannot bite.

    A pull request number is an integer and a commit id is hex: the CI system
    picks both, so interpolating one is not an injection however untrusted the
    surrounding context is. Reporting them is how a rule that matters acquires
    a reputation for crying wolf -- which was learned once on GitHub Actions
    and then again, identically, on Azure Pipelines.
    """
    excluded = {field.lower() for field in harmless}
    for match in pattern.finditer(text):
        name = match.group("name") if "name" in match.groupdict() else match.group(0)
        if name.strip().split(".")[-1].lower() in excluded:
            continue
        yield match


#: Fields of an otherwise untrusted context that cannot carry an injection.
#: Shared because every system has the same ones under different names.
HARMLESS_FIELDS = frozenset(
    {
        "number", "id", "node_id", "sha", "merged", "state", "draft", "locked",
        "created_at", "updated_at", "closed_at", "merged_at", "commits",
        "additions", "deletions", "changed_files", "comments", "review_comments",
        "pullrequestid", "sourcecommitid", "pr_number",
    }
)
