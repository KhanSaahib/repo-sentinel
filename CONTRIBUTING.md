# Contributing

The bar for this project is not "does the check work". It is "will people still
be reading the output six months from now". Most of what follows is about that.

## Ground rules

**No runtime dependencies.** Not one. A tool you point at your supply chain has
no business enlarging it, and the constraint has been good for the design: it is
why the workflow scanner reads files the way a reviewer skims them instead of
building a YAML tree nobody asked for. Test-time and CI-time tooling is a
different question, but it has to earn its place too.

**Read structure, not lines, wherever the question is about structure.** There
are two small readers for this -- `hcl` for Terraform blocks and `yamlish` for
YAML documents -- and neither is a parser. Both are explicit in their docstrings
about what they do not handle, and both degrade to "no nested value here" rather
than to a wrong answer, so a rule built on them goes quiet rather than lying. If
you need something they cannot do, extend them with the same discipline: unknown
structure becomes a scalar, and silence is the safe direction.

**Facts about the world go in `wellknown`.** Which ports are worth shouting
about, which host paths grant the host, which capabilities are a synonym for
root: three scanners want each of those, and a copy kept next to whichever rule
needed it first is how two of them end up disagreeing.

**Python 3.9 and up.** Use `from __future__ import annotations` and write modern
annotations; do not use match statements or anything else 3.9 cannot parse.

**Every finding names its fix.** A report that says what is wrong without saying
what to do about it is a nag. Remediation text should name the concrete action —
"deactivate the key in IAM, then rotate it", not "review this credential".

**Never print a secret.** Evidence goes through `findings.redact`, always. The
scanner's output ends up in CI logs, issue threads and screenshots; it must
never be the thing that leaks the credential it found.

## Adding a rule

1. Pick the next free id in the right family: `SEC` for secrets, `WF` for
   workflows, `DK` for Dockerfiles, `TF` for Terraform, `K8S` for Kubernetes,
   `DC` for Compose. `SEC100+` is reserved for heuristics and `SEC900+` for the
   scanner's own hygiene checks.
2. Write the detection. Provider patterns are data — add a `ProviderRule` to
   `scanners/secrets.py`. Structural checks are functions.
3. Add it to `rules.py`. The suite fails if you do not.
4. Extend `tests/corpus.py` so the rule fires there. The corpus is what proves
   the catalogue, the scanners and the README agree; a rule missing from any of
   the three fails the build.
5. Write tests for what it should *not* match. This matters more than the
   positive case: the positive case is why you wrote the rule, and the negative
   cases are why anyone will still have it switched on next quarter.
6. Add a row to the README table. This is enforced, not asked for.

### Choosing a severity

Severity is what the finding costs if it is real, assuming the rule is right:

- **critical** — a live credential that grants access right now, or a workflow
  that lets an outside contributor run code with your secrets.
- **high** — a credential with a narrower blast radius, or a permission grant
  much wider than the job needs.
- **medium** — a real weakness that needs a second mistake to be exploited: a
  mutable action pin, a self-hosted runner, a default-permissions job.
- **low** — worth knowing, not worth failing a build over.

### Choosing a confidence

Confidence is how sure the *rule* is, and it is independent of severity:

- **high** — a documented token shape that nothing else produces.
- **medium** — a shape loose enough to have coincidences (`SK` plus 32 hex
  characters), or a heuristic like entropy.
- **low** — reserved for rules that are mostly right in one ecosystem and mostly
  wrong elsewhere. There are none yet; if you need it, say why in the review.

If you find yourself lowering a severity because the rule is unreliable, lower
the confidence instead. That is what it is for.

## Adding to the example allowlist

`scanners/allowlist.py` silences a credential permanently, so an entry must be
both **publicly documented** and **inert**. "Probably not a real key" is not
enough — that judgement belongs to the person reading the report.

Where the exact bytes of a vendor sample are uncertain, prefer a convention the
vendor documents over a literal transcribed from memory. A convention that
misses is silent; a wrong literal quietly claims coverage the scanner does not
have.

## Suppression and configuration

Two places name rules -- a `disable` list in `.repo-sentinel.json` and a
`# repo-sentinel: ignore[RULE]` marker in a file -- and they share
`rules.matcher`, so the syntax is identical in both. Keep it that way: the
answer to "what do I write here" should not depend on where here is.

## Tests

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

No test may contain a credential that was ever issued. Fake ones are assembled
from pieces at import time, for the reason `tests/fixtures.py` explains: a
well-formed token written as a single literal is rejected by GitHub's push
protection, correctly, and no fixture is worth costing a person a judgement call.

## Style

Match the surrounding code. Comments explain *why*, especially where a
constraint led somewhere non-obvious — the file-level suppression marker's
twenty-line limit, the entropy floor moving with the alphabet, the baseline
omitting line numbers. If a decision took you an afternoon, write down what you
learned; the next person has the same afternoon ahead of them otherwise.

Docstrings are prose, not restatements of the signature. `"""Return the path."""`
on a function called `path` is worse than nothing.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md). Report privately, not in a public issue.
