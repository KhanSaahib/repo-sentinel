"""A tree that trips every rule in the catalogue, exactly once each.

Two jobs. It is the fixture behind the catalogue drift test -- every rule
described in :mod:`repo_sentinel.rules` has to fire here, and every rule that
fires here has to be described there -- and it is a standing end-to-end check
that the scanners still work when pointed at a file rather than a string.

Every credential is invented and assembled from pieces at import time, for the
reason :mod:`fixtures` explains: a well-formed token written as one literal is
rejected by GitHub's push protection, correctly, and no fixture is worth
costing a person a judgement call.
"""

import fixtures

_ALNUM = "aB3dEf7hIj0kLm2nOp5qRs8tUv1wXy4z"


def _filler(length, alphabet=_ALNUM):
    return (alphabet * (length // len(alphabet) + 1))[:length]


SECRETS_FILE = "\n".join(
    (
        f'aws_key = "{fixtures.REALISTIC_AWS_KEY_ID}"',
        "github_pat = " + '"gh' + "p_" + _filler(36) + '"',
        "fine_grained = " + '"github' + "_pat_" + _filler(60) + '"',
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        'stripe = "sk' + "_live_" + _filler(24) + '"',
        'slack = "xox' + "b-" + _filler(24) + '"',
        'google = "AIz' + "a" + _filler(35) + '"',
        'openai = "sk' + "-proj-" + _filler(32) + '"',
        "jwt = " + '"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMxMjM0NTY3ODkifQ.' + _filler(24) + '"',
        'stripe_test = "sk' + "_test_" + _filler(24) + '"',
        'azure = "DefaultEndpointsProtocol=https;AccountKey=' + _filler(86, "aB3dEf7h") + '=="',
        'google_oauth = "GOC' + "SPX-" + _filler(28) + '"',
        'sendgrid = "S' + "G." + _filler(22) + "." + _filler(43) + '"',
        'twilio = "S' + "K" + _filler(32, "0a1b2c3d4e5f") + '"',
        'npm = "np' + "m_" + _filler(36) + '"',
        'pypi = "pyp' + "i-AgEIcHlwaS5vcmc" + _filler(60) + '"',
        'docker = "dck' + "r_pat_" + _filler(24) + '"',
        'slack_hook = "https://hooks.sl' + "ack.com/services/T" + _filler(32) + '"',
        'huggingface = "h' + "f_" + _filler(34) + '"',
        'dsn = "postgres://svc:Xk92mQp7Lz4TvB8n@db.internal:5432/app"',
        'session_secret = "Qq7Zx9Lm2Pv4Rt8WcY6h"',
    )
)

ENV_FILE = "\n".join(
    (
        "APP_NAME=billing",
        "DATABASE_PASSWORD=Tv8nRw1YXk92mQp7Lz4T",
    )
)

RUNAWAY_SUPPRESSION_FILE = "\n".join(
    (
        "settings = {}",
        "# repo-sentinel: ignore-start",
        "generated = 1",
    )
)

WORKFLOW_FILE = """name: risky
on:
  pull_request_target:
  workflow_run:
    workflows: [CI]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: some-vendor/deploy@v2
        with:
          token: ${{ secrets.DEPLOY_TOKEN }}
      - run: echo "reviewing ${{ github.event.issue.title }}"
  audit:
    permissions: write-all
    runs-on: [self-hosted, linux]
    steps:
      - run: make audit
"""

DOCKERFILE = """FROM golang:1.22 AS build
RUN go build ./...

FROM debian:latest
ARG NPM_TOKEN=Xk92mQp7Lz4TvB8nRw1Y
RUN curl -sSL https://get.example.io/install.sh | bash
RUN wget --no-check-certificate https://example.invalid/pkg.tar.gz
ADD https://example.invalid/app.tar.gz /opt/
CMD ["/app"]
"""

#: ``(path, text)`` pairs, in the shape :func:`iter_files` yields.
FILES = (
    ("src/config.py", SECRETS_FILE),
    (".env", ENV_FILE),
    ("src/generated.py", RUNAWAY_SUPPRESSION_FILE),
    (".github/workflows/risky.yml", WORKFLOW_FILE),
    ("Dockerfile", DOCKERFILE),
)
