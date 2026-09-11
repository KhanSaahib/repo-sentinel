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

import base64

import fixtures

_ALNUM = "aB3dEf7hIj0kLm2nOp5qRs8tUv1wXy4z"


def _filler(length, alphabet=_ALNUM):
    return (alphabet * (length // len(alphabet) + 1))[:length]


def _b64(value):
    """Encode the way a Kubernetes Secret does, so K8S007 has to decode it."""
    return base64.b64encode(value.encode()).decode()


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

SERVICE_ACCOUNT_FILE = "\n".join(
    (
        "{",
        '  "type": "service_account",',
        '  "project_id": "billing-prod",',
        '  "private_key_id": "' + _filler(40) + '",',
        '  "client_email": "svc@billing-prod.iam.gserviceaccount.com"',
        "}",
    )
)

ENV_FILE = "\n".join(
    (
        "APP_NAME=billing",
        "AWS_BACKUP=" + _b64("aws_access_key_id=" + fixtures.REALISTIC_AWS_KEY_ID),
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
      - run: echo "token=${{ secrets.DEPLOY_TOKEN }}" >> $GITHUB_OUTPUT
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

TERRAFORM_FILE = """terraform {
  backend "s3" {
    bucket = "tfstate"
    key    = "prod.tfstate"
  }
}

resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "assets" {
  acl = "public-read"
}

resource "aws_db_instance" "main" {
  publicly_accessible = true
  storage_encrypted   = false
}

resource "azurerm_storage_account" "logs" {
  enable_https_traffic_only = false
}

data "aws_iam_policy_document" "admin" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}
"""

MANIFEST_FILE = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: app
          image: nginx
          securityContext:
            privileged: true
            runAsUser: 0
            capabilities:
              add: ["SYS_ADMIN"]
      volumes:
        - name: sock
          hostPath:
            path: /var/run/docker.sock
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: everything
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: open
roleRef:
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: Group
    name: system:unauthenticated
---
apiVersion: v1
kind: Secret
metadata:
  name: db
data:
  password: """ + _b64("Tv8nRw1YXk92mQp7Lz4T") + """
"""

COMPOSE_FILE = """services:
  db:
    image: postgres
    ports:
      - "5432:5432"
  runner:
    image: ci:1.2
    privileged: true
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    security_opt:
      - seccomp:unconfined
"""

PIPELINE_FILE = """stages: [build]

variables:
  CI_DEBUG_TRACE: "true"

build:
  image: python
  script:
    - echo "Building $CI_COMMIT_TITLE"
    - curl -sSL https://get.example.invalid/install.sh | bash
"""

TEMPLATE_FILE = """AWSTemplateFormatVersion: "2010-09-09"
Resources:
  WebSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
  Assets:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
  Database:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: true
      StorageEncrypted: false
  AdminRole:
    Type: AWS::IAM::Role
    Properties:
      Policies:
        - PolicyDocument:
            Statement:
              - Effect: Allow
                Action: "*"
                Resource: "*"
"""

PACKAGE_JSON = """{
  "name": "billing",
  "scripts": {
    "postinstall": "curl -sSL https://get.example.invalid/i.sh | sh"
  },
  "dependencies": {
    "internal-lib": "git+https://github.example.invalid/acme/internal-lib.git"
  }
}
"""

NPMRC_FILE = "registry=http://registry.example.invalid/\nstrict-ssl=false\n"

#: ``(path, text)`` pairs, in the shape :func:`iter_files` yields.
FILES = (
    ("src/config.py", SECRETS_FILE),
    (".env", ENV_FILE),
    ("deploy/service-account.json", SERVICE_ACCOUNT_FILE),
    ("src/generated.py", RUNAWAY_SUPPRESSION_FILE),
    (".github/workflows/risky.yml", WORKFLOW_FILE),
    ("Dockerfile", DOCKERFILE),
    ("infra/main.tf", TERRAFORM_FILE),
    ("deploy/web.yaml", MANIFEST_FILE),
    ("docker-compose.yml", COMPOSE_FILE),
    (".gitlab-ci.yml", PIPELINE_FILE),
    ("infra/stack.yaml", TEMPLATE_FILE),
    ("package.json", PACKAGE_JSON),
    ("web/.npmrc", NPMRC_FILE),
)

#: ``(path, text)`` pairs, in the shape the walk reports, with None for the
#: files it could not read. The names are the point here: two of these could
#: not be read at all, and the third is judged on what is in it.
PATHS = (
    *FILES,
    ("deploy/id_rsa", None),
    ("certs/server.pem", None),
    (".npmrc", "//registry.npmjs.org/:_authToken=" + _filler(36)),
    ("infra/terraform.tfstate", '{"version": 4, "resources": []}'),
)
