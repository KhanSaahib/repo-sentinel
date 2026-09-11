"""Facts about the world that more than one scanner needs.

Three different rules want to know whether port 3306 is worth shouting about,
whether ``/var/run/docker.sock`` is worse than ``/srv/data``, and whether
``SYS_ADMIN`` is a capability or a synonym for root. Keeping those lists next to
whichever rule happened to need them first means the Terraform scanner and the
Kubernetes scanner disagree about the same question within a release or two.

So they live here, with the reasoning attached. Adding an entry is a judgement
about the world rather than about a file format, which is exactly why it should
not be buried in a file-format module.
"""

from __future__ import annotations

import re

#: Ports whose exposure to the internet is a finding in itself. Web ports are
#: absent on purpose: a server on 443 open to the world is the point of it.
ADMIN_PORTS: "dict[int, str]" = {
    22: "SSH",
    23: "telnet",
    445: "SMB",
    1433: "SQL Server",
    2375: "the Docker daemon",
    2379: "etcd",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5984: "CouchDB",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "memcached",
    27017: "MongoDB",
}

#: Anything reachable from here is reachable from everywhere.
OPEN_CIDRS = ("0.0.0.0/0", "::/0")

#: Linux capabilities that hand back most of what dropping root took away.
#: NET_RAW is here because it is granted by default almost everywhere and is
#: enough to spoof ARP between containers on the same network.
DANGEROUS_CAPABILITIES = frozenset(
    {
        "ALL",
        "SYS_ADMIN",
        "SYS_PTRACE",
        "SYS_MODULE",
        "SYS_BOOT",
        "NET_ADMIN",
        "NET_RAW",
        "DAC_READ_SEARCH",
    }
)

#: Host paths whose exposure to a container is equivalent to owning the host.
#: The runtime sockets are the sharpest: anything that can talk to them can
#: start a new privileged container mounting the root filesystem.
CRITICAL_HOST_PATHS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/var/run/containerd",
    "/var/run/crio",
    "/etc/kubernetes",
    "/var/lib/kubelet",
    "/var/lib/docker",
    "/root",
    "/etc",
    "/",  # the whole filesystem; matched exactly, never as a prefix
)


#: Shell, Helm and Compose interpolation, including the bare ``$NAME`` form
#: that GitLab and every shell accept. A value written like this is decided
#: somewhere else, so nothing about its shape here is evidence of anything.
_INTERPOLATION = re.compile(r"\$\{|\$\(|\{\{|\$[A-Za-z_]")


def is_interpolated(value: str) -> bool:
    """True when a value is filled in from elsewhere at deploy or run time."""
    return _INTERPOLATION.search(value) is not None


#: Directory and file names that mean "this is not the real thing": fixtures,
#: recorded responses, sample configuration. A credential here is usually
#: invented -- usually, not always, which is why this lowers confidence rather
#: than silencing anything.
_TEST_DIRECTORIES = frozenset(
    {"testdata", "test", "tests", "fixtures", "__fixtures__", "testing", "mocks",
     "__mocks__", "spec", "specs", "examples", "example", "e2e", "integration"}
)
_TEST_NAME_MARKERS = ("_test.", "test_", ".test.", "_spec.", "mock_", "_mock.")


def is_test_path(path: str) -> bool:
    """True when a path is somewhere invented values are expected to live."""
    parts = path.replace("\\", "/").split("/")
    if {part.lower() for part in parts[:-1]} & _TEST_DIRECTORIES:
        return True
    name = parts[-1].lower()
    return any(marker in name for marker in _TEST_NAME_MARKERS)


#: Extensions and directories that hold prose. A credential written in
#: documentation is overwhelmingly an example -- that is what documentation is
#: for -- and the ones that are not are usually caught by a provider rule,
#: which keeps its confidence everywhere.
_PROSE_SUFFIXES = (".md", ".markdown", ".rst", ".adoc", ".asciidoc", ".txt")
_PROSE_DIRECTORIES = frozenset({"docs", "doc", "documentation", "website", "site", "man"})


def is_prose_path(path: str) -> bool:
    """True when a file is documentation rather than something that runs."""
    parts = path.replace("\\", "/").split("/")
    if any(part.lower().startswith(tuple(_PROSE_DIRECTORIES)) for part in parts[:-1]):
        return True
    return parts[-1].lower().endswith(_PROSE_SUFFIXES)


def is_critical_host_path(path: str) -> bool:
    """True when mounting ``path`` hands over the host.

    The root entry is matched exactly. Treating it as a prefix would make every
    absolute path critical, which is the same as making none of them critical.
    """
    cleaned = path.strip().strip("\"'").rstrip("/") or "/"
    if cleaned == "/":
        return True
    return any(
        cleaned == dangerous or cleaned.startswith(dangerous + "/")
        for dangerous in CRITICAL_HOST_PATHS
        if dangerous != "/"
    )


def services_in_range(low: int, high: int) -> "list[str]":
    """Which well-known admin services a port range leaves exposed."""
    return [name for port, name in sorted(ADMIN_PORTS.items()) if low <= port <= high]
