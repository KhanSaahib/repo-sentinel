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
