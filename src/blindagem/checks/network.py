"""Firewall, listening services and network-facing kernel parameters."""

from __future__ import annotations

from ..host import Host
from ..models import CheckMeta, CheckResult, Severity, Status
from ..registry import check
from ._common import sysctl_check

CATEGORY = "network"

#: Protocols that send credentials in the clear or exist only for legacy reasons.
LEGACY_PORTS = {
    21: "FTP (credentials in clear text)",
    23: "Telnet (everything in clear text)",
    69: "TFTP (no authentication at all)",
    512: "rexec (legacy r-services)",
    513: "rlogin (legacy r-services)",
    514: "rsh (legacy r-services)",
}


@check(
    CheckMeta(
        id="net.firewall_active",
        title="A host firewall is running",
        category=CATEGORY,
        severity=Severity.HIGH,
        rationale=(
            "Without a firewall every service that binds a port is reachable from wherever the "
            "machine is — including the database or admin panel someone started 'just for a test'. "
            "A default-deny firewall means a mistake in one service is not automatically exposed."
        ),
        remediation="Allow the SSH port first, then enable ufw, firewalld or an nftables ruleset.",
        reference="CIS Linux Benchmark 3.5 (host based firewall)",
        skip_profiles=("container",),
    )
)
def firewall_active(host: Host) -> CheckResult:
    check_id = "net.firewall_active"
    evidence: list[str] = []

    result = host.run(["ufw", "status"])
    if result and result.returncode == 0:
        if "Status: active" in result.stdout:
            return CheckResult(check_id, Status.PASS, "ufw is active")
        evidence.append("ufw is installed but inactive")

    result = host.run(["firewall-cmd", "--state"])
    if result and "running" in result.stdout:
        return CheckResult(check_id, Status.PASS, "firewalld is running")
    if result:
        evidence.append("firewalld is installed but not running")

    result = host.run(["nft", "list", "ruleset"])
    if result and result.returncode == 0:
        if _nft_has_rules(result.stdout):
            return CheckResult(check_id, Status.PASS, "nftables has an active ruleset")
        evidence.append("nftables ruleset is empty")

    result = host.run(["iptables", "-S"])
    if result and result.returncode == 0:
        rules = [line for line in result.stdout.splitlines() if line.startswith("-A")]
        policies_drop = any(
            line.startswith(("-P INPUT DROP", "-P INPUT REJECT"))
            for line in result.stdout.splitlines()
        )
        if rules or policies_drop:
            return CheckResult(check_id, Status.PASS, f"iptables has {len(rules)} rules")
        evidence.append("iptables has no rules")

    if not evidence:
        return CheckResult(
            check_id,
            Status.ERROR,
            "no firewall tool could be queried (ufw, firewalld, nft, iptables)",
        )
    return CheckResult(check_id, Status.FAIL, "No host firewall is active", evidence)


def _nft_has_rules(output: str) -> bool:
    """True when the ruleset contains something other than empty chains."""
    for raw in output.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "table", "chain", "}", "type ")):
            continue
        return True
    return False


@check(
    CheckMeta(
        id="net.legacy_listeners",
        title="No clear-text legacy services are listening",
        category=CATEGORY,
        severity=Severity.HIGH,
        rationale=(
            "Telnet, FTP, TFTP and the r-services send passwords across the network in plain "
            "text. Anyone in a position to watch the traffic gets the credentials for free."
        ),
        remediation="Stop and disable the service, and use SSH or SFTP instead.",
        reference="CIS Linux Benchmark 2.1 (server services)",
    )
)
def legacy_listeners(host: Host) -> CheckResult:
    check_id = "net.legacy_listeners"
    result = host.run(["ss", "-H", "-tuln"])
    if result is None or result.returncode != 0:
        return CheckResult(
            check_id, Status.ERROR, "listening ports could not be read (ss is missing)"
        )
    found = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        local = fields[4]
        port_text = local.rsplit(":", 1)[-1]
        if not port_text.isdigit():
            continue
        port = int(port_text)
        if port in LEGACY_PORTS:
            found.append(f"port {port} — {LEGACY_PORTS[port]} (bound to {local})")
    if found:
        return CheckResult(
            check_id, Status.FAIL, "Legacy clear-text services are listening", sorted(set(found))
        )
    return CheckResult(check_id, Status.PASS, "no legacy clear-text service is listening")


@check(
    CheckMeta(
        id="net.ip_forward",
        title="The machine does not route packets",
        category=CATEGORY,
        severity=Severity.MEDIUM,
        rationale=(
            "With IP forwarding on, the host passes traffic between networks. On a server that "
            "is not a router, that turns a compromised box into a bridge into the internal network."
        ),
        remediation=(
            "Set net.ipv4.ip_forward = 0 in /etc/sysctl.d/60-blindagem.conf. If the host really "
            "is a router or a container host, record it as an exception in blindagem.yaml."
        ),
        reference="CIS Linux Benchmark 3.2 (network parameters)",
        skip_profiles=("container", "workstation"),
    )
)
def ip_forward(host: Host) -> CheckResult:
    return sysctl_check(
        host,
        "net.ip_forward",
        "net.ipv4.ip_forward",
        "0",
        fail_message="The machine is forwarding IP packets",
    )


@check(
    CheckMeta(
        id="net.accept_redirects",
        title="ICMP redirects are ignored",
        category=CATEGORY,
        severity=Severity.LOW,
        rationale=(
            "An ICMP redirect tells the machine to send traffic through a different gateway. "
            "Accepting them lets anyone on the local network quietly reroute traffic through "
            "their own machine."
        ),
        remediation="Set net.ipv4.conf.all.accept_redirects = 0 in /etc/sysctl.d/60-blindagem.conf.",
        reference="CIS Linux Benchmark 3.2 (network parameters)",
        skip_profiles=("container",),
    )
)
def accept_redirects(host: Host) -> CheckResult:
    return sysctl_check(
        host,
        "net.accept_redirects",
        "net.ipv4.conf.all.accept_redirects",
        "0",
        fail_message="The machine accepts ICMP redirects",
    )


@check(
    CheckMeta(
        id="net.syncookies",
        title="TCP SYN cookies are enabled",
        category=CATEGORY,
        severity=Severity.LOW,
        rationale=(
            "SYN cookies let the machine keep answering legitimate connections while a flood of "
            "half-open ones is filling the backlog queue."
        ),
        remediation="Set net.ipv4.tcp_syncookies = 1 in /etc/sysctl.d/60-blindagem.conf.",
        reference="CIS Linux Benchmark 3.2 (network parameters)",
        skip_profiles=("container",),
    )
)
def syncookies(host: Host) -> CheckResult:
    return sysctl_check(
        host,
        "net.syncookies",
        "net.ipv4.tcp_syncookies",
        "1",
        fail_message="TCP SYN cookies are disabled",
    )
