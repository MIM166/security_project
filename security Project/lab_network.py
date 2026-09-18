"""Create an owned namespace topology with no links to the host network."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from lab_common import CLIENT, SERVER, ATTACKER, NAMESPACES, SWITCH, ROOT, write_json

STATE = Path("/run/c406-icmp-lab.json")
ALL_NS = [SWITCH, *NAMESPACES.values()]


def run(*args, check=True):
    return subprocess.run(list(args), check=check, text=True, capture_output=True)


def ip(*args):
    return run("ip", *args)


def ns_names():
    # `ip -j netns list` emits an empty string (not "[]") when no namespaces
    # exist on some iproute2 builds (e.g. 6.1.0 on Ubuntu 24.04), so guard it.
    output = ip("-j", "netns", "list").stdout.strip()
    return {row["name"] for row in json.loads(output)} if output else set()


def check_owner():
    if not STATE.exists():
        raise RuntimeError("No lab ownership record; refusing to remove unowned network resources")
    state = json.loads(STATE.read_text())
    if state.get("project") != str(ROOT) or state.get("namespaces") != ALL_NS:
        raise RuntimeError("Lab ownership record belongs to another project")


def down():
    if not STATE.exists() and not (set(ALL_NS) & ns_names()):
        return
    check_owner()
    present = ns_names()
    # Never terminate unrelated processes. The runner stops its children first.
    for ns in ALL_NS:
        if ns in present and ip("netns", "pids", ns).stdout.strip():
            raise RuntimeError(f"{ns} still has running processes; stop the lab trial before cleanup")
    for ns in reversed(ALL_NS):
        if ns in present:
            ip("netns", "del", ns)
    STATE.unlink(missing_ok=True)


def up():
    if STATE.exists():
        check_owner()
        status(validate=True)
        print("Existing owned topology is healthy.")
        return
    collision = set(ALL_NS) & ns_names()
    if collision:
        raise RuntimeError(f"Namespace name collision: {sorted(collision)}; refusing to replace it")
    write_json(STATE, {"project": str(ROOT), "namespaces": ALL_NS})
    created = []
    try:
        for ns in ALL_NS:
            ip("netns", "add", ns)
            created.append(ns)
            ip("-n", ns, "link", "set", "lo", "up")
        ip("-n", SWITCH, "link", "add", "br-lab", "type", "bridge")
        ip("-n", SWITCH, "link", "set", "br-lab", "up")
        for role, address in (("client", CLIENT), ("server", SERVER), ("attacker", ATTACKER)):
            ns = NAMESPACES[role]
            peer = "port-" + role[0]
            # Both endpoints are created inside the switch namespace, never on the host.
            ip("-n", SWITCH, "link", "add", peer, "type", "veth", "peer", "name", "tmp-peer")
            ip("-n", SWITCH, "link", "set", "tmp-peer", "netns", ns)
            ip("-n", ns, "link", "set", "tmp-peer", "name", "eth0")
            ip("-n", SWITCH, "link", "set", peer, "master", "br-lab")
            ip("-n", SWITCH, "link", "set", peer, "up")
            ip("-n", ns, "addr", "add", address + "/24", "dev", "eth0")
            ip("-n", ns, "link", "set", "eth0", "up")
        status(validate=True)
    except BaseException:
        for ns in reversed(created):
            run("ip", "netns", "del", ns, check=False)
        STATE.unlink(missing_ok=True)
        raise


def status(validate=False):
    if validate:
        check_owner()
    present = ns_names()
    evidence = {}
    expected_interfaces = {SWITCH: {"lo", "br-lab", "port-c", "port-s", "port-a"},
                           **{ns: {"lo", "eth0"} for ns in NAMESPACES.values()}}
    for ns in ALL_NS:
        if ns not in present:
            raise RuntimeError(f"Missing namespace: {ns}")
        links = json.loads(ip("-n", ns, "-j", "link").stdout)
        routes = json.loads(ip("-n", ns, "-j", "-4", "route").stdout)
        routes6 = json.loads(ip("-n", ns, "-j", "-6", "route").stdout)
        addresses = json.loads(ip("-n", ns, "-j", "addr").stdout)
        if validate:
            # Some host kernels (e.g. Docker Desktop's LinuxKit) load the tunnel
            # modules, so every fresh namespace is auto-populated with down,
            # address-less fallback devices. They provide no host connectivity
            # (routes/addresses are validated separately below), so ignore them.
            FALLBACK = {"tunl0", "gre0", "gretap0", "erspan0", "ip_vti0",
                        "ip6_vti0", "sit0", "ip6tnl0", "ip6gre0"}
            present_ifaces = {link["ifname"] for link in links} - FALLBACK
            if present_ifaces != expected_interfaces[ns]:
                raise RuntimeError(f"Unexpected interfaces in {ns}")
            if any(r.get("gateway") or r.get("dst") != "10.10.10.0/24" for r in routes):
                raise RuntimeError(f"Unexpected IPv4 route in {ns}")
            if any(r.get("dst") == "default" or r.get("gateway") for r in routes6):
                raise RuntimeError(f"Unexpected IPv6 route in {ns}")
            if ns != SWITCH:
                role = next(role for role, value in NAMESPACES.items() if value == ns)
                expected = {"client": CLIENT, "server": SERVER, "attacker": ATTACKER}[role]
                local4 = {a["local"] for link in addresses if link["ifname"] == "eth0"
                          for a in link["addr_info"] if a["family"] == "inet"}
                if local4 != {expected} or len(routes) != 1:
                    raise RuntimeError(f"Unexpected address or missing subnet route in {ns}")
        evidence[ns] = {"links": links, "routes_ipv4": routes, "routes_ipv6": routes6, "addresses": addresses}
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["up", "down", "status", "doctor"])
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("Use Ubuntu/WSL, not Windows Python")
    missing = [name for name in ("ip", "tcpdump", "python3") if not shutil.which(name)]
    if missing:
        parser.error("Missing tools: " + ", ".join(missing) + "; install python3 iproute2 tcpdump")
    if os.geteuid() != 0:
        parser.error("Run with sudo")
    if args.command == "doctor":
        print(json.dumps({"platform": os.uname().release, "python": sys.version,
                          "tools": {name: shutil.which(name) for name in ("ip", "tcpdump", "python3")}}, indent=2))
    elif args.command == "up":
        up()
        print("Lab ready: three endpoint namespaces and an isolated bridge namespace.")
    elif args.command == "down":
        down()
        print("Owned lab topology removed.")
    else:
        print(json.dumps(status(validate=True), indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"Lab error: {exc}", file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError):
            print(exc.stderr, file=sys.stderr)
        sys.exit(1)
