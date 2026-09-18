"""Two-machine LAN variant of the lab configuration.

Differences from the graded namespace lab:
  * CLIENT / SERVER / ATTACKER come from environment variables so the same code
    runs on both real machines without editing.  On the machine that runs BOTH
    the server and the client (Machine A) set CLIENT == SERVER == that machine's
    LAN IP (they only differ by port).  ATTACKER is Machine B's LAN IP.
  * require_namespace() only checks for root -- there is no `ip netns` here.
Everything else is copied verbatim from the graded lab.
"""
import hashlib
import json
import os
from pathlib import Path
import time

CLIENT = os.environ.get("LAB_CLIENT", "10.10.10.10")     # Machine A LAN IP
SERVER = os.environ.get("LAB_SERVER", "10.10.10.20")     # Machine A LAN IP (same host)
ATTACKER = os.environ.get("LAB_ATTACKER", "10.10.10.30") # Machine B LAN IP
CLIENT_PORT = int(os.environ.get("LAB_CLIENT_PORT", "40000"))
SERVER_PORT = int(os.environ.get("LAB_SERVER_PORT", "5001"))
LAB_SEQUENCE = 0x12345678
NAMESPACES = {"client": "c406-client", "server": "c406-server", "attacker": "c406-attacker"}
SWITCH = "c406-switch"
ROOT = Path(__file__).resolve().parent
PATTERN = bytes(range(256))


def payload(offset, size):
    start = offset % len(PATTERN)
    return (PATTERN * ((size + start + 255) // 256))[start:start + size]


def payload_hash(size):
    digest = hashlib.sha256()
    for offset in range(0, size, 65536):
        digest.update(payload(offset, min(65536, size - offset)))
    return digest.hexdigest()


class EventLog:
    def __init__(self, path):
        self.file = Path(path).open("w", encoding="utf-8", buffering=1)

    def emit(self, event, **fields):
        record = {"event": event, "monotonic": time.monotonic(), "unix_time": time.time(), **fields}
        self.file.write(json.dumps(record, sort_keys=True) + "\n")
        return record

    def close(self):
        self.file.close()


def read_events(path):
    if not Path(path).exists():
        return []
    events = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass  # The last line may still be being written by a running endpoint.
    return events


def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def require_namespace(role):
    """Two-machine LAN variant: raw sockets still require root, but there is no
    owned `ip netns` to verify -- each real machine IS the isolation boundary."""
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise RuntimeError("Run with sudo (raw sockets require root).")
    return


def positive_int(value):
    value = int(value)
    if value <= 0:
        raise ValueError("Value must be positive")
    return value
