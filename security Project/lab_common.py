"""Fixed laboratory configuration and shared evidence helpers (standard library only)."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

CLIENT = "10.10.10.10"
SERVER = "10.10.10.20"
ATTACKER = "10.10.10.30"
CLIENT_PORT = 40000
SERVER_PORT = 5001
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
    """Raw sending and endpoints must run in the exact owned network namespace."""
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise RuntimeError("Run the lab in Linux/WSL with sudo (raw sockets and namespaces require root).")
    expected = NAMESPACES[role]
    actual = subprocess.check_output(["ip", "netns", "identify", str(os.getpid())], text=True).strip()
    if actual != expected:
        raise RuntimeError(f"Refusing execution outside {expected}; use run_trial.py.")
    routes = json.loads(subprocess.check_output(["ip", "-j", "-4", "route"], text=True))
    if any(r.get("dst") != "10.10.10.0/24" or r.get("gateway") for r in routes):
        raise RuntimeError("Lab namespace has an unexpected route; refusing execution.")


def positive_int(value):
    value = int(value)
    if value <= 0:
        raise ValueError("Value must be positive")
    return value
