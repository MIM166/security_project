"""TCP receiver with deterministic payload verification and delivered-byte evidence."""
import argparse
import hashlib
import json
import socket
import time

from lab_common import SERVER, SERVER_PORT, EventLog, payload, positive_int, require_namespace


def receive(args):
    require_namespace("server")
    log = EventLog(args.log)
    received, corrupt = 0, False
    digest = hashlib.sha256()
    started = None
    reason = "error"
    try:
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((SERVER, SERVER_PORT))
            listener.listen(1)
            listener.settimeout(args.timeout)
            log.emit("listening", address=SERVER, port=SERVER_PORT)
            connection, peer = listener.accept()
            with connection:
                connection.settimeout(args.timeout)
                header = bytearray()
                while not header.endswith(b"\n"):
                    byte = connection.recv(1)
                    if not byte or len(header) >= 4096:
                        raise ValueError("Missing or oversized transfer header")
                    header.extend(byte)
                metadata = json.loads(header)
                if metadata.get("payload_bytes") != args.payload_bytes:
                    raise ValueError("Unexpected workload size")
                started = time.monotonic()
                log.emit("transfer_start", peer=peer, expected_bytes=args.payload_bytes)
                connection.sendall(b"OK")
                next_sample = started + 0.5
                while True:
                    data = connection.recv(65536)
                    if not data:
                        reason = "eof"
                        break
                    if data != payload(received, len(data)):
                        corrupt = True
                    received += len(data)
                    digest.update(data)
                    now = time.monotonic()
                    if now >= next_sample:
                        log.emit("sample", elapsed=now - started, bytes_received=received)
                        next_sample = now + 0.5
                complete = received == args.payload_bytes and not corrupt
                result = {"bytes_received": received, "complete": complete,
                          "sha256": digest.hexdigest(), "payload_valid": not corrupt}
                connection.sendall(json.dumps(result).encode() + b"\n")
    except (OSError, ValueError) as exc:
        reason = f"{type(exc).__name__}: {exc}"
        log.emit("error", message=reason)
    elapsed = time.monotonic() - started if started is not None else 0
    complete = received == args.payload_bytes and not corrupt and reason == "eof"
    log.emit("transfer_end", bytes_received=received, expected_bytes=args.payload_bytes,
             complete=complete, premature_close=received < args.payload_bytes,
             payload_valid=not corrupt, sha256=digest.hexdigest(), elapsed=elapsed,
             goodput_mbps=received * 8 / elapsed / 1e6 if elapsed else 0, reason=reason)
    log.close()
    return 0 if reason == "eof" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload-bytes", type=positive_int, required=True)
    parser.add_argument("--timeout", type=float, default=90)
    parser.add_argument("--log", required=True)
    raise SystemExit(receive(parser.parse_args()))


if __name__ == "__main__":
    main()
