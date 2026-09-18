"""Paced real TCP workload plus explicitly selected ICMP compatibility policy."""
import argparse
import hashlib
import json
import select
import socket
import time

from icmp_policy import decide
from lab_common import (CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, LAB_SEQUENCE,
                        EventLog, payload, positive_int, require_namespace)


def send(args):
    require_namespace("client")
    log = EventLog(args.log)
    sent, aborted, slow = 0, False, False
    started, receipt, error = None, None, None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as control, socket.socket() as tcp:
            control.bind((CLIENT, 0))
            control.setblocking(False)
            tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tcp.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            tcp.settimeout(args.timeout)
            tcp.bind((CLIENT, CLIENT_PORT))
            tcp.connect((SERVER, SERVER_PORT))
            tcp.sendall(json.dumps({"payload_bytes": args.payload_bytes}).encode() + b"\n")
            response = b""
            while len(response) < 2:
                part = tcp.recv(2 - len(response))
                if not part:
                    raise OSError("Receiver closed before readiness acknowledgement")
                response += part
            if response != b"OK":
                raise OSError("Invalid receiver acknowledgement")
            started = time.monotonic()
            log.emit("transfer_start", mode=args.mode, source=CLIENT, destination=SERVER,
                     source_port=CLIENT_PORT, destination_port=SERVER_PORT,
                     configured_quote_sequence=LAB_SEQUENCE, payload_bytes=args.payload_bytes,
                     normal_rate_bytes=args.rate, low_rate_bytes=args.low_rate,
                     sequence_validation="unavailable_for_kernel_socket")
            next_send, next_sample = started, started + 0.5
            while sent < args.payload_bytes and not aborted:
                now = time.monotonic()
                readable, _, _ = select.select([control], [], [], max(0, min(next_send - now, 0.05)))
                if readable:
                    packet = control.recv(65535)
                    decision = decide(packet, args.mode)
                    log.emit("icmp_decision", mode=args.mode, bytes_sent=sent,
                             packet_sha256=hashlib.sha256(packet).hexdigest(), **decision)
                    if decision["action"] == "abort":
                        aborted = True
                        break
                    if decision["action"] == "slow":
                        slow = True
                now = time.monotonic()
                if now >= next_send:
                    block = payload(sent, min(16384, args.payload_bytes - sent))
                    tcp.sendall(block)
                    sent += len(block)
                    rate = args.low_rate if slow else args.rate
                    # Do not catch up missed deadlines with bursts after scheduler stalls.
                    next_send = now + len(block) / rate
                if now >= next_sample:
                    log.emit("sample", elapsed=now - started, bytes_sent=sent, pacing="low" if slow else "normal")
                    next_sample = now + 0.5
            # ICMP-triggered application close uses FIN/EOF; no forged TCP RST is generated.
            tcp.shutdown(socket.SHUT_WR)
            log.emit("write_closed", bytes_sent=sent, aborted=aborted)
            response = bytearray()
            while not response.endswith(b"\n"):
                part = tcp.recv(4096)
                if not part or len(response) > 8192:
                    raise OSError("Missing receiver completion receipt")
                response.extend(part)
            receipt = json.loads(response)
    except (OSError, ValueError) as exc:
        error = f"{type(exc).__name__}: {exc}"
        log.emit("error", message=error)
    log.emit("transfer_end", bytes_sent=sent, aborted=aborted, low_rate_entered=slow,
             elapsed=time.monotonic() - started if started else 0,
             complete=bool(receipt and receipt["complete"]), receiver_receipt=receipt, error=error)
    log.close()
    return 1 if error else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["legacy", "hardened", "kernel"], required=True)
    parser.add_argument("--payload-bytes", type=positive_int, required=True)
    parser.add_argument("--rate", type=positive_int, default=1048576)
    parser.add_argument("--low-rate", type=positive_int, default=262144)
    parser.add_argument("--timeout", type=float, default=90)
    parser.add_argument("--log", required=True)
    raise SystemExit(send(parser.parse_args()))


if __name__ == "__main__":
    main()
