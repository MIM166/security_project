"""Run reproducible, isolated ICMP/TCP experiments and collect independent evidence."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from evidence import inspect_pcap, window_goodput
from icmp_builder import build_packet, decode_packet
from dataclasses import asdict
from lab_common import ROOT, SWITCH, NAMESPACES, payload_hash, read_events, write_json, positive_int
import lab_network
from report import render

CONDITIONS = [("baseline", "hardened", None), ("legacy_reset", "legacy", "reset"),
              ("hardened_reset", "hardened", "reset"), ("legacy_quench", "legacy", "quench"),
              ("hardened_quench", "hardened", "quench")]


def stop(process):
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def wait_event(path, event_name, process, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for event in read_events(path):
            if event["event"] == event_name:
                return event
        if process.poll() is not None:
            raise RuntimeError(f"Process exited before {event_name}; inspect {path.parent}")
        time.sleep(0.025)
    raise RuntimeError(f"Timed out waiting for {event_name}; inspect {path.parent}")


def last_event(events, kind):
    found = [event for event in events if event["event"] == kind]
    if not found:
        raise RuntimeError(f"Missing endpoint event {kind}")
    return found[-1]


def analyze(directory, condition, mode, kind, repeat, config, packet_path):
    sender = read_events(directory / "sender.jsonl")
    receiver = read_events(directory / "receiver.jsonl")
    tx_end, rx_end = last_event(sender, "transfer_end"), last_event(receiver, "transfer_end")
    rx_start = last_event(receiver, "transfer_start")["monotonic"]
    tx_start = last_event(sender, "transfer_start")["monotonic"]
    decisions = [event for event in sender if event["event"] == "icmp_decision"]
    capture = inspect_pcap(directory / "capture.pcap")
    checks = {"payload_prefix_verified": rx_end["payload_valid"],
              "sender_receiver_byte_counts_match": tx_end["bytes_sent"] == rx_end["bytes_received"],
              "endpoints_exited_without_error": tx_end["error"] is None and rx_end["reason"] == "eof",
              "tcp_traffic_captured": capture["tcp_packets"] > 0}
    attack = decisions[0]["monotonic"] if decisions else None
    packet_hash = hashlib.sha256(packet_path.read_bytes()).hexdigest() if kind else None
    if kind:
        attacker = last_event(read_events(directory / "attacker.jsonl"), "packet_sent")
        checks.update({"one_icmp_packet_captured": len(capture["icmp_packets"]) == 1,
                       "capture_matches_prebuilt_packet": any(p.get("valid") and p["sha256"] == packet_hash for p in capture["icmp_packets"]),
                       "transmitter_matches_prebuilt_packet": attacker["sha256"] == packet_hash,
                       "endpoint_received_identical_packet": len(decisions) == 1 and decisions[0]["packet_sha256"] == packet_hash,
                       "attack_after_baseline": attacker["monotonic"] >= tx_start + config["baseline_seconds"]})
    else:
        checks["no_icmp_in_baseline"] = not capture["icmp_packets"] and not decisions
    event_time = attack or tx_start + config["baseline_seconds"]
    pre_start = rx_start + min(0.5, config["baseline_seconds"] * 0.2)
    pre_end = min(event_time - 0.2, rx_end["monotonic"])
    pre = window_goodput(receiver, pre_start, pre_end)
    post_start = event_time + 0.5
    post_end = min(event_time + 2.5, rx_end["monotonic"] - 0.1)
    post = window_goodput(receiver, post_start, post_end) if post_end > post_start else None
    reduction = 100 * (pre - post) / pre if post is not None and pre > 0 else None
    action = decisions[0]["action"] if decisions else "none"
    if condition == "legacy_reset":
        checks.update({"fatal_policy_logged": action == "abort", "transfer_incomplete": not rx_end["complete"] and rx_end["premature_close"],
                       "sender_aborted": tx_end["aborted"],
                       "close_follows_icmp": attack is not None and 0 <= rx_end["monotonic"] - attack < 2})
    else:
        checks["full_payload_delivered"] = rx_end["complete"]
        checks["full_payload_hash_verified"] = rx_end["sha256"] == config["payload_sha256"]
        checks["no_connection_abort"] = not tx_end["aborted"]
        if condition == "legacy_quench":
            checks.update({"low_rate_policy_logged": action == "slow" and tx_end["low_rate_entered"],
                           "goodput_reduced_at_least_50_percent": reduction is not None and reduction >= 50})
        else:
            checks["no_low_rate_state"] = not tx_end["low_rate_entered"]
            checks["post_rate_within_25_percent_of_pre_rate"] = reduction is not None and abs(reduction) <= 25
            if kind:
                expected = "observe" if mode == "kernel" else ("advisory" if kind == "reset" else "ignore")
                checks["defensive_decision_logged"] = action == expected
    result = {"condition": condition, "repeat": repeat, "mode": mode, "directory": directory.name,
              "passed": all(checks.values()), "checks": checks, "bytes_received": rx_end["bytes_received"],
              "complete": rx_end["complete"], "elapsed_seconds": rx_end["elapsed"],
              "overall_goodput_mbps": rx_end["goodput_mbps"], "pre_goodput_mbps": pre,
              "post_goodput_mbps": post, "reduction_percent": reduction, "decision": action,
              "attack_elapsed_seconds": attack - rx_start if attack else None,
              "measurement_windows_seconds": {"pre": [pre_start - rx_start, pre_end - rx_start],
                                               "post": [post_start - rx_start, post_end - rx_start] if post is not None else None},
              "packet_sha256": packet_hash, "capture": capture}
    write_json(directory / "result.json", result)
    return result


def trial(output, condition, mode, kind, repeat, config):
    directory = output / f"{repeat:02d}_{condition}"
    directory.mkdir()
    lab_network.down()
    lab_network.up()
    write_json(directory / "topology.json", lab_network.status(validate=True))
    processes, streams = [], []
    packet_path = output / "packets" / f"{kind}.bin" if kind else None
    timeout = config["payload_bytes"] / config["low_rate"] + 30

    def launch(role, script, arguments):
        stream = (directory / f"{role}.console.log").open("w")
        streams.append(stream)
        command = ["ip", "netns", "exec", NAMESPACES[role], sys.executable, "-u", str(ROOT / script), *map(str, arguments)]
        process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT, cwd=ROOT)
        processes.append(process)
        return process

    try:
        capture_log = (directory / "tcpdump.log").open("w")
        streams.append(capture_log)
        capture = subprocess.Popen(["ip", "netns", "exec", SWITCH, "tcpdump", "--immediate-mode", "-i", "br-lab", "-nn", "-U", "-s", "128",
                                    "-w", str(directory / "capture.pcap"), "icmp or tcp port 5001"],
                                   stdout=capture_log, stderr=subprocess.STDOUT)
        processes.append(capture)
        deadline = time.monotonic() + 10
        while "listening on" not in (directory / "tcpdump.log").read_text():
            if capture.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError(f"Packet capture failed; inspect {directory / 'tcpdump.log'}")
            time.sleep(0.025)
        receiver = launch("server", "tcp_receiver.py", ["--payload-bytes", config["payload_bytes"], "--timeout", timeout,
                                                       "--log", directory / "receiver.jsonl"])
        wait_event(directory / "receiver.jsonl", "listening", receiver)
        sender = launch("client", "tcp_sender.py", ["--mode", mode, "--payload-bytes", config["payload_bytes"],
                                                   "--rate", config["rate"], "--low-rate", config["low_rate"],
                                                   "--timeout", timeout, "--log", directory / "sender.jsonl"])
        start = wait_event(directory / "sender.jsonl", "transfer_start", sender)["monotonic"]
        if kind:
            while time.monotonic() < start + config["baseline_seconds"]:
                if sender.poll() is not None:
                    raise RuntimeError("Sender completed before scheduled ICMP injection")
                time.sleep(min(0.05, max(0, start + config["baseline_seconds"] - time.monotonic())))
            attacker = launch("attacker", "icmp_builder.py", ["send", packet_path, "--log", directory / "attacker.jsonl"])
            if attacker.wait(timeout=10) != 0:
                raise RuntimeError(f"Packet transmission failed; inspect {directory / 'attacker.console.log'}")
        if sender.wait(timeout=timeout) != 0 or receiver.wait(timeout=10) != 0:
            raise RuntimeError(f"Endpoint process failed; inspect console logs in {directory}")
        time.sleep(0.15)
        stop(capture)
        decoded = subprocess.run(["tcpdump", "-nn", "-vvv", "-XX", "-r", str(directory / "capture.pcap"), "icmp"], capture_output=True, text=True, check=True)
        (directory / "capture.txt").write_text(decoded.stdout + decoded.stderr, encoding="utf-8")
        return analyze(directory, condition, mode, kind, repeat, config, packet_path)
    finally:
        for process in reversed(processes):
            stop(process)
        for stream in streams:
            stream.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true", help="1-second baseline and 2 MiB payload for smoke testing")
    parser.add_argument("--include-kernel", action="store_true", help="Add two trials with observational user-space ICMP handling")
    parser.add_argument("--repeats", type=int, choices=[1, 2, 3], default=1)
    parser.add_argument("--payload-bytes", type=positive_int)
    parser.add_argument("--baseline-seconds", type=float)
    parser.add_argument("--rate", type=positive_int, default=1048576)
    parser.add_argument("--low-rate", type=positive_int, default=262144)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--keep-lab", action="store_true")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("Run inside Ubuntu/WSL with sudo; see README.md or use Run-Lab.ps1")
    baseline = args.baseline_seconds if args.baseline_seconds is not None else (1 if args.quick else 5)
    size = args.payload_bytes if args.payload_bytes is not None else (2097152 if args.quick else 8388608)
    if baseline < 1 or size / args.rate < baseline + 0.9 or args.low_rate > args.rate * 0.4:
        parser.error("Require baseline >= 1 s, payload/rate >= baseline + 0.9 s, and low-rate <= 40% of normal rate")
    import fcntl
    lock = open("/run/c406-icmp-run.lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        parser.error("Another project trial is running")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    output = (args.output or ROOT / "results" / stamp).resolve()
    if output.exists() and any(output.iterdir()):
        parser.error("Output directory must be empty; existing evidence will not be overwritten")
    output.mkdir(parents=True, exist_ok=True)
    config = {"payload_bytes": size, "payload_sha256": payload_hash(size), "baseline_seconds": baseline,
              "rate": args.rate, "low_rate": args.low_rate, "repeats": args.repeats, "quick": args.quick}
    summary = {"created_utc": stamp, "kernel": os.uname().release, "config": config, "trials": []}
    write_json(output / "environment.json", {"uname": list(os.uname()), "python": sys.version, "config": config,
               "tcpdump": subprocess.check_output(["tcpdump", "--version"], text=True)})
    packets = output / "packets"
    packets.mkdir()
    for kind in ("reset", "quench"):
        data = build_packet(kind)
        (packets / f"{kind}.bin").write_bytes(data)
        write_json(packets / f"{kind}.json", {**asdict(decode_packet(data)), "sha256": hashlib.sha256(data).hexdigest(), "hex": data.hex()})
    conditions = CONDITIONS + ([("kernel_reset", "kernel", "reset"), ("kernel_quench", "kernel", "quench")] if args.include_kernel else [])
    print(f"Evidence directory: {output}", flush=True)
    try:
        for repeat in range(1, args.repeats + 1):
            for condition, mode, kind in conditions:
                print(f"[{repeat}/{args.repeats}] Running {condition} ...", flush=True)
                result = trial(output, condition, mode, kind, repeat, config)
                baseline_row = next((r for r in summary["trials"] if r["repeat"] == repeat and r["condition"] == "baseline"), None)
                result["post_vs_baseline_percent"] = (100 * (baseline_row["post_goodput_mbps"] - result["post_goodput_mbps"]) / baseline_row["post_goodput_mbps"]
                                                       if baseline_row and baseline_row["post_goodput_mbps"] and result["post_goodput_mbps"] is not None else None)
                if baseline_row and kind != "reset" and mode != "legacy":
                    ratio = result["post_vs_baseline_percent"]
                    result["checks"]["post_rate_within_25_percent_of_baseline"] = ratio is not None and abs(ratio) <= 25
                if condition == "legacy_quench":
                    result["checks"]["completion_slower_than_baseline"] = result["elapsed_seconds"] > baseline_row["elapsed_seconds"] * 1.2
                result["passed"] = all(result["checks"].values())
                write_json(output / result["directory"] / "result.json", result)
                summary["trials"].append(result)
                write_json(output / "summary.json", summary)
                render(output)
                print(f"  {'PASS' if result['passed'] else 'FAIL'} | {result['bytes_received']} bytes | {result['overall_goodput_mbps']:.2f} Mbps | policy={result['decision']}", flush=True)
                for check, passed in result["checks"].items():
                    if not passed:
                        print(f"  Failed check: {check}", flush=True)
    except BaseException as exc:
        write_json(output / "failure.json", {"error": str(exc), "type": type(exc).__name__})
        raise
    finally:
        if not args.keep_lab:
            lab_network.down()
        lock.close()
    print(f"Report: {output / 'report.html'}", flush=True)
    return 0 if all(row["passed"] for row in summary["trials"]) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Trial interrupted; owned child processes and topology cleaned up.", file=sys.stderr)
        raise SystemExit(130)
    except (RuntimeError, OSError, subprocess.SubprocessError, ValueError) as exc:
        print(f"Trial error: {exc}", file=sys.stderr)
        raise SystemExit(1)
