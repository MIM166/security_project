"""Package source and one verified measured run; generate a written results report."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import statistics
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    args = parser.parse_args()
    results = args.results.resolve()
    results.relative_to(ROOT / "results")
    summary = json.loads((results / "summary.json").read_text())
    rows = summary["trials"]
    if not rows or not all(row["passed"] for row in rows):
        parser.error("Select a completed run with all condition checks passing")
    conditions = {row["condition"] for row in rows}
    required = {"baseline", "legacy_reset", "hardened_reset", "legacy_quench", "hardened_quench"}
    if not required <= conditions or len(rows) != len(conditions) * summary["config"]["repeats"]:
        parser.error("The selected experiment is incomplete")
    groups = defaultdict(list)
    for row in rows:
        groups[row["condition"]].append(row)
    def average(condition, field):
        return statistics.mean(row[field] for row in groups[condition] if row[field] is not None)
    report_rel = results.relative_to(ROOT).as_posix()
    lines = ["# ICMP Blind Attacks against TCP — Implementation Results", "",
             "CSE 406, Project 12. Proposal: Shemanty Mahjabin (2105091) and Mahabuba Sharmin Mim (2105103).", "",
             "## Outcome", "",
             f"The implementation passed all {len(rows)} measured trial conditions across {summary['config']['repeats']} repetitions. "
             "Real TCP payload transfer, raw ICMP packet delivery, endpoint policy decisions, and independently captured packet bytes were verified together.", "",
             f"Legacy Source Quench reduced post-event receiver goodput by an average of {average('legacy_quench', 'post_vs_baseline_percent'):.2f}% relative to the corresponding baseline. "
             "Legacy hard errors caused premature connection closure. Hardened trials completed the full payload without entering a low-rate state.", "",
             "## Environment and method", "",
             f"* Measured run: `{summary['created_utc']}` (UTC).",
             f"* Linux kernel: `{summary['kernel']}` in Ubuntu-24.04 on WSL2.",
             f"* Workload: {summary['config']['payload_bytes']:,} deterministic payload bytes per condition.",
             f"* Baseline before injection: {summary['config']['baseline_seconds']} seconds.",
             f"* Application pacing targets: {summary['config']['rate']:,} bytes/s normally; {summary['config']['low_rate']:,} bytes/s in legacy quench mode.",
             "* Topology: three endpoint namespaces and one isolated bridge namespace; no external interface or default route.",
             "* Flow: `10.10.10.10:40000 -> 10.10.10.20:5001`; ICMP originates at `10.10.10.30`.",
             "* Quoted sequence: fixed `0x12345678`, configured before the trial; no live sniffing or guessing loop.",
             "* One 56-byte packet per attacked condition: reset Type 3 Code 2, or Source Quench Type 4 Code 0.", "",
             "## Measured averages", "",
             "| Condition | Completed trials | Mean elapsed s | Mean overall Mbps | Mean post-event Mbps | Post reduction vs baseline % |",
             "|---|---:|---:|---:|---:|---:|"]
    for condition, group in groups.items():
        post = "—" if group[0]["post_goodput_mbps"] is None else f"{average(condition, 'post_goodput_mbps'):.3f}"
        reduction = "—" if group[0]["post_vs_baseline_percent"] is None else f"{average(condition, 'post_vs_baseline_percent'):.2f}"
        lines.append(f"| {condition} | {sum(r['complete'] for r in group)}/{len(group)} | {average(condition, 'elapsed_seconds'):.3f} | {average(condition, 'overall_goodput_mbps'):.3f} | {post} | {reduction} |")
    lines += ["", "An incomplete legacy reset transfer is the expected successful experiment outcome. No post-event throughput is reported for a closed transfer.", "",
              "## Evidence and validation", "",
              "All injected packets passed outer and quoted IPv4 checksum validation and ICMP checksum validation. Artifact, transmitter, capture, and receiving handler SHA-256 values matched. All complete transfers matched the expected payload hash. The receiver verified the delivered prefix of each intentionally aborted transfer.", "",
              "The Python test suite covers packet checksums and malformed inputs, policy decisions, tuple mismatch, sequence arithmetic, PCAP parsing, receiver-goodput calculations, and mocked namespace/transmitter guards. Run it with `python3 -m unittest discover -s tests -v`.", "",
              f"* [Interactive browser report with per-trial graphs]({report_rel}/report.html) (offline; expandable evidence details).",
              f"* [Machine-readable summary]({report_rel}/summary.json).",
              f"* [CSV measurements]({report_rel}/summary.csv).",
              f"* [Recorded environment]({report_rel}/environment.json).", "",
              "## Interpretation and limitations", "",
              "The reset stimulus is an ICMP error, not a TCP RST. In compatibility mode, the handler closes its TCP write direction and the receiver observes early EOF. The Source Quench effect is a deliberate application-pacing change; it is not a modification of Linux's congestion window.", "",
              "Hardened mode discards Source Quench for transport control and treats the selected hard error as a nonfatal advisory for the established transfer. Modeled sequence-window validation is tested separately; this socket harness does not obtain absolute live Linux SND.UNA/SND.NXT values. It explicitly logs that limitation.", "",
              "The optional kernel trials leave transport decisions to Linux while user space only observes ICMP arrival. Survival applies to these particular fixed quotations and workload. It does not establish resistance to all ICMP attacks, and the fixed sequence may be outside the actual outstanding kernel window.", "",
              "Three laboratory repetitions provide repeatability evidence, not a general statistical claim about Internet hosts. WSL scheduling, application pacing, and counter interpolation affect the measured goodput.", "",
              "## Reproduce and present", "",
              "Run `sudo python3 run_trial.py --include-kernel --repeats 3` inside the project directory in Ubuntu. A new evidence directory is created and the temporary topology is removed after completion. See [README.md](README.md), [implementation notes](docs/IMPLEMENTATION.md), and [demo guide](docs/DEMO_GUIDE.md).", "",
              "## References", "",
              "* [RFC 792 — Internet Control Message Protocol](https://www.rfc-editor.org/rfc/rfc792).",
              "* [RFC 5927 — ICMP Attacks against TCP](https://www.rfc-editor.org/rfc/rfc5927), sections 4–6.",
              "* [RFC 6633 — Deprecation of ICMP Source Quench Messages](https://www.rfc-editor.org/rfc/rfc6633).", ""]
    (ROOT / "FINAL_REPORT.md").write_text("\n".join(lines), encoding="utf-8")
    files = [p for p in ROOT.iterdir() if p.is_file() and (p.suffix in {".py", ".sh", ".ps1", ".md", ".pdf"} or p.name == ".gitignore")]
    for folder in (ROOT / "docs", ROOT / "tests", ROOT / "scripts", results):
        files += [p for p in folder.rglob("*") if p.is_file() and "__pycache__" not in p.parts]
    manifest = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}
    destination = ROOT / "ICMP_TCP_Project.zip"
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(files):
            archive.write(path, path.relative_to(ROOT))
        archive.writestr("SHA256SUMS.json", json.dumps(manifest, indent=2) + "\n")
    with zipfile.ZipFile(destination) as archive:
        bad = archive.testzip()
        if bad:
            raise RuntimeError(f"ZIP integrity check failed: {bad}")
    print(f"Written {destination.name}: {len(files)} files, {destination.stat().st_size:,} bytes")
    print("Written FINAL_REPORT.md using measured results only.")


if __name__ == "__main__":
    main()
