# ICMP Blind Attacks against TCP — Implementation Results

CSE 406, Project 12. Proposal: Shemanty Mahjabin (2105091) and Mahabuba Sharmin Mim (2105103).

## Outcome

The implementation passed all 21 measured trial conditions across 3 repetitions. Real TCP payload transfer, raw ICMP packet delivery, endpoint policy decisions, and independently captured packet bytes were verified together.

Legacy Source Quench reduced post-event receiver goodput by an average of 74.31% relative to the corresponding baseline. Legacy hard errors caused premature connection closure. Hardened trials completed the full payload without entering a low-rate state.

## Environment and method

* Measured run: `20260912T151534_514585Z` (UTC).
* Linux kernel: `6.6.87.2-microsoft-standard-WSL2` in Ubuntu-24.04 on WSL2.
* Workload: 8,388,608 deterministic payload bytes per condition.
* Baseline before injection: 5 seconds.
* Application pacing targets: 1,048,576 bytes/s normally; 262,144 bytes/s in legacy quench mode.
* Topology: three endpoint namespaces and one isolated bridge namespace; no external interface or default route.
* Flow: `10.10.10.10:40000 -> 10.10.10.20:5001`; ICMP originates at `10.10.10.30`.
* Quoted sequence: fixed `0x12345678`, configured before the trial; no live sniffing or guessing loop.
* One 56-byte packet per attacked condition: reset Type 3 Code 2, or Source Quench Type 4 Code 0.

## Measured averages

| Condition | Completed trials | Mean elapsed s | Mean overall Mbps | Mean post-event Mbps | Post reduction vs baseline % |
|---|---:|---:|---:|---:|---:|
| baseline | 3/3 | 8.262 | 8.123 | 8.093 | — |
| legacy_reset | 0/3 | 5.110 | 8.122 | — | — |
| hardened_reset | 3/3 | 8.247 | 8.138 | 8.101 | -0.09 |
| legacy_quench | 3/3 | 17.462 | 3.843 | 2.079 | 74.31 |
| hardened_quench | 3/3 | 8.279 | 8.106 | 8.085 | 0.10 |
| kernel_reset | 3/3 | 8.289 | 8.097 | 8.059 | 0.43 |
| kernel_quench | 3/3 | 8.283 | 8.102 | 8.087 | 0.08 |

An incomplete legacy reset transfer is the expected successful experiment outcome. No post-event throughput is reported for a closed transfer.

## Evidence and validation

All injected packets passed outer and quoted IPv4 checksum validation and ICMP checksum validation. Artifact, transmitter, capture, and receiving handler SHA-256 values matched. All complete transfers matched the expected payload hash. The receiver verified the delivered prefix of each intentionally aborted transfer.

The Python test suite covers packet checksums and malformed inputs, policy decisions, tuple mismatch, sequence arithmetic, PCAP parsing, receiver-goodput calculations, and mocked namespace/transmitter guards. Run it with `python3 -m unittest discover -s tests -v`.

* [Interactive browser report with per-trial graphs](results/20260912T151534_514585Z/report.html) (offline; expandable evidence details).
* [Machine-readable summary](results/20260912T151534_514585Z/summary.json).
* [CSV measurements](results/20260912T151534_514585Z/summary.csv).
* [Recorded environment](results/20260912T151534_514585Z/environment.json).

## Interpretation and limitations

The reset stimulus is an ICMP error, not a TCP RST. In compatibility mode, the handler closes its TCP write direction and the receiver observes early EOF. The Source Quench effect is a deliberate application-pacing change; it is not a modification of Linux's congestion window.

Hardened mode discards Source Quench for transport control and treats the selected hard error as a nonfatal advisory for the established transfer. Modeled sequence-window validation is tested separately; this socket harness does not obtain absolute live Linux SND.UNA/SND.NXT values. It explicitly logs that limitation.

The optional kernel trials leave transport decisions to Linux while user space only observes ICMP arrival. Survival applies to these particular fixed quotations and workload. It does not establish resistance to all ICMP attacks, and the fixed sequence may be outside the actual outstanding kernel window.

Three laboratory repetitions provide repeatability evidence, not a general statistical claim about Internet hosts. WSL scheduling, application pacing, and counter interpolation affect the measured goodput.

## Reproduce and present

Run `sudo python3 run_trial.py --include-kernel --repeats 3` inside the project directory in Ubuntu. A new evidence directory is created and the temporary topology is removed after completion. See [README.md](README.md), [implementation notes](docs/IMPLEMENTATION.md), and [demo guide](docs/DEMO_GUIDE.md).

## References

* [RFC 792 — Internet Control Message Protocol](https://www.rfc-editor.org/rfc/rfc792).
* [RFC 5927 — ICMP Attacks against TCP](https://www.rfc-editor.org/rfc/rfc5927), sections 4–6.
* [RFC 6633 — Deprecation of ICMP Source Quench Messages](https://www.rfc-editor.org/rfc/rfc6633).
