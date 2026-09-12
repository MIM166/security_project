# Implementation and proposal mapping

## Architecture

The supplied design proposal is implemented with Python's standard library and Linux networking tools. The data plane is the actual Linux TCP stack. An ICMP raw socket at the client receives a copy of the ICMP datagram, and a selected user-space policy applies the educational compatibility response. This is an experiment harness, not a complete user-space TCP implementation.

`run_trial.py` prepares exactly two packet artifacts before starting endpoint traffic. Every legacy, hardened, and optional kernel trial reuses those bytes. A switch-namespace tcpdump observer records traffic, but no capture or inferred live sequence number is supplied to the attacker. Each trial starts with a fresh topology to avoid residual sockets, TIME_WAIT and route-cache effects from previous conditions.

The client binds to `10.10.10.10:40000`; the server listens on `10.10.10.20:5001`. A small JSON header declares the expected payload length and the receiver sends an `OK` readiness acknowledgement. These protocol bytes are excluded from payload goodput. The client sends a deterministic repeating byte pattern. The receiver verifies it incrementally and returns a final byte-count/hash receipt after EOF.

## Packet layout

| Offset | Bytes | Meaning |
|---:|---:|---|
| 0 | 20 | Outer IPv4: source .30, destination .10, protocol 1, total length 56 |
| 20 | 8 | ICMP: Type 3 Code 2 or Type 4 Code 0, checksum, zero unused word |
| 28 | 20 | Quoted IPv4: source .10, destination .20, protocol 6, original total length 40 |
| 48 | 8 | Quoted TCP prefix: source 40000, destination 5001, sequence 0x12345678 |

The quoted total length describes the original datagram, not the available quotation. The encoder uses big-endian `struct.pack`, one's-complement checksum arithmetic, and `IP_HDRINCL`. Ethernet addressing is supplied by the kernel. The kernel may normally rewrite some `IP_HDRINCL` fields; the lab supplies nonzero identification/source and verifies the actual captured bytes against its artifacts instead of assuming byte identity.

The decoder checks version, header length, total length, IPv4 checksums, ICMP checksum, absence of unsupported fragmentation/reserved flags, quoted protocol, available TCP prefix, and supported type/code. It supports IPv4 header options by using each IHL. Only the fixed packet generator is exposed for transmission; there is no arbitrary target, spoofed source, packet flood, tuple scan, or sequence-search interface.

## Policy

All modes require valid syntax/checksums and the matching endpoint tuple. Legacy mode treats the selected hard error as fatal and Source Quench as a persistent low-pacing trigger for the remainder of the transfer. Hardened mode leaves hard errors nonfatal and discards Source Quench for transport control. Other accepted ICMP Type 3 codes are advisory in this narrowly scoped harness; it does not implement a complete PMTUD policy.

The optional `sequence_window` parameter in `icmp_policy.decide` provides a conceptual outstanding-data validation step. Serial arithmetic uses a half-open interval and handles 32-bit wraparound. Empty or ambiguous intervals at least half the sequence space wide are rejected. This parameter is unit tested and is not populated with fabricated kernel state in real trials.

## Timing and measurement

All processes share the WSL kernel's monotonic clock. The coordinator waits for receiver readiness and sender transfer start, then launches one fixed packet transmission after the configured baseline period. Logs contain both monotonic time for calculations and wall time for PCAP alignment.

Goodput is useful payload bytes delivered divided by elapsed receiver transfer time, multiplied by eight. MiB means 1,048,576 bytes; Mbps uses 1,000,000 bits per second. The baseline application target is 1 MiB/s, or approximately 8.39 Mbps before scheduling overhead. The legacy low-rate target is 256 KiB/s, approximately 2.10 Mbps. Configured targets are not substituted for measured receiver results.

Before/after rates use interpolated cumulative byte counters sampled approximately twice per second. The pre-event window skips initial startup and ends 0.2 seconds before arrival. The post-event window skips the first 0.5 seconds after arrival and ends at 2.5 seconds after arrival or 0.1 seconds before transfer end, whichever comes first. A reset trial has no usable post-event throughput window; the report shows it as absent rather than zero.

Within-trial reduction is `100 * (pre - post) / pre`. Cross-condition reduction is `100 * (baseline_post - attacked_post) / baseline_post`, matched by repetition. A negative value means the measured trial was slightly faster than baseline. Small deviations are expected from scheduling and sampling.

Default thresholds are declared before assessment: at least 50% legacy quench rate reduction, at least 20% longer completion than baseline, and at most 25% hardened rate deviation. Payload consistency and matching independent packet evidence are mandatory. This is a classroom experiment with three repetitions available, not a statistical estimate of Internet-scale exploit reliability.

## Isolation and lifecycle

Three endpoint namespaces connect to an unnumbered bridge inside a fourth infrastructure namespace. No veth endpoint is attached to the host network. Setup checks for collisions and keeps an ownership record under `/run`; cleanup removes only the recorded namespaces associated with this project. It refuses cleanup while processes remain inside them. The runner owns and stops its own subprocesses, serializes concurrent runs with a file lock, preserves failed evidence, and normally cleans up in a `finally` block.

The optional `--keep-lab` switch retains the final topology for inspection. Cleanup is `sudo bash setup_lab.sh down`. No global firewall rules, default routes, Docker configuration, or host forwarding settings are changed.

## Proposal coverage

| Proposal requirement | Implementation/evidence |
|---|---|
| Original IPv4/ICMP construction | `icmp_builder.py`, known-vector checksum tests, PCAP validation |
| Three isolated endpoint roles | `lab_network.py`, saved per-trial topology |
| Off-path attacker with fixed identifiers | Separate attacker namespace and two prebuilt packets |
| Five-second baseline | Default trial schedule and timestamp pass check |
| Legacy hard-error abort | `abort` event, FIN/EOF, incomplete receiver payload |
| Hardened nonfatal hard error | `advisory` event, complete/hash-verified receiver payload |
| Legacy throughput reduction | `slow` event, measured pre/post goodput, delayed completion |
| Hardened Source Quench discard | `ignore` event, full payload, near-baseline goodput |
| Identical packets across modes | SHA-256 agreement among artifacts, transmitter, capture, endpoint |
| Packet analyzer evidence | PCAP plus `tcpdump -vvv -XX` decode |
| Endpoint and performance evidence | JSONL events, receiver byte/hash verification, CSV and HTML charts |
| Up to three repetitions | `--repeats 3` |
| Optional modern Linux observation | `--include-kernel` |

## Limitations to retain in the final presentation

* The low-rate and abort behaviors are application compatibility policies, not an obsolete TCP stack or demonstrated modern Linux vulnerability.
* Fixed flow identifiers and sequence values do not measure the cost of discovering or guessing an unknown connection.
* Actual kernel outstanding sequence bounds are not available to this implementation; sequence-window checks are separately modeled and tested.
* Capturing packets in the switch namespace is observer-only, not part of the attacker's strategy. Linux network namespaces are an experimental topology, not a filesystem/privilege security boundary between hostile users.
* Veth/WSL timing differs from physical-network timing. Payload samples and interpolation introduce finite resolution.
* Kernel-observation results apply only to the packets, workload, and kernel version recorded in `environment.json`.

## Primary references

[RFC 792](https://www.rfc-editor.org/rfc/rfc792) specifies the ICMP quotation layout. [RFC 5927, sections 4–6](https://www.rfc-editor.org/rfc/rfc5927) discusses sequence validation, hard-error connection abort, and historical throughput reduction. [RFC 6633](https://www.rfc-editor.org/rfc/rfc6633) requires TCP to discard Source Quench. The report uses these sources to interpret measured behavior while retaining the limitations above.
