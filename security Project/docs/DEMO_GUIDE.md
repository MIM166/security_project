# Demonstration guide

## Before presenting

1. Open Ubuntu and change to the project directory shown in `README.md`.
2. Run `python3 -m unittest discover -s tests -v`.
3. Run `sudo python3 run_trial.py --include-kernel`. For repeatability evidence, add `--repeats 3`.
4. Open the generated `report.html` in Windows. Keep the run's folder open in Explorer.
5. Open `01_legacy_reset/capture.pcap` in Wireshark, or follow the report's PCAP link. The directory prefix is the repetition number.

## Suggested presentation sequence

### 1. Establish the scope

“This project studies unauthenticated ICMP feedback associated with a known TCP flow. The attacker is a separate, non-forwarding namespace. We fix the addresses, ports, and quoted sequence before the trial. We demonstrate historical reactions through an explicit compatibility handler.”

Show the topology diagram in `README.md` and a trial's `topology.json`. There is no default route and no link to the WSL uplink.

### 2. Explain the generated packet

Show `packets/reset.json`, then:

```bash
python3 icmp_builder.py decode results/<run>/packets/reset.bin
```

The packet is 56 bytes: 20-byte outer IPv4 header, 8-byte ICMP header, 20-byte quoted IPv4 header, and 8-byte quoted TCP prefix. Reset uses Type 3 Code 2; throughput reduction uses Type 4 Code 0. Checksums are computed in the project's own code.

### 3. Show legacy connection abort

Open `01_legacy_reset/capture.pcap` in Wireshark and apply `icmp`. Expand both IPv4 headers and the quoted TCP prefix. The outer destination is `10.10.10.10`; the quotation identifies `10.10.10.10:40000 -> 10.10.10.20:5001`.

Show the matching `icmp_decision` in `sender.jsonl`: `action=abort`. Show the receiver's final incomplete byte count, premature EOF, and the report's failed-to-complete transfer outcome (the **experiment itself passes** because this is expected).

Use `tcp.flags.fin == 1` to show closure. Explain that the forged packet is ICMP, not TCP RST.

### 4. Show hardened connection survival

Open the hardened reset card and sender log: `action=advisory`, complete payload, verified SHA-256. Compare `packet_sha256` in legacy/hardened `result.json`; they match. Only the selected endpoint policy differs.

### 5. Show throughput reduction and defense

Show the legacy quench graph: received-payload goodput falls after the event, the transfer remains open, and completion is delayed. Show `action=slow` and `low_rate_entered=true`.

Show the hardened quench graph and `action=ignore`: full payload, no low-rate state, and goodput close to baseline. State that application pacing reproduces the historical effect; the experiment does not manipulate Linux's TCP congestion window.

### 6. Explain current-kernel comparison and limits

In optional `kernel_*` cards, user-space handling records `observe` and does not control the socket. The actual kernel received the same fixed packet. Survival is an observation for this setup; a fixed quoted sequence may not correspond to live outstanding kernel data.

## Useful Wireshark filters

| Filter | Purpose |
|---|---|
| `icmp` | Both generated ICMP messages |
| `icmp.type == 3 && icmp.code == 2` | Protocol-unreachable reset stimulus |
| `icmp.type == 4 && icmp.code == 0` | Source Quench stimulus |
| `tcp.port == 5001` | The fixed transfer |
| `tcp.flags.fin == 1` | Connection closure evidence |
| `tcp.flags.reset == 1` | Check for actual TCP resets; not the injected mechanism |

In Wireshark preferences, enable IPv4 and ICMP checksum validation if it is disabled. `capture.txt` is a pre-generated tcpdump decoding for machines without Wireshark.

## Questions to prepare for

**Why is it blind if the four-tuple is known?** The attacker has preconfigured flow identifiers but observes no live data/ACK stream. This is a controlled trust-decision experiment, not a demonstration of unknown-flow discovery.

**Why does the quoted original IP total length say 40 while only 28 quoted bytes are present?** The original datagram contains at least a 20-byte TCP header. An ICMP error carries only the original IP header and the first 8 transport bytes in this design.

**What does the sequence check prove?** Unit tests validate the conceptual serial-number comparison, including wraparound. The live socket experiment does not claim to read Linux SND.UNA/SND.NXT. The report states this limitation.

**Why not block all ICMP?** ICMP also carries useful error feedback, including information used for path MTU discovery. This experiment isolates hard-error and deprecated Source Quench handling, rather than designing a complete ICMP firewall.

**Can the same packets affect a modern Linux kernel?** The optional kernel trial records what happens here. The user-space compatibility effect must not be presented as a Linux vulnerability. TCP is required to discard Source Quench for transport control by RFC 6633.

**What makes the result credible?** Independent PCAP bytes, checksums and hashes, logged policy decisions, receiver payload verification, timing measurements, and repeated trials agree.
