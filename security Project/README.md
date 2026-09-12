# ICMP blind attacks against TCP

Working implementation of the attached CSE 406 Project 12 proposal: **blind connection abort and blind throughput reduction**, with legacy and hardened user-space policies, real TCP transfers, original IPv4/ICMP construction, and packet-capture evidence.

No third-party Python packages are required. The project runs inside Ubuntu on WSL2 or native Linux. Your Ubuntu-24.04 installation already has Python 3, iproute2, and tcpdump.

The completed three-repetition WSL experiment passed **21/21 conditions**, and the unit suite passed **38/38 tests**. Start with [the measured final report](FINAL_REPORT.md), [the browser report](results/20260912T151534_514585Z/report.html), or [the exported PDF](results/20260912T151534_514585Z/report.pdf). The full package is `ICMP_TCP_Project.zip`.

## Run from Windows PowerShell

Open PowerShell in this project folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\Run-Lab.ps1
```

This creates an isolated network, runs the five proposal conditions, saves an HTML report, and cleans up the network. Expect approximately one minute. `-ExecutionPolicy Bypass` applies to this PowerShell process; it does not change your saved execution policy.

For a short smoke test or a repeated demonstration with the optional kernel comparisons:

```powershell
powershell -ExecutionPolicy Bypass -File .\Run-Lab.ps1 -Quick
powershell -ExecutionPolicy Bypass -File .\Run-Lab.ps1 -IncludeKernel -Repeats 3
```

Each run prints the path to `results/<timestamp>/report.html`. Double-click that file to view the results in a browser. It works offline and can be printed to PDF. Open a trial's `capture.pcap` in Wireshark for independent packet inspection.

## Run directly inside Ubuntu / WSL

```bash
cd '/mnt/c/Users/shema/Documents/2.security Project'
python3 -m unittest discover -s tests -v
sudo python3 run_trial.py
```

Optional commands:

```bash
sudo python3 run_trial.py --quick --include-kernel
sudo python3 run_trial.py --include-kernel --repeats 3
sudo bash setup_lab.sh doctor
sudo bash setup_lab.sh up
sudo bash setup_lab.sh status
sudo bash setup_lab.sh down
```

On a different Ubuntu installation, install missing system tools with `sudo apt update && sudo apt install python3 iproute2 tcpdump`. Wireshark is optional and is only an observer.

## What the demonstration proves

| Condition | Packet | Expected measured behavior |
|---|---|---|
| Baseline | None | Full payload, steady receiver goodput |
| Legacy reset | ICMP Type 3 Code 2 | Handler closes the sending side; receiver sees premature EOF |
| Hardened reset | Identical Type 3 Code 2 bytes | Nonfatal advisory; complete transfer |
| Legacy quench | ICMP Type 4 Code 0 | Application pacing falls from 1 MiB/s to 256 KiB/s; complete but slower transfer |
| Hardened quench | Identical Type 4 Code 0 bytes | Discard for transport control; complete transfer near baseline rate |
| Optional kernel reset/quench | Same two packets | Observer logs arrival without applying a user-space control action |

Default configuration: 8 MiB deterministic payload, source port 40000, destination port 5001, and five seconds of transfer before one ICMP injection. The fixed quoted sequence is `0x12345678`. Identical binary packet files are reused across policy modes and repetitions.

The legacy behavior is an educational compatibility implementation. The abort is caused by the application's ICMP handler closing its TCP write direction, producing FIN/EOF; **the injected packet is not a TCP RST**. The throughput effect changes application pacing, not Linux's congestion window. The kernel comparison demonstrates survival of this particular fixed quotation and workload, not comprehensive kernel security.

The policy module includes tested, wraparound-aware sequence-window validation for a supplied modeled `SND.UNA`/`SND.NXT` range. Normal Python TCP sockets do not expose the live absolute kernel sequence range through this implementation, so real trials explicitly log that validation as unavailable. Hardened protection in those trials comes from nonfatal established-flow handling and Source Quench discard.

## Network layout

```text
c406-client              c406-server              c406-attacker
10.10.10.10              10.10.10.20               10.10.10.30
TCP 40000  ------------> TCP 5001                  fixed ICMP builder
      \                     |                      /
       +---------------- br-lab ------------------+
                    c406-switch namespace
                    independent tcpdump observer
```

There are three endpoint namespaces as proposed, plus one infrastructure namespace containing the bridge. Keeping the bridge in its own namespace gives the topology no interface into the host, Docker, WSL uplink, or Internet. Endpoints have only a connected lab-subnet route and no default route. Existing Docker bridges and host firewall/forwarding settings are untouched.

The attacker never captures packets or reads TCP endpoint logs. It receives only a prebuilt fixed packet and an externally scheduled launch. The coordinator times the trial from the sender's readiness event; packet observations are used only for assessment. The raw transmitter accepts only the two exact project packets and requires the attacker namespace. This models known laboratory flow identifiers, not discovery of an unknown flow.

## Files

| File | Purpose |
|---|---|
| `setup_lab.sh`, `lab_network.py` | Ownership-aware topology creation, verification, and removal |
| `icmp_builder.py` | Original `socket`/`struct` IPv4 and ICMP serialization, checksums, decoding, fixed lab injection |
| `icmp_policy.py` | Legacy, hardened, and observational decisions; modeled sequence-range checks |
| `tcp_sender.py` | Real TCP workload, raw ICMP reception, pacing, and endpoint decision evidence |
| `tcp_receiver.py` | Delivered-byte counters, deterministic payload verification, SHA-256, completion receipt |
| `run_trial.py` | Synchronized trials, packet capture, outcome checks, repetitions, cleanup |
| `evidence.py` | Independent PCAP inspection and receiver-goodput window calculations |
| `report.py` | Offline HTML charts, CSV, JSON-backed summary, and Markdown results |
| `Run-Lab.ps1` | Windows launcher targeting Ubuntu-24.04 |
| `tests/` | Packet correctness, malformed inputs, policy behavior, sequence arithmetic, evidence calculations |
| `docs/DEMO_GUIDE.md` | Presentation steps, Wireshark inspection, and explanation prompts |
| `docs/IMPLEMENTATION.md` | Design mapping, protocol details, measurement method, and limitations |

## Evidence and pass criteria

Each timestamped output directory contains:

* `report.html`, `RESULTS.md`, `summary.csv`, `summary.json`, and `environment.json`.
* `packets/reset.bin` and `packets/quench.bin`, with decoded fields and SHA-256 in adjacent JSON files.
* One subdirectory per condition/repetition containing `capture.pcap`, `capture.txt`, `sender.jsonl`, `receiver.jsonl`, `attacker.jsonl` when applicable, `topology.json`, `result.json`, and process logs.

Success requires agreement between the captured packet hash, transmitted packet hash, endpoint receipt hash, policy decision, receiver-delivered bytes, and transfer outcome. Payload bytes are verified as they arrive; complete transfers are also checked against the expected SHA-256. Hardened goodput must remain within 25% of the trial's pre-event goodput; hardened quench is also compared to the baseline condition. Legacy quench must reduce its post-event rate by at least 50% and finish at least 20% later than baseline. A failed check produces a nonzero exit code and remains visible in the report.

Receiver samples are logged roughly every 0.5 seconds. Window calculations interpolate cumulative counters, skip the event transition, and exclude the end-of-transfer tail. Default before-event window starts at 0.5 seconds and ends 0.2 seconds before ICMP; after-event window runs from 0.5 to 2.5 seconds after arrival, shortened if necessary. This is an application-goodput experiment, not a link-capacity benchmark.

## Troubleshooting

* **WSL access denied from a restricted terminal:** run the launcher in your normal Windows PowerShell session. Ubuntu uses root only for namespaces and raw sockets.
* **`Operation not permitted` creating namespaces:** verify you are on WSL2 and running Linux commands with `sudo`. This needs namespace support; Windows Python cannot run the networking experiment.
* **Namespace collision or ownership error:** the setup intentionally refuses to replace unrelated resources. Its state record is `/run/c406-icmp-lab.json`; inspect the error and `sudo ip netns list`. Do not delete arbitrary namespaces.
* **An interrupted trial left processes running:** inspect `sudo ip netns pids c406-client` (and server/attacker/switch). Stop the identified lab process, then use `sudo bash setup_lab.sh down`. Normal completion and Ctrl+C clean up automatically.
* **Performance check fails on a busy machine:** retain the evidence, close competing heavy workloads, and repeat. The report must show actual results even when a tolerance fails.
* **tcpdump shows quoted TCP truncation:** the quotation intentionally contains the first 8 TCP bytes, as specified for this ICMP layout. The original quoted IP length describes a full TCP header; only a prefix is carried by ICMP. A decoder may print the remaining TCP header as truncated. The outer packet is a complete 56-byte ICMP datagram with validated checksums.
* **TCP checksum warnings in Wireshark:** veth offloading and the 128-byte capture snapshot can prevent full TCP checksum verification. Full ICMP packets fit in the capture and all their IPv4/ICMP checksums are independently verified.

## References

* [RFC 792 — ICMP error packet format](https://www.rfc-editor.org/rfc/rfc792)
* [RFC 5927 — ICMP attacks against TCP, sections 4–6](https://www.rfc-editor.org/rfc/rfc5927)
* [RFC 6633 — Source Quench deprecation](https://www.rfc-editor.org/rfc/rfc6633)
* [RFC 1122 — historical host requirements](https://www.rfc-editor.org/rfc/rfc1122)

The supplied PDF remains unchanged. Review the implementation and generated evidence before presenting or submitting it.
