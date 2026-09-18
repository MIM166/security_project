# HANDOFF — ICMP blind attack lab: session notes & demo playbook

Written for: a future Claude Code session (and the project owner / a teammate) that
continues this work on another machine. Read this file first to recover full context.

This captures a working session where the goal was to **run and demonstrate the
ICMP-blind-attack-against-TCP lab**, first on a macOS (Apple M1) laptop via Docker,
and then across two real machines / a dual-boot Ubuntu.

---

## 1. What the project is

- CSE 406 Project 12: **blind connection abort** and **blind throughput reduction**
  using unauthenticated ICMP feedback tied to a known TCP flow.
- Pure Python, no third-party packages. Designed for **Linux / WSL2**.
- Key files:
  - `tcp_receiver.py` — server (plain TCP, verifies payload).
  - `tcp_sender.py` — **client**; opens a RAW ICMP socket and applies a user-space
    policy (legacy / hardened) when an ICMP arrives. **This is the vulnerable piece.**
  - `icmp_builder.py` — attacker; crafts + sends raw IPv4/ICMP (build / decode / send).
  - `lab_common.py` — constants: `CLIENT`, `SERVER`, `CLIENT_PORT=40000`,
    `SERVER_PORT=5001`, `LAB_SEQUENCE=0x12345678`; and `require_namespace()`.
  - `lab_network.py` — builds the 3-namespace + bridge lab (`up/down/status/doctor`).
  - `run_trial.py` — orchestrates the full 5-condition experiment + report.
- Attack packets: **reset = ICMP type 3 code 2**, **quench = ICMP type 4 code 0**.

**Crucial fact:** the abort/slow effect is ONLY visible against this project's own
`tcp_sender.py` client, because that client voluntarily reads ICMP and reacts.
It does NOT work against `iperf` or any normal app — modern kernels ignore Source
Quench (RFC 6633) and treat hard errors on established connections as non-fatal.

---

## 2. Changes made this session (already committed & pushed)

Commit `dcca997` on branch `main`, pushed to remote **`mim166`**
(`https://github.com/MIM166/security_project.git`). The original `origin`
(ShemantyMahjabin/...) was left untouched.

**`lab_network.py` — two Docker/Ubuntu-24.04 compatibility fixes** (behavior-preserving;
needed because the lab was built on WSL2 whose kernel differs from Docker's LinuxKit):
1. `ns_names()` guards an empty string from `ip -j netns list` (iproute2 6.1.0 returns
   `""` not `[]` when no namespaces exist) — otherwise `json.loads` crashed.
2. `status()` interface validator filters kernel fallback tunnel devices
   (`tunl0, gre0, gretap0, erspan0, ip_vti0, ip6_vti0, sit0, ip6tnl0, ip6gre0`) that
   Docker's kernel auto-creates in every new namespace. Routes/addresses are still
   validated strictly, so isolation is unchanged.

**New presentation helper scripts** (not part of the graded experiment; safe to delete):
- `demo_live.sh {legacy|hardened}` — single-screen live demo with a switch-side
  `tcpdump` view showing client→server data, the one ICMP attack packet, then FIN.
- `demo_story.sh` — runs the full **four-act story** automatically and writes readable
  per-act logs to `demo/act1_*.jsonl` … `demo/act4_*.jsonl`.
- `demo_role.sh {up | server [LABEL] | client [legacy|hardened] [LABEL] |
  attacker [reset|quench] [LABEL] | down}` — **3-terminal role-based** live demo; each
  terminal plays one machine and prints a human-readable result. LABEL keeps each act's
  log separate under `demo/`.

Untracked/ignored locally (NOT pushed): `demo/` logs, stray `reset.bin`,
`demo_server.jsonl`. `results/` is git-ignored.

---

## 3. The four-act demo (the story to present)

| ACT | attacker | client mode | result | teaches |
|-----|----------|-------------|--------|---------|
| 1 | none | legacy | COMPLETE | baseline: no attack = full transfer |
| 2 | RESET (3/2) | legacy | action=abort, INCOMPLETE | one packet kills a legacy connection |
| 3 | QUENCH (4/0) | legacy | action=slow, COMPLETE but slower | attacker throttles without dropping data |
| 4 | RESET (3/2) | hardened | action=advisory, COMPLETE | SAME packet, hardened survives (defense) |

Strongest point: **ACT 2 vs ACT 4 — identical attack packet, only the client policy
differs.** All four verified consistent in this session (payload SHA matches on
completed transfers; ACT2 hash differs because it is incomplete).

---

## 4. How to RUN

### A. Native Ubuntu / dual-boot (easiest — no Docker, no VM)
```bash
cd "<repo>/security Project"
python3 -m unittest discover -s tests -v          # 38/38
sudo python3 run_trial.py --include-kernel        # full experiment + report.html
# or the 3-terminal live story:
sudo bash demo_role.sh up
#   T1: sudo bash demo_role.sh server act2
#   T2: sudo bash demo_role.sh client legacy act2
#   T3: sudo bash demo_role.sh attacker reset act2
sudo bash demo_role.sh down
```
(On native Linux `demo_role.sh`/`demo_story.sh` run under `sudo` directly.)

### B. macOS (Apple M1) via Docker
macOS has no `ip netns`/raw-socket lab support, so use a privileged Ubuntu container.
Docker Desktop must be running.
```bash
docker run --rm -it --privileged \
  -v "<abs path>/security Project":/lab -w /lab ubuntu:24.04 bash
# inside:
apt-get update && apt-get install -y python3 iproute2 tcpdump
bash demo_story.sh                # or demo_live.sh legacy / demo_role.sh ...
```
Results land in `security Project/results|demo/` on the Mac (mounted).
If `apt-get`/containers hang: restart Docker Desktop and `docker rm -f` stale containers.

---

## 5. TWO-MACHINE demo (dual-boot + two laptops)

Goal topology: **Machine A = server + client**, **Machine B = attacker**, over a
**private LAN you control** (own hotspot/router — never a public/university network).

Hard rules:
- Whichever machine runs the **client** must be **Linux, root, on the LAN**.
- macOS → bridged Linux VM (UTM); Windows → bridged VirtualBox VM **or** WSL2 with
  `networkingMode=mirrored` (Windows 11 22H2+); native Ubuntu → run directly.
  Default WSL2 (NAT) and Docker Desktop do NOT put you on the LAN — they won't work.
- **iPad cannot be the attacker** (sandboxed, no raw sockets).

Ease ranking (easiest → hardest): two native Ubuntu laptops > Win11 WSL-mirrored + Ubuntu
> bridged VirtualBox/UTM VM + Ubuntu > two VMs. Put the attacker on a native Ubuntu box
when possible (zero setup). Bridged VirtualBox VM is the most reliable on demo day.

Edits (do them on a COPY so the graded lab stays intact; ask the owner first):
1. `lab_common.py`: `CLIENT = "A_IP"` and `SERVER = "A_IP"` (both endpoints run on
   Machine A → same IP, different ports).
2. `lab_common.py` `require_namespace()` → keep only the root check, then `return`:
   ```python
   def require_namespace(role):
       import os
       if os.geteuid() != 0:
           raise RuntimeError("run with sudo")
       return
   ```
3. Put the same edited code on BOTH machines. Verify `ping A_IP` works.

Run:
```bash
# Machine A (find A_IP with: ip addr)
sudo python3 tcp_receiver.py --payload-bytes 4194304 --timeout 120 --log server.jsonl
sudo python3 tcp_sender.py  --mode legacy --payload-bytes 4194304 --rate 262144 --log client.jsonl
# Machine B, 3-5 s after the client starts
sudo python3 icmp_builder.py build reset reset.bin
sudo python3 icmp_builder.py send reset.bin --log attacker.jsonl
```
Expect: legacy+reset → client `action=abort`, server INCOMPLETE; `--mode hardened` →
survives; `quench` → `action=slow`. Optional: run `iperf3` as a control to show a modern
kernel ignores the same packet.

---

## 6. Git state & next steps

- Remote `mim166` → `https://github.com/MIM166/security_project.git`, branch `main`,
  latest relevant commit `dcca997` (+ this HANDOFF commit).
- To push more:  `git add … && git commit -m "…" && git push mim166 main`
- Owner preference: **ask before modifying any project files.**
- Open next step (not yet done): create the edited two-machine COPY of the project
  (`lab_common.py` IP + `require_namespace` bypass) once the second machine is chosen.
