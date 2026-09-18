# Two-machine LAN demo (attacker on Ubuntu, client+server on WSL)

This is an **edited COPY** of the graded lab, changed only so the attack can run
across two real machines on one private LAN. The graded namespace lab in the parent
folder is untouched.

Layout for this demo:
- **Machine A = friend's WSL** -> runs **server AND client** (both on the same host,
  so they share one IP `A_IP`, differing only by port: client 40000, server 5001).
- **Machine B = your Ubuntu** -> runs the **attacker** (fires one forged ICMP at A_IP).

The only packet that crosses machines is the single forged ICMP (B -> A). The whole
TCP transfer happens inside Machine A.

## What changed vs the graded lab (all in this folder only)
- `lab_common.py`: CLIENT/SERVER/ATTACKER/ports now read from environment variables;
  `require_namespace()` only checks for root (no `ip netns` on a real LAN).
- `icmp_builder.py`: `LAB_NET` (the allowed address range) now reads from env `LAB_NET`.
- `tcp_receiver.py`, `tcp_sender.py`, `icmp_policy.py`: copied verbatim.
- `net_demo.sh`: runner for the server / client / attacker roles.

## HARD RULES (do not skip)
1. Use a **private LAN you control** (a phone hotspot or your own router). **Never** a
   university/public network. (AP/client isolation there will also block the attack.)
2. The machine running the **client** must be Linux, **root**, and truly **on the LAN**.
3. Default WSL2 (NAT) and Docker Desktop do NOT put you on the LAN. WSL needs
   **mirrored** networking (Windows 11 22H2+), see Step 1.

---

## Step 0 - get both machines on the same private LAN, find the IPs
Connect both to the same phone hotspot / router. Then:

- On **your Ubuntu (B)**:  `ip -4 addr show scope global`  -> note `B_IP`
- On **friend's WSL (A)** (after Step 1): `ip -4 addr show scope global` -> note `A_IP`

Both must be in the same subnet, e.g. `192.168.x.0/24`. That subnet is `LAB_NET`.

## Step 1 - friend's WSL: enable mirrored networking (Machine A only)
Default WSL is NAT and will NOT receive the attacker's packet. On the friend's
**Windows** machine (Win 11 22H2+), create/edit `%UserProfile%\.wslconfig`:

```
[wsl2]
networkingMode=mirrored
```

Then in PowerShell: `wsl --shutdown`, and reopen Ubuntu/WSL.
Verify inside WSL: `ip -4 addr show scope global` now shows the Windows LAN IP (`A_IP`,
same as `ipconfig` on Windows).

**Windows firewall:** unsolicited inbound ICMP is blocked by default. In an
**Administrator PowerShell** on the friend's Windows machine, allow ICMPv4 inbound
(for the demo only; remove it afterward):

```powershell
New-NetFirewallRule -DisplayName "LAB ICMPv4-In" -Protocol ICMPv4 -IcmpType Any -Direction Inbound -Action Allow -Profile Any
```
Remove later with:
```powershell
Remove-NetFirewallRule -DisplayName "LAB ICMPv4-In"
```

(If WSL inbound ICMP still won't cooperate, the easiest fallback is to make the
**native-Linux machine the client host**. e.g. swap roles: your Ubuntu = client+server,
friend = attacker. The attacker only *sends*, which is far less fussy than receiving.)

## Step 2 - copy this folder to the friend's WSL
Copy the whole `twomachine/` folder to the friend's WSL (git pull, scp, or a USB).
Both machines run the **same** code.

## Step 3 - set env vars (same values on BOTH machines)
Replace the IPs/subnet with your real ones from Step 0.

On **both** machines:
```bash
export LAB_CLIENT=A_IP        # friend's WSL IP  (e.g. 192.168.1.50)
export LAB_SERVER=A_IP        # same as CLIENT
export LAB_ATTACKER=B_IP      # your Ubuntu IP   (e.g. 192.168.1.60)
export LAB_NET=192.168.1.0/24 # your LAN subnet
```

## Step 4 - connectivity precheck
From **your Ubuntu (B)**:  `ping A_IP`
If you get replies, ICMP reaches Machine A and the demo can work. No replies -> fix
the LAN / WSL mirrored / firewall before continuing.

## Step 5 - run the four acts
`sudo -E` is required (root for raw sockets; `-E` keeps the LAB_* env vars).

**ACT 1 - baseline (no attack):**
```
# A term1:  sudo -E bash net_demo.sh server act1
# A term2:  sudo -E bash net_demo.sh client legacy act1
```
Expect: client RESULT complete, server COMPLETE.

**ACT 2 - RESET vs legacy (the kill):**
```
# A term1:  sudo -E bash net_demo.sh server act2
# A term2:  sudo -E bash net_demo.sh client legacy act2
# B term3 (3-5 s after the client starts):
             sudo -E bash net_demo.sh attacker reset act2
```
Expect: client action=abort, server INCOMPLETE.

**ACT 3 - QUENCH vs legacy (the throttle):**
```
# A term1:  sudo -E bash net_demo.sh server act3
# A term2:  sudo -E bash net_demo.sh client legacy act3
# B term3:  sudo -E bash net_demo.sh attacker quench act3
```
Expect: client action=slow, still COMPLETE but slower.

**ACT 4 - SAME RESET vs hardened (the defense):**
```
# A term1:  sudo -E bash net_demo.sh server act4
# A term2:  sudo -E bash net_demo.sh client hardened act4
# B term3:  sudo -E bash net_demo.sh attacker reset act4
```
Expect: client action=advisory, server COMPLETE. Same packet as ACT 2, different policy.

Logs land in `twomachine/out/`.

## Troubleshooting
- Client never reacts to the attack: the ICMP isn't reaching A. Recheck `ping A_IP`,
  WSL mirrored mode, and the Windows firewall rule. Also confirm `LAB_CLIENT`/`LAB_SERVER`
  are identical on both machines (the client rejects any ICMP whose quoted flow doesn't
  match exactly).
- "Address must be a host in ... lab": `LAB_NET` doesn't contain your IPs. Fix it.
- Fire the attacker within the transfer window (a 4 MiB @ 512 KiB/s run lasts ~8 s).
  Increase `PAYLOAD` (env) if you need a longer window.
