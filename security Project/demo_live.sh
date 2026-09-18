#!/usr/bin/env bash
# Live single-screen demonstration of the ICMP blind attack.
# Shows the three parties (client, server, attacker) acting on the shared
# switch, and prints the packet the attacker injected plus the outcome.
#
#   Usage (run inside the Linux/Docker container, as root):
#     bash demo_live.sh legacy      # attack succeeds: connection aborts
#     bash demo_live.sh hardened    # attack fails: transfer completes
#
# This is a presentation helper. The graded experiment is run_trial.py.
set -euo pipefail
MODE="${1:-legacy}"                       # legacy | hardened
SIZE=8388608                              # 8 MiB transfer
FIRE_AFTER=3                              # seconds of clean transfer before the attack
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

hr() { printf '%s\n' "------------------------------------------------------------"; }

echo "### 1. Building the isolated topology (client / server / attacker + switch)"
python3 lab_network.py up
hr

echo "### 2. Attacker prepares one forged ICMP 'port unreachable' packet"
python3 icmp_builder.py build reset /tmp/reset.bin
python3 icmp_builder.py decode /tmp/reset.bin
hr

echo "### 3. SERVER 10.10.10.20:5001 starts listening"
ip netns exec c406-server python3 tcp_receiver.py \
    --payload-bytes "$SIZE" --timeout 40 --log /tmp/rx.jsonl &
sleep 1

echo "### 4. A packet monitor on the shared switch records everything on the wire"
ip netns exec c406-switch timeout $((FIRE_AFTER + 9)) \
    tcpdump -l -i br-lab -nn "icmp or tcp port 5001" > /tmp/wire.txt 2>/dev/null &
sleep 0.5

echo "### 5. CLIENT 10.10.10.10:40000 begins sending ${SIZE} bytes (mode=${MODE})"
ip netns exec c406-client python3 tcp_sender.py \
    --mode "$MODE" --payload-bytes "$SIZE" --log /tmp/tx.jsonl &
echo "        ... transfer running for ${FIRE_AFTER}s ..."
sleep "$FIRE_AFTER"

hr
echo "### 6. >>> ATTACKER 10.10.10.30 FIRES THE FORGED PACKET <<<"
ip netns exec c406-attacker python3 icmp_builder.py send /tmp/reset.bin --log /tmp/atk.jsonl
wait 2>/dev/null || true
hr

echo "### WHAT THE SWITCH SAW ON THE WIRE"
echo "-- client -> server TCP data (first 3 packets): --"
grep "10.10.10.10.40000 > 10.10.10.20.5001" /tmp/wire.txt | head -3 || true
echo
echo "-- the ATTACK: one ICMP packet from the attacker (10.10.10.30): --"
grep -i "10.10.10.30 > 10.10.10.10: ICMP" /tmp/wire.txt | head -2 || true
echo
echo "-- what happened next (FIN = connection closing): --"
grep -E "Flags \[F" /tmp/wire.txt | head -3 || true
hr

echo "### OUTCOME"
echo -n "CLIENT decision : "
grep icmp_decision /tmp/tx.jsonl | python3 -c 'import json,sys;d=json.loads(sys.stdin.read());print("action="+d["action"]+"  ("+d["reason"]+")")' 2>/dev/null || echo "(no ICMP decision logged)"
echo -n "SERVER received : "
tail -1 /tmp/rx.jsonl | python3 -c 'import json,sys;d=json.loads(sys.stdin.read());print(str(d["bytes_received"])+"/"+str(d["expected_bytes"])+" bytes  complete="+str(d["complete"])+"  premature_close="+str(d.get("premature_close")))'
hr

python3 lab_network.py down >/dev/null 2>&1 || true
echo "### Topology cleaned up. Demo complete."
