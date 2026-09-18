#!/usr/bin/env bash
# Four-act story demonstration of the ICMP blind attack against TCP.
# Same client sends the same file four times; only the attacker / policy change.
#
#   ACT 1  clean transfer, no attacker            -> completes fully
#   ACT 2  legacy client, attacker sends RESET     -> connection ABORTS
#   ACT 3  legacy client, attacker sends QUENCH     -> transfer goes SLOW
#   ACT 4  hardened client, attacker sends RESET    -> attack has NO EFFECT
#
# Run inside the Linux/Docker container as root:
#     bash demo_story.sh
# Evidence (readable JSONL) is written under  ./demo/  so you can open it on the Mac.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PAYLOAD=4194304          # 4 MiB
RATE=1048576             # 1 MiB/s normal pacing  -> clean transfer ~4 s
LOW=262144               # 256 KiB/s slowed pacing after a quench
FIRE_AFTER=2             # attacker fires 2 s into the transfer
OUT="$ROOT/demo"

hr()  { printf '%s\n' "============================================================"; }
line(){ printf '%s\n' "------------------------------------------------------------"; }

# ---- one readable summariser, written once to /tmp ----
cat > /tmp/_summarize.py <<'PY'
import json, sys
cl, sv, at, attack = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
def last(path, event):
    try:
        rows = [json.loads(l) for l in open(path).read().splitlines() if l.strip()]
    except FileNotFoundError:
        return None
    hits = [r for r in rows if r.get("event") == event]
    return hits[-1] if hits else None
if attack == "none":
    print("  Attacker      : did NOT attack  (clean control run)")
else:
    a = last(at, "packet_sent")
    if a:
        print("  Attacker      : sent 1 forged ICMP packet   type=" + str(a["icmp_type"]) + " code=" + str(a["icmp_code"]) + "  from 10.10.10.30")
    else:
        print("  Attacker      : (no packet logged)")
d = last(cl, "icmp_decision")
print("  Client policy : action=" + (d["action"] if d else "none  (no ICMP acted upon)"))
s = last(sv, "transfer_end")
if s:
    got, exp, comp = s["bytes_received"], s["expected_bytes"], s["complete"]
    verdict = "COMPLETE" if comp else "INCOMPLETE  (connection cut short)"
    print("  Server got    : " + str(got) + " / " + str(exp) + " bytes   ->   " + verdict)
    print("  Time taken    : " + format(s["elapsed"], ".1f") + " s   (goodput " + format(s["goodput_mbps"], ".2f") + " Mbps)")
PY

run_act() {                      # title mode attack fire
    local title="$1" mode="$2" attack="$3" fire="$4"
    local sv="$OUT/${title}_server.jsonl"
    local cl="$OUT/${title}_client.jsonl"
    local at="$OUT/${title}_attacker.jsonl"
    rm -f "$sv" "$cl" "$at"

    ip netns exec c406-server python3 tcp_receiver.py \
        --payload-bytes "$PAYLOAD" --timeout 90 --log "$sv" &
    local spid=$!
    sleep 1
    ip netns exec c406-client python3 tcp_sender.py \
        --mode "$mode" --payload-bytes "$PAYLOAD" --rate "$RATE" --low-rate "$LOW" --log "$cl" &
    local cpid=$!

    if [ "$attack" != "none" ]; then
        sleep "$fire"
        echo "  >>> attacker fires the '$attack' packet now <<<"
        ip netns exec c406-attacker python3 icmp_builder.py send "$OUT/${attack}.bin" --log "$at" || true
    fi
    wait "$cpid" 2>/dev/null || true
    wait "$spid" 2>/dev/null || true
    python3 /tmp/_summarize.py "$cl" "$sv" "$at" "$attack"
}

echo "### Preparing lab (client 10.10.10.10 / server 10.10.10.20 / attacker 10.10.10.30)"
python3 lab_network.py up
mkdir -p "$OUT"
python3 icmp_builder.py build reset  "$OUT/reset.bin"  >/dev/null
python3 icmp_builder.py build quench "$OUT/quench.bin" >/dev/null
echo "Ready. Evidence will be written under: $OUT"

hr; echo "ACT 1  |  Clean transfer, NO attacker"; line
run_act act1_baseline hardened none 0

hr; echo "ACT 2  |  Legacy client, attacker sends RESET  -> expect ABORT"; line
run_act act2_reset legacy reset "$FIRE_AFTER"

hr; echo "ACT 3  |  Legacy client, attacker sends QUENCH -> expect SLOWDOWN"; line
run_act act3_quench legacy quench "$FIRE_AFTER"

hr; echo "ACT 4  |  HARDENED client, attacker sends the SAME RESET -> expect NO EFFECT"; line
run_act act4_hardened hardened reset "$FIRE_AFTER"

hr
echo "Story complete."
echo "Compare ACT 2 (aborted) vs ACT 4 (survived): identical packet, only the client's"
echo "policy differs. ACT 1 is the clean baseline; ACT 3 shows throughput reduction."
echo "All per-act logs are in: $OUT"
python3 lab_network.py down >/dev/null 2>&1 || true
