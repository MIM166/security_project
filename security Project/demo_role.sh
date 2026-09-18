#!/usr/bin/env bash
# Per-machine helper for the 3-terminal live demonstration.
# Each terminal plays one machine and prints a human-readable result.
#
#   Terminal 1 (SERVER)  : bash demo_role.sh up        # once, at the start
#                          bash demo_role.sh server    # run once per ACT
#   Terminal 2 (CLIENT)  : bash demo_role.sh client legacy      (or: hardened)
#   Terminal 3 (ATTACKER): bash demo_role.sh attacker reset     (or: quench)
#   Terminal 1 (SERVER)  : bash demo_role.sh down       # once, at the end
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
OUT="$ROOT/demo"; mkdir -p "$OUT"

PAYLOAD=4194304          # 4 MiB
RATE=524288              # 512 KiB/s -> a clean transfer takes ~8 s (time to switch terminals)
LOW=131072               # 128 KiB/s -> the slowed rate after a quench

ROLE="${1:-}"; ARG="${2:-}"

case "$ROLE" in
  up)
    python3 lab_network.py up
    python3 icmp_builder.py build reset  "$OUT/reset.bin"  >/dev/null
    python3 icmp_builder.py build quench "$OUT/quench.bin" >/dev/null
    echo "Lab is up. client=10.10.10.10  server=10.10.10.20:5001  attacker=10.10.10.30"
    ;;

  server)
    LABEL="${2:-run}"
    echo "[SERVER 10.10.10.20:5001] waiting for the client ...   (log: demo/${LABEL}_server.jsonl)"
    ip netns exec c406-server python3 tcp_receiver.py \
        --payload-bytes "$PAYLOAD" --timeout 180 --log "$OUT/${LABEL}_server.jsonl" || true
    python3 - "$OUT/${LABEL}_server.jsonl" <<'PY'
import json,sys
r=[json.loads(l) for l in open(sys.argv[1]).read().splitlines() if l.strip()]
e=[x for x in r if x.get("event")=="transfer_end"][-1]
tag="COMPLETE  (full file received)" if e["complete"] else "INCOMPLETE  (connection was cut short!)"
print("[SERVER RESULT] "+str(e["bytes_received"])+" / "+str(e["expected_bytes"])+" bytes  ->  "+tag)
print("               time "+format(e["elapsed"],".1f")+" s , goodput "+format(e["goodput_mbps"],".2f")+" Mbps")
PY
    ;;

  client)
    MODE="${ARG:-legacy}"; LABEL="${3:-run}"
    echo "[CLIENT 10.10.10.10] sending 4 MiB to the server  (policy = $MODE)  (log: demo/${LABEL}_client.jsonl) ..."
    ip netns exec c406-client python3 tcp_sender.py \
        --mode "$MODE" --payload-bytes "$PAYLOAD" --rate "$RATE" --low-rate "$LOW" \
        --log "$OUT/${LABEL}_client.jsonl" || true
    python3 - "$OUT/${LABEL}_client.jsonl" <<'PY'
import json,sys
r=[json.loads(l) for l in open(sys.argv[1]).read().splitlines() if l.strip()]
d=[x for x in r if x.get("event")=="icmp_decision"]
end=[x for x in r if x.get("event")=="transfer_end"][-1]
if d:
    d=d[-1]
    print("[CLIENT saw the attacker's ICMP]  decision: action="+d["action"])
    print("      reason: "+d["reason"])
else:
    print("[CLIENT] no ICMP acted upon (clean run)")
print("[CLIENT RESULT] sent "+str(end["bytes_sent"])+" bytes , aborted="+str(end["aborted"])+
      " , slowed="+str(end["low_rate_entered"])+" , took "+format(end["elapsed"],".1f")+" s")
PY
    ;;

  attacker)
    KIND="${ARG:-reset}"; LABEL="${3:-run}"
    echo ">>> [ATTACKER 10.10.10.30] firing one forged ICMP '$KIND' packet at the client <<<   (log: demo/${LABEL}_attacker.jsonl)"
    ip netns exec c406-attacker python3 icmp_builder.py send "$OUT/${KIND}.bin" --log "$OUT/${LABEL}_attacker.jsonl"
    python3 - "$OUT/${LABEL}_attacker.jsonl" <<'PY'
import json,sys
a=[json.loads(l) for l in open(sys.argv[1]).read().splitlines() if l.strip()][-1]
kind="RESET (protocol unreachable)" if a["icmp_type"]==3 else "SOURCE QUENCH"
print("[ATTACKER SENT] "+kind+"  type="+str(a["icmp_type"])+" code="+str(a["icmp_code"])+
      "  claiming flow 10.10.10.10:40000 -> 10.10.10.20:5001")
PY
    ;;

  down)
    python3 lab_network.py down && echo "Lab cleaned up."
    ;;

  *)
    echo "usage: bash demo_role.sh {up|server [LABEL]|client [legacy|hardened] [LABEL]|attacker [reset|quench] [LABEL]|down}"
    echo "  LABEL keeps each act's log separate, e.g.  server act1 / client legacy act1 / attacker reset act2"
    exit 1
    ;;
esac
