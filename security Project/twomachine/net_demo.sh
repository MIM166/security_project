#!/usr/bin/env bash
# Two-machine LAN demo runner (no namespaces).
# Requires these env vars (export them first, same values on BOTH machines):
#   LAB_CLIENT   = Machine A LAN IP   (runs client)
#   LAB_SERVER   = Machine A LAN IP   (runs server; same host as client)
#   LAB_ATTACKER = Machine B LAN IP   (runs attacker)
#   LAB_NET      = your LAN subnet, e.g. 192.168.1.0/24
#
# Machine A, terminal 1:  sudo -E bash net_demo.sh server            [LABEL]
# Machine A, terminal 2:  sudo -E bash net_demo.sh client legacy     [LABEL]   (or: hardened)
# Machine B, terminal 3:  sudo -E bash net_demo.sh attacker reset    [LABEL]   (or: quench)
set -euo pipefail
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"; cd "$DIR"
OUT="$DIR/out"; mkdir -p "$OUT"

: "${LAB_CLIENT:?set LAB_CLIENT}"; : "${LAB_SERVER:?set LAB_SERVER}"
: "${LAB_ATTACKER:?set LAB_ATTACKER}"; : "${LAB_NET:?set LAB_NET}"

PAYLOAD="${PAYLOAD:-4194304}"   # 4 MiB
RATE="${RATE:-524288}"          # 512 KiB/s -> clean run ~8 s (time to switch terminals)
LOW="${LOW:-131072}"            # 128 KiB/s -> slowed rate after a quench

ROLE="${1:-}"; ARG="${2:-}"; LABEL="${3:-run}"
if [ "$ROLE" = "server" ] && [ -n "$ARG" ]; then LABEL="$ARG"; fi
echo "config: client=$LAB_CLIENT server=$LAB_SERVER attacker=$LAB_ATTACKER net=$LAB_NET"

case "$ROLE" in
  server)
    echo "[SERVER $LAB_SERVER:5001] waiting for client ...  (log: out/${LABEL}_server.jsonl)"
    python3 tcp_receiver.py --payload-bytes "$PAYLOAD" --timeout 180 --log "$OUT/${LABEL}_server.jsonl" || true
    python3 - "$OUT/${LABEL}_server.jsonl" <<'PY'
import json,sys
r=[json.loads(l) for l in open(sys.argv[1]).read().splitlines() if l.strip()]
e=[x for x in r if x.get("event")=="transfer_end"][-1]
tag="COMPLETE (full file received)" if e["complete"] else "INCOMPLETE (connection cut short!)"
print(f"[SERVER RESULT] {e['bytes_received']} / {e['expected_bytes']} bytes -> {tag}")
print(f"               time {e['elapsed']:.1f}s , goodput {e['goodput_mbps']:.2f} Mbps")
PY
    ;;
  client)
    MODE="${ARG:-legacy}"
    echo "[CLIENT $LAB_CLIENT] sending to server (policy=$MODE)  (log: out/${LABEL}_client.jsonl) ..."
    python3 tcp_sender.py --mode "$MODE" --payload-bytes "$PAYLOAD" --rate "$RATE" --low-rate "$LOW" \
        --log "$OUT/${LABEL}_client.jsonl" || true
    python3 - "$OUT/${LABEL}_client.jsonl" <<'PY'
import json,sys
r=[json.loads(l) for l in open(sys.argv[1]).read().splitlines() if l.strip()]
d=[x for x in r if x.get("event")=="icmp_decision"]
end=[x for x in r if x.get("event")=="transfer_end"][-1]
if d:
    d=d[-1]; print(f"[CLIENT saw attacker ICMP] action={d['action']}  reason: {d['reason']}")
else:
    print("[CLIENT] no ICMP acted upon (clean run)")
print(f"[CLIENT RESULT] sent {end['bytes_sent']} bytes , aborted={end['aborted']} , "
      f"slowed={end['low_rate_entered']} , took {end['elapsed']:.1f}s")
PY
    ;;
  attacker)
    KIND="${ARG:-reset}"
    python3 icmp_builder.py build "$KIND" "$OUT/${KIND}.bin" >/dev/null
    echo ">>> [ATTACKER $LAB_ATTACKER] firing one forged ICMP '$KIND' at client $LAB_CLIENT <<<"
    python3 icmp_builder.py send "$OUT/${KIND}.bin" --log "$OUT/${LABEL}_attacker.jsonl"
    python3 - "$OUT/${LABEL}_attacker.jsonl" <<'PY'
import json,sys
a=[json.loads(l) for l in open(sys.argv[1]).read().splitlines() if l.strip()][-1]
kind="RESET (protocol unreachable)" if a["icmp_type"]==3 else "SOURCE QUENCH"
print(f"[ATTACKER SENT] {kind}  type={a['icmp_type']} code={a['icmp_code']} "
      f"claiming flow {a['quoted_source']}:{a['source_port']} -> {a['quoted_destination']}:{a['destination_port']}")
PY
    ;;
  *)
    echo "usage: sudo -E bash net_demo.sh {server|client [legacy|hardened]|attacker [reset|quench]} [LABEL]"
    exit 1;;
esac
