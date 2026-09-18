"""Pure policy decisions. Sequence-window validation is optional and explicitly modeled."""
from dataclasses import asdict
from icmp_builder import PacketError, decode_packet
from lab_common import CLIENT, SERVER, CLIENT_PORT, SERVER_PORT


def in_sequence_window(sequence, snd_una, snd_nxt):
    """Serial arithmetic across 32-bit wraparound; empty/ambiguous windows reject."""
    width = (snd_nxt - snd_una) & 0xffffffff
    return 0 < width < 0x80000000 and ((sequence - snd_una) & 0xffffffff) < width


def decide(data, mode, sequence_window=None):
    if mode not in ("legacy", "hardened", "kernel"):
        raise ValueError("Unknown policy mode")
    try:
        packet = decode_packet(data)
    except PacketError as exc:
        return {"action": "reject", "reason": str(exc)}
    details = {"packet": asdict(packet), "sequence_validation": "unavailable_for_kernel_socket"}
    flow = (packet.destination, packet.quoted_source, packet.quoted_destination,
            packet.source_port, packet.destination_port)
    if flow != (CLIENT, CLIENT, SERVER, CLIENT_PORT, SERVER_PORT):
        return {**details, "action": "reject", "reason": "quoted flow mismatch"}
    if mode == "kernel":
        return {**details, "action": "observe", "reason": "kernel comparison: no user-space control action"}
    if mode == "hardened" and packet.icmp_type == 4:
        return {**details, "action": "ignore", "reason": "RFC 6633: Source Quench discarded for transport control"}
    if mode == "hardened" and sequence_window is not None:
        details["sequence_validation"] = "modeled_window"
        if not in_sequence_window(packet.sequence, *sequence_window):
            return {**details, "action": "reject", "reason": "sequence outside modeled outstanding range"}
    if packet.icmp_type == 3 and packet.icmp_code in (2, 3, 4):
        if mode == "legacy":
            return {**details, "action": "abort", "reason": "legacy compatibility: hard error is fatal"}
        return {**details, "action": "advisory", "reason": "hard error is nonfatal for established transfer"}
    if packet.icmp_type == 4:
        return {**details, "action": "slow", "reason": "legacy compatibility: activate application pacing"}
    return {**details, "action": "advisory", "reason": "other ICMP error has no control action in this lab"}
