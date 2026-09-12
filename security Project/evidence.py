"""Read classic Ethernet PCAP and compute goodput from receiver byte counters."""
import hashlib
import struct

from icmp_builder import PacketError, decode_packet


def inspect_pcap(path):
    data = path.read_bytes()
    if len(data) < 24:
        raise ValueError("Missing PCAP global header")
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
               b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
    if data[:4] not in formats:
        raise ValueError("Expected classic PCAP format")
    endian, divisor = formats[data[:4]]
    if struct.unpack_from(endian + "I", data, 20)[0] != 1:
        raise ValueError("Expected Ethernet capture from br-lab")
    offset, packets, tcp_packets, tcp_fin, tcp_rst = 24, [], 0, 0, 0
    while offset < len(data):
        if len(data) - offset < 16:
            raise ValueError("Truncated PCAP record header")
        seconds, fraction, captured, original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        frame = data[offset:offset + captured]
        if len(frame) != captured:
            raise ValueError("Truncated PCAP record")
        offset += captured
        if len(frame) < 34 or frame[12:14] != b"\x08\x00":
            continue
        packet = frame[14:]
        ihl = (packet[0] & 15) * 4
        if packet[9] == 1:
            total = struct.unpack_from("!H", packet, 2)[0]
            packet = packet[:total]
            try:
                decoded = decode_packet(packet)
                packets.append({"unix_time": seconds + fraction / divisor,
                                "sha256": hashlib.sha256(packet).hexdigest(),
                                "valid": True, "type": decoded.icmp_type, "code": decoded.icmp_code})
            except PacketError as exc:
                packets.append({"valid": False, "error": str(exc)})
        elif packet[9] == 6 and len(packet) >= ihl + 14:
            tcp_packets += 1
            flags = packet[ihl + 13]
            tcp_fin += bool(flags & 1)
            tcp_rst += bool(flags & 4)
    return {"icmp_packets": packets, "tcp_packets": tcp_packets,
            "tcp_fin_packets": tcp_fin, "tcp_rst_packets": tcp_rst}


def counter_points(events):
    points = []
    for event in events:
        if event["event"] == "transfer_start":
            points.append((event["monotonic"], 0))
        elif event["event"] in ("sample", "transfer_end") and "bytes_received" in event:
            points.append((event["monotonic"], event["bytes_received"]))
    return points


def interpolate(points, timestamp):
    if timestamp < points[0][0] or timestamp > points[-1][0]:
        raise ValueError("Measurement window extends outside the transfer")
    for (t0, b0), (t1, b1) in zip(points, points[1:]):
        if t0 <= timestamp <= t1:
            return b0 + (b1 - b0) * (timestamp - t0) / (t1 - t0) if t1 > t0 else b1
    return points[-1][1]


def window_goodput(events, start, end):
    if end <= start:
        raise ValueError("Measurement window must have positive duration")
    points = counter_points(events)
    return (interpolate(points, end) - interpolate(points, start)) * 8 / (end - start) / 1e6
