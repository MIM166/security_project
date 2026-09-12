"""Original IPv4/ICMP serializer, validator and fixed-destination lab transmitter."""
import argparse
from dataclasses import asdict, dataclass
import hashlib
import ipaddress
import json
from pathlib import Path
import socket
import struct

from lab_common import (ATTACKER, CLIENT, SERVER, CLIENT_PORT, SERVER_PORT,
                        LAB_SEQUENCE, EventLog, require_namespace)

LAB_NET = ipaddress.IPv4Network("10.10.10.0/24")


class PacketError(ValueError):
    pass


def checksum(data):
    """RFC 1071 one's-complement checksum, including odd-length padding."""
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def lab_address(address):
    address = ipaddress.IPv4Address(address)
    if address not in LAB_NET or address in (LAB_NET.network_address, LAB_NET.broadcast_address):
        raise PacketError("Address must be a host in the configured isolated 10.10.10.0/24 lab")
    return address.packed


def ipv4_header(source, destination, protocol, payload_length, identification):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + payload_length,
                         identification, 0, 64, protocol, 0,
                         lab_address(source), lab_address(destination))
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:]


def build_packet(kind, source_port=CLIENT_PORT, destination_port=SERVER_PORT, sequence=LAB_SEQUENCE):
    if kind not in ("reset", "quench"):
        raise PacketError("kind must be reset or quench")
    if not 1 <= source_port <= 65535 or not 1 <= destination_port <= 65535:
        raise PacketError("TCP ports must be between 1 and 65535")
    if not 0 <= sequence <= 0xffffffff:
        raise PacketError("Sequence must be an unsigned 32-bit integer")
    prefix = struct.pack("!HHI", source_port, destination_port, sequence)
    # Original datagram claims a full minimum TCP header; ICMP quotes only 8 bytes.
    quote = ipv4_header(CLIENT, SERVER, socket.IPPROTO_TCP, 20, 0x406) + prefix
    icmp = struct.pack("!BBHI", 3 if kind == "reset" else 4, 2 if kind == "reset" else 0, 0, 0) + quote
    icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
    return ipv4_header(ATTACKER, CLIENT, socket.IPPROTO_ICMP, len(icmp), 0x406) + icmp


def parse_ip(data, quoted=False):
    if len(data) < 20:
        raise PacketError("truncated IPv4 header")
    version, ihl = data[0] >> 4, (data[0] & 15) * 4
    if version != 4 or ihl < 20 or len(data) < ihl:
        raise PacketError("invalid IPv4 version/header length")
    total = struct.unpack_from("!H", data, 2)[0]
    if total < ihl or (not quoted and total > len(data)):
        raise PacketError("invalid IPv4 total length")
    if checksum(data[:ihl]):
        raise PacketError("invalid IPv4 checksum")
    if struct.unpack_from("!H", data, 6)[0] & 0xbfff:
        raise PacketError("fragmented or reserved-flag IPv4 packet is unsupported")
    return {"ihl": ihl, "total": total, "protocol": data[9],
            "source": socket.inet_ntoa(data[12:16]), "destination": socket.inet_ntoa(data[16:20])}


@dataclass(frozen=True)
class DecodedPacket:
    source: str
    destination: str
    icmp_type: int
    icmp_code: int
    quoted_source: str
    quoted_destination: str
    source_port: int
    destination_port: int
    sequence: int
    length: int
    ipv4_checksum_valid: bool = True
    quoted_ipv4_checksum_valid: bool = True
    icmp_checksum_valid: bool = True


def decode_packet(data):
    outer = parse_ip(data)
    if outer["protocol"] != socket.IPPROTO_ICMP:
        raise PacketError("outer protocol is not ICMP")
    body = data[outer["ihl"]:outer["total"]]
    if len(body) < 36:
        raise PacketError("truncated ICMP error quotation")
    if checksum(body):
        raise PacketError("invalid ICMP checksum")
    icmp_type, code = body[:2]
    if (icmp_type == 3 and code not in range(16)) or (icmp_type == 4 and code != 0) or icmp_type not in (3, 4):
        raise PacketError("unsupported ICMP type/code")
    inner = parse_ip(body[8:], quoted=True)
    if inner["protocol"] != socket.IPPROTO_TCP:
        raise PacketError("quoted protocol is not TCP")
    if inner["total"] < inner["ihl"] + 20:
        raise PacketError("quoted original datagram too short for TCP")
    prefix_offset = 8 + inner["ihl"]
    if len(body) < prefix_offset + 8:
        raise PacketError("truncated quoted TCP prefix")
    sport, dport, sequence = struct.unpack_from("!HHI", body, prefix_offset)
    return DecodedPacket(outer["source"], outer["destination"], icmp_type, code,
                         inner["source"], inner["destination"], sport, dport, sequence, outer["total"])


def transmit(path, log_path):
    require_namespace("attacker")
    data = Path(path).read_bytes()
    decoded = decode_packet(data)
    if data not in (build_packet("reset"), build_packet("quench")):
        raise PacketError("Transmitter accepts only the two fixed, prebuilt laboratory packets")
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sent = sock.sendto(data, (CLIENT, 0))
    log = EventLog(log_path)
    log.emit("packet_sent", bytes=sent, sha256=hashlib.sha256(data).hexdigest(), **asdict(decoded))
    log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build")
    build.add_argument("kind", choices=["reset", "quench"])
    build.add_argument("output", type=Path)
    decode = sub.add_parser("decode")
    decode.add_argument("packet", type=Path)
    send = sub.add_parser("send")
    send.add_argument("packet", type=Path)
    send.add_argument("--log", required=True)
    args = parser.parse_args()
    if args.command == "build":
        data = build_packet(args.kind)
        args.output.write_bytes(data)
        print(json.dumps(asdict(decode_packet(data)), indent=2))
    elif args.command == "decode":
        print(json.dumps(asdict(decode_packet(args.packet.read_bytes())), indent=2))
    else:
        transmit(args.packet, args.log)


if __name__ == "__main__":
    main()
