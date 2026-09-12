import random
import socket
import struct
import unittest

from icmp_builder import PacketError, build_packet, checksum, decode_packet, lab_address
from icmp_policy import decide, in_sequence_window
from lab_common import CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, LAB_SEQUENCE


def repair(data, inner=False):
    data = bytearray(data)
    if inner:
        data[38:40] = b"\0\0"
        data[38:40] = struct.pack("!H", checksum(bytes(data[28:48])))
    data[22:24] = b"\0\0"
    data[22:24] = struct.pack("!H", checksum(bytes(data[20:])))
    data[10:12] = b"\0\0"
    data[10:12] = struct.pack("!H", checksum(bytes(data[:20])))
    return bytes(data)


class PacketTests(unittest.TestCase):
    def test_known_checksum_vector(self):
        self.assertEqual(checksum(bytes.fromhex("0001f203f4f5f6f7")), 0x220d)

    def test_odd_checksum(self):
        self.assertEqual(checksum(b"\x01\x02\x03"), 0xfbfd)
        self.assertEqual(checksum(b""), 0xffff)

    def test_both_packet_formats(self):
        for kind, fields in (("reset", (3, 2)), ("quench", (4, 0))):
            with self.subTest(kind=kind):
                data = build_packet(kind)
                decoded = decode_packet(data)
                self.assertEqual(len(data), 56)
                self.assertEqual((decoded.icmp_type, decoded.icmp_code), fields)
                self.assertEqual((decoded.quoted_source, decoded.quoted_destination), (CLIENT, SERVER))
                self.assertEqual((decoded.source_port, decoded.destination_port, decoded.sequence), (CLIENT_PORT, SERVER_PORT, LAB_SEQUENCE))
                self.assertEqual(checksum(data[:20]), 0)
                self.assertEqual(checksum(data[20:]), 0)
                self.assertEqual(checksum(data[28:48]), 0)
                self.assertEqual(struct.unpack_from("!H", data, 30)[0], 40)

    def test_deterministic_bytes(self):
        self.assertEqual(build_packet("reset"), build_packet("reset"))

    def test_unsafe_addresses_refused(self):
        for address in ("8.8.8.8", "127.0.0.1", "10.10.11.10", "10.10.10.0", "10.10.10.255", "::1"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                lab_address(address)

    def test_invalid_builder_arguments(self):
        for options in ({"kind": "other"}, {"kind": "reset", "source_port": 0},
                        {"kind": "reset", "destination_port": 65536}, {"kind": "quench", "sequence": -1}):
            with self.subTest(options=options), self.assertRaises(PacketError):
                build_packet(**options)

    def test_every_truncation_rejected(self):
        packet = build_packet("reset")
        for length in range(len(packet)):
            with self.subTest(length=length), self.assertRaises(PacketError):
                decode_packet(packet[:length])

    def test_corrupt_checksums_rejected(self):
        for offset in (8, 24, 34, 55):
            data = bytearray(build_packet("reset"))
            data[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(PacketError):
                decode_packet(bytes(data))

    def test_inner_checksum_independent_of_icmp(self):
        data = bytearray(build_packet("reset"))
        data[36] ^= 1
        with self.assertRaisesRegex(PacketError, "IPv4 checksum"):
            decode_packet(repair(data))

    def test_outer_protocol(self):
        data = bytearray(build_packet("reset"))
        data[9] = 17
        with self.assertRaisesRegex(PacketError, "not ICMP"):
            decode_packet(repair(data))

    def test_inner_protocol(self):
        data = bytearray(build_packet("reset"))
        data[37] = 17
        with self.assertRaisesRegex(PacketError, "not TCP"):
            decode_packet(repair(data, inner=True))

    def test_fragmentation_and_reserved_flags(self):
        for offset in (6, 34):
            for flags in (0x2000, 1, 0x8000):
                data = bytearray(build_packet("reset"))
                struct.pack_into("!H", data, offset, flags)
                with self.subTest(offset=offset, flags=flags), self.assertRaises(PacketError):
                    decode_packet(repair(data, inner=True))

    def test_invalid_type_and_code(self):
        for kind, code in ((4, 1), (3, 16), (8, 0)):
            data = bytearray(build_packet("reset"))
            data[20:22] = bytes([kind, code])
            with self.subTest(kind=kind, code=code), self.assertRaises(PacketError):
                decode_packet(repair(data))

    def test_short_original_tcp_datagram(self):
        data = bytearray(build_packet("reset"))
        struct.pack_into("!H", data, 30, 28)
        with self.assertRaisesRegex(PacketError, "too short for TCP"):
            decode_packet(repair(data, inner=True))

    def test_ip_options_supported(self):
        packet = bytearray(build_packet("reset"))
        # Insert outer IPv4 NOP options and recompute its checksum.
        packet[20:20] = b"\x01" * 4
        packet[0] = 0x46
        struct.pack_into("!H", packet, 2, 60)
        packet[10:12] = b"\0\0"
        packet[10:12] = struct.pack("!H", checksum(bytes(packet[:24])))
        self.assertEqual(decode_packet(bytes(packet)).source_port, CLIENT_PORT)

    def test_random_input_fails_cleanly(self):
        rng = random.Random(406)
        for _ in range(1000):
            packet = rng.randbytes(rng.randrange(128))
            try:
                decode_packet(packet)
            except PacketError:
                pass


class PolicyTests(unittest.TestCase):
    def test_legacy_reset(self):
        self.assertEqual(decide(build_packet("reset"), "legacy")["action"], "abort")

    def test_hardened_reset(self):
        self.assertEqual(decide(build_packet("reset"), "hardened")["action"], "advisory")

    def test_legacy_quench(self):
        self.assertEqual(decide(build_packet("quench"), "legacy")["action"], "slow")

    def test_hardened_quench(self):
        self.assertEqual(decide(build_packet("quench"), "hardened")["action"], "ignore")

    def test_kernel_observation(self):
        for kind in ("reset", "quench"):
            self.assertEqual(decide(build_packet(kind), "kernel")["action"], "observe")

    def test_mismatched_ports(self):
        for options in ({"source_port": 40001}, {"destination_port": 5002}):
            for mode in ("legacy", "hardened"):
                self.assertEqual(decide(build_packet("reset", **options), mode)["action"], "reject")

    def test_mismatched_addresses(self):
        for offset in (16, 40, 44):
            data = bytearray(build_packet("reset"))
            data[offset:offset + 4] = socket.inet_aton("10.10.10.99")
            for mode in ("legacy", "hardened"):
                self.assertEqual(decide(repair(data, inner=True), mode)["action"], "reject")

    def test_invalid_packet_is_logged_rejection(self):
        self.assertEqual(decide(b"invalid", "legacy")["action"], "reject")

    def test_modeled_window(self):
        packet = build_packet("reset", sequence=110)
        self.assertEqual(decide(packet, "hardened", (100, 120))["action"], "advisory")
        self.assertEqual(decide(packet, "hardened", (111, 120))["action"], "reject")

    def test_source_quench_ignored_even_without_matching_sequence(self):
        self.assertEqual(decide(build_packet("quench"), "hardened", (10, 20))["action"], "ignore")

    def test_sequence_boundaries_and_wrap(self):
        for sequence, start, end, expected in ((10, 10, 20, True), (20, 10, 20, False), (9, 10, 20, False),
                                               (0, 0xfffffff0, 16, True), (16, 0xfffffff0, 16, False),
                                               (0xfffffff0, 0xfffffff0, 16, True), (10, 10, 10, False),
                                               (1, 0, 0x80000000, False)):
            self.assertEqual(in_sequence_window(sequence, start, end), expected)

    def test_invalid_policy_mode(self):
        with self.assertRaises(ValueError):
            decide(build_packet("reset"), "typo")


if __name__ == "__main__":
    unittest.main()
