from pathlib import Path
import struct
import tempfile
import unittest

from evidence import inspect_pcap, window_goodput
from icmp_builder import build_packet
from lab_common import payload, payload_hash


class EvidenceTests(unittest.TestCase):
    def test_payload_chunk_boundaries(self):
        self.assertEqual(payload(0, 1000), payload(0, 333) + payload(333, 667))
        self.assertEqual(payload(0, 0), b"")

    def test_payload_hash(self):
        import hashlib
        self.assertEqual(payload_hash(70001), hashlib.sha256(payload(0, 70001)).hexdigest())

    def test_receiver_goodput_interpolation(self):
        events = [{"event": "transfer_start", "monotonic": 10},
                  {"event": "sample", "monotonic": 11, "bytes_received": 1000000},
                  {"event": "transfer_end", "monotonic": 12, "bytes_received": 2000000}]
        self.assertEqual(window_goodput(events, 10.25, 11.75), 8)
        with self.assertRaises(ValueError):
            window_goodput(events, 9, 12)
        with self.assertRaises(ValueError):
            window_goodput(events, 11, 11)

    def test_pcap_endianness_and_checksums(self):
        for endian in ("<", ">"):
            for damaged in (False, True):
                header = struct.pack(endian + "IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
                packet = bytearray(build_packet("reset"))
                if damaged:
                    packet[-1] ^= 1
                frame = b"\0" * 12 + b"\x08\x00" + packet
                record = struct.pack(endian + "IIII", 1, 500000, len(frame), len(frame))
                with tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp) / "test.pcap"
                    path.write_bytes(header + record + frame)
                    evidence = inspect_pcap(path)
                    self.assertEqual(evidence["icmp_packets"][0]["valid"], not damaged)
                    if not damaged:
                        self.assertEqual(evidence["icmp_packets"][0]["unix_time"], 1.5)

    def test_truncated_capture_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.pcap"
            path.write_bytes(b"short")
            with self.assertRaises(ValueError):
                inspect_pcap(path)


if __name__ == "__main__":
    unittest.main()
