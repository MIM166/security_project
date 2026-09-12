from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from icmp_builder import PacketError, build_packet, transmit
from lab_common import require_namespace


class GuardTests(unittest.TestCase):
    def test_non_root_refused_without_network_calls(self):
        with patch("lab_common.os.name", "posix"), patch("lab_common.os.geteuid", return_value=1000, create=True), patch("lab_common.subprocess.check_output") as command:
            with self.assertRaisesRegex(RuntimeError, "root"):
                require_namespace("attacker")
            command.assert_not_called()

    def test_wrong_namespace_refused_with_mocked_identity(self):
        with patch("lab_common.os.name", "posix"), patch("lab_common.os.geteuid", return_value=0, create=True), patch("lab_common.subprocess.check_output", return_value=""):
            with self.assertRaisesRegex(RuntimeError, "outside c406-attacker"):
                require_namespace("attacker")

    def test_default_route_refused_with_mocked_routes(self):
        with patch("lab_common.os.name", "posix"), patch("lab_common.os.geteuid", return_value=0, create=True), patch("lab_common.subprocess.check_output", side_effect=["c406-attacker", '[{"dst":"default","gateway":"10.10.10.1"}]']):
            with self.assertRaisesRegex(RuntimeError, "unexpected route"):
                require_namespace("attacker")

    def test_guard_failure_prevents_socket_creation(self):
        with patch("icmp_builder.require_namespace", side_effect=RuntimeError("outside lab")), patch("icmp_builder.socket.socket") as raw:
            with self.assertRaisesRegex(RuntimeError, "outside lab"):
                transmit("unused.bin", "unused.jsonl")
            raw.assert_not_called()

    def test_modified_packet_refused_before_socket_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "modified.bin"
            path.write_bytes(build_packet("reset", source_port=40001))
            with patch("icmp_builder.require_namespace"), patch("icmp_builder.socket.socket") as raw:
                with self.assertRaisesRegex(PacketError, "only the two fixed"):
                    transmit(path, Path(tmp) / "unused.jsonl")
                raw.assert_not_called()


if __name__ == "__main__":
    unittest.main()
