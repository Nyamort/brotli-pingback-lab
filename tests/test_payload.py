"""Unit tests for the payload generator.

These do not need Docker and do not crash anything.  They pin the sizes and
the crash-tail layout that the lab depends on.
"""

from __future__ import annotations

import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lab" / "attacker"))

import payload  # noqa: E402


class PayloadTests(unittest.TestCase):
    def test_hang_payload_size(self) -> None:
        blob = payload.build_hang_payload()
        self.assertEqual(len(blob), 86)
        self.assertTrue(blob.startswith(payload.HANG_SEED))

    def test_crash_tail_layout(self) -> None:
        tail = payload.build_crash_tail()
        self.assertEqual(len(tail), 127)
        self.assertEqual(tail[7], 8)
        self.assertEqual(struct.unpack_from("<i", tail, 15)[0], -0x40000000)
        self.assertEqual(struct.unpack_from("<I", tail, 19)[0], 0x7FFFFFFF)
        self.assertEqual(struct.unpack_from("<I", tail, 23)[0], 0x7FFFFFFF)

    def test_stream_size(self) -> None:
        stream = payload.build_stream()
        self.assertEqual(len(stream), payload.CRASH_STREAM_SIZE)

    def test_crash_payload_shape(self) -> None:
        blob = payload.build_crash_payload()
        self.assertEqual(
            len(blob), payload.CRASH_STREAM_SIZE + 3 + payload.CRASH_TAIL_SIZE
        )
        self.assertEqual(blob[-127:], payload.build_crash_tail())
        self.assertEqual(blob[-130:-127], b"\x00\x00\x00")


if __name__ == "__main__":
    unittest.main()
