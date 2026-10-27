"""Payload generator tests (no Docker, no crash)."""

from __future__ import annotations

import pathlib
import struct
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lab" / "attacker"))

import payload  # noqa: E402


class PayloadTests(unittest.TestCase):
    def test_hang_size(self) -> None:
        blob = payload.build_hang_payload()
        self.assertEqual(len(blob), 86)
        self.assertTrue(blob.startswith(payload.HANG_SEED))

    def test_tail_layout(self) -> None:
        tail = payload.build_crash_tail()
        self.assertEqual(len(tail), 127)
        self.assertEqual(tail[7], 8)
        self.assertEqual(struct.unpack_from("<i", tail, 15)[0], -0x40000000)
        self.assertEqual(struct.unpack_from("<I", tail, 19)[0], 0x7FFFFFFF)
        self.assertEqual(struct.unpack_from("<I", tail, 23)[0], 0x7FFFFFFF)

    def test_stream_size(self) -> None:
        self.assertEqual(len(payload.build_stream()), payload.CRASH_STREAM_SIZE)


if __name__ == "__main__":
    unittest.main()
