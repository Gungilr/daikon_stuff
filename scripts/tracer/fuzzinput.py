"""Fuzz-input mode: how inputs get into a stripped binary under emulation.

The tracer has no input mechanism of its own (the open item since the
phase-5 retrospective): it starts at main with rdi=1 and an argv that is
never populated. File and stdin I/O would mean emulating libc. Instead the
fuzz harness (fuzz/runtime/harness_bb.c) owns a global buffer that starts
with a 16-byte magic string:

    struct { char magic[16]; uint32_t len; uint8_t data[FUZZ_MAX]; }

It is initialized, so it lives in .data, and section contents survive
`strip --strip-all`. The tracer scans the loaded segments for the magic and
writes each input's length and bytes into the struct before running main.
Symbols are never needed.

Pure: no unicorn, no capstone, no pyelftools.
"""
import struct

BLOB_MAGIC = b"DAIKON-FUZZ-BLOB"
LEN_OFFSET = len(BLOB_MAGIC)          # u32 length follows the magic
DATA_OFFSET = LEN_OFFSET + 4          # then the bytes
FUZZ_MAX = 4096                       # must match harness_bb.c

MARKER_PPT = "..fuzz_input_begin():::ENTER"
MARKER_VAR = "fuzz_id"


def find_blob(segments):
    """Virtual address of the input struct, or None.

    `segments` are the loader's dicts with 'vaddr' and 'data'. Exactly one
    occurrence is required: two would mean the magic also appears as data,
    and writing into the wrong one would silently feed the program nothing.
    """
    hits = []
    for seg in segments:
        data = seg.get("data") or b""
        start = 0
        while True:
            i = data.find(BLOB_MAGIC, start)
            if i < 0:
                break
            hits.append(seg["vaddr"] + i)
            start = i + 1
    if len(hits) != 1:
        return None
    return hits[0]


def parse_batch(blob):
    """[bytes] from the harness batch format: u32 LE length, then bytes."""
    out, pos = [], 0
    while pos + 4 <= len(blob):
        (n,) = struct.unpack_from("<I", blob, pos)
        pos += 4
        out.append(bytes(blob[pos:pos + n]))
        pos += n
    return out


def encode_input(data):
    """The bytes to write at LEN_OFFSET: length, then the (truncated) input."""
    data = data[:FUZZ_MAX]
    return struct.pack("<I", len(data)) + data
