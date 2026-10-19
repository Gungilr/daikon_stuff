"""Byte-level mutation, AFL/libFuzzer style, seeded for reproducibility.

The targets decode their arguments as little-endian 32-bit words, so the
word-aligned operators (arithmetic, interesting values, dictionary constants)
do most of the useful work; the byte-level ones keep the search from being
blind to everything that is not an int.

Pure: no subprocesses, no third-party imports.
"""
import struct

INTERESTING_8 = [0, 1, 0x7f, 0x80, 0xff, 0x10, 0x20, 0x40, ord("0"), ord("9"),
                 ord("A"), ord("Z"), ord("a"), ord("z")]
INTERESTING_32 = [0, 1, -1, 2, 16, 100, 255, 256, 1000, 1024, 4096, 65535,
                  65536, 0x7fffffff, -0x80000000, 0x7ffffffe, -0x7fffffff]


class Mutator(object):
    def __init__(self, rng, max_len=64):
        self.rng = rng
        self.max_len = max_len
        self.dictionary = set()      # integer constants from trace-cmp

    def add_constants(self, consts):
        for c in consts:
            self.dictionary.add(c & 0xffffffffffffffff)

    # -- operators. Each takes and returns a bytearray. --------------------

    def _word_offset(self, buf):
        if len(buf) < 4:
            buf.extend(b"\0" * (4 - len(buf)))
        return 4 * self.rng.randrange(len(buf) // 4)

    def flip_bit(self, buf):
        if not buf:
            return self.insert_bytes(buf)
        i = self.rng.randrange(len(buf) * 8)
        buf[i // 8] ^= 1 << (i % 8)
        return buf

    def random_byte(self, buf):
        if not buf:
            return self.insert_bytes(buf)
        buf[self.rng.randrange(len(buf))] = self.rng.randrange(256)
        return buf

    def interesting_byte(self, buf):
        if not buf:
            return self.insert_bytes(buf)
        buf[self.rng.randrange(len(buf))] = self.rng.choice(INTERESTING_8)
        return buf

    def arith_byte(self, buf):
        """AFL's arith8: one byte +/- 1..35. Text-shaped inputs need it -
        turning the digit '4' into '5' is invisible to word arithmetic."""
        if not buf:
            return self.insert_bytes(buf)
        i = self.rng.randrange(len(buf))
        delta = self.rng.randint(1, 35)
        buf[i] = (buf[i] + (delta if self.rng.random() < 0.5 else -delta)) & 0xff
        return buf

    def interesting_word(self, buf):
        off = self._word_offset(buf)
        buf[off:off + 4] = struct.pack("<i", self.rng.choice(INTERESTING_32))
        return buf

    def arith_word(self, buf):
        off = self._word_offset(buf)
        v = struct.unpack("<i", bytes(buf[off:off + 4]))[0]
        # Mostly small steps, occasionally a large one, so both local hill
        # climbing and jumps across the range are possible.
        if self.rng.random() < 0.8:
            delta = self.rng.randint(1, 35)
        else:
            delta = 1 << self.rng.randrange(31)
        v = v + delta if self.rng.random() < 0.5 else v - delta
        buf[off:off + 4] = struct.pack("<I", v & 0xffffffff)
        return buf

    def scale_word(self, buf):
        """Multiply or halve a word: the fast route to an overflow."""
        off = self._word_offset(buf)
        v = struct.unpack("<i", bytes(buf[off:off + 4]))[0]
        v = v * self.rng.choice((2, 4, 16, 256, -1)) if self.rng.random() < 0.7 else v // 2
        buf[off:off + 4] = struct.pack("<I", v & 0xffffffff)
        return buf

    def dictionary_word(self, buf):
        if not self.dictionary:
            return self.interesting_word(buf)
        c = self.rng.choice(sorted(self.dictionary))
        width = self.rng.choice((1, 4, 4, 4))
        if width == 1:
            if not buf:
                buf.append(0)
            buf[self.rng.randrange(len(buf))] = c & 0xff
        else:
            off = self._word_offset(buf)
            buf[off:off + 4] = struct.pack("<I", c & 0xffffffff)
        return buf

    def insert_bytes(self, buf):
        at = self.rng.randrange(len(buf) + 1)
        if self.rng.random() < 0.5:
            fill = bytes(self.rng.randrange(256) for _ in range(self.rng.randint(1, 8)))
        else:
            # A run of one byte, long enough to cross a 16-byte buffer: the
            # route to "ten digits in a row" and similar length-driven paths.
            fill = bytes([self.rng.choice(INTERESTING_8)]) * self.rng.randint(1, 16)
        buf[at:at] = fill
        return buf

    def delete_bytes(self, buf):
        if not buf:
            return self.insert_bytes(buf)
        n = self.rng.randint(1, min(8, len(buf)))
        at = self.rng.randrange(len(buf) - n + 1)
        del buf[at:at + n]
        return buf

    def truncate(self, buf):
        """Cut to a random length, including zero: the empty input is a
        boundary case nothing else would reach."""
        del buf[self.rng.randrange(len(buf) + 1):]
        return buf

    def copy_chunk(self, buf):
        if len(buf) < 2:
            return self.insert_bytes(buf)
        n = self.rng.randint(1, len(buf) // 2 or 1)
        src = self.rng.randrange(len(buf) - n + 1)
        dst = self.rng.randrange(len(buf) - n + 1)
        buf[dst:dst + n] = buf[src:src + n]
        return buf

    OPS = ("flip_bit", "random_byte", "interesting_byte", "arith_byte", "interesting_word",
           "arith_word", "arith_word", "scale_word", "dictionary_word",
           "dictionary_word", "insert_bytes", "delete_bytes", "truncate", "copy_chunk")

    def splice(self, a, b):
        if not a or not b:
            return bytearray(a or b)
        i = self.rng.randrange(len(a) + 1)
        j = self.rng.randrange(len(b) + 1)
        return bytearray(a[:i] + b[j:])

    def mutate(self, data, other=None):
        """One child: optionally spliced with `other`, then 1-8 stacked ops
        (AFL's "havoc"), truncated to max_len."""
        buf = bytearray(data)
        if other is not None and self.rng.random() < 0.15:
            buf = self.splice(buf, other)
        for _ in range(1 << self.rng.randrange(4)):
            buf = getattr(self, self.rng.choice(self.OPS))(buf)
        return bytes(buf[:self.max_len])


def pack_batch(inputs):
    """The harness's batch format: [u32 len][bytes] per record."""
    return b"".join(struct.pack("<I", len(x)) + x for x in inputs)


def parse_seed_file(text):
    """Seeds from a text file: one input per line, as hex, or as
    `i32: 1 2 3` (little-endian words) or `str: hello`. `#` starts a comment.
    """
    out = []
    for raw in text.split("\n"):
        line = raw.split("#", 1)[0].strip() if not raw.lstrip().startswith("str:") \
            else raw.strip()
        if not line:
            continue
        if line.startswith("i32:"):
            out.append(b"".join(struct.pack("<I", int(w, 0) & 0xffffffff)
                                for w in line[4:].split()))
        elif line.startswith("str:"):
            out.append(line[4:].strip().encode("latin-1"))
        else:
            out.append(bytes.fromhex(line))
    return out
