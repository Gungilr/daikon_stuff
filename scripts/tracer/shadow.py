"""Shadow memory: which heap bytes have been initialised (phase 11, step 5).

Pure. Kvasir runs under Memcheck and reads validity (V) bits; Unicorn has none,
and fresh pages read as zero, so without this the tracer reports a value for
memory the program never wrote - the one way its output is untrue rather than
incomplete. --poison-uninitialized approximates this with a fill byte, and
misreads a genuine value equal to the pattern; this is exact.

Scope follows Kvasir's own rules (fjalar_runtime.c):
  heap      tracked per byte: malloc'd bytes start undefined, calloc'd defined,
            realloc copies the definedness of the bytes it moves
  stack     the current frame counts as initialised - Kvasir does the same
  globals   initialised (loader-written .data, zero-filled .bss)
"""


class ShadowMap:
    def __init__(self):
        self._v = {}          # heap block base -> bytearray, 1 = defined

    def allocate(self, base, size, defined=False):
        if base and size and size > 0:
            self._v[base] = bytearray([1 if defined else 0]) * size

    def reallocate(self, old_base, new_base, new_size, ncopy):
        new = bytearray(max(new_size or 0, 0))
        old = self._v.get(old_base)
        if old is not None and ncopy:
            new[:ncopy] = old[:ncopy]
        if new_base:
            self._v[new_base] = new

    def write(self, base, offset, size):
        v = self._v.get(base)
        if v is None:
            return
        lo = max(offset, 0)
        hi = min(offset + size, len(v))
        if lo < hi:
            v[lo:hi] = b"\x01" * (hi - lo)

    def mask(self, base):
        """Bytes object of definedness for a heap block, or None (untracked)."""
        v = self._v.get(base)
        return bytes(v) if v is not None else None


def defined(mask, offset, size):
    """True if every byte of [offset, offset+size) is defined (or untracked)."""
    if mask is None:
        return True
    if offset < 0 or offset + size > len(mask):
        return False
    return all(mask[offset:offset + size])


def last_defined_element(mask, stride):
    """Number of leading elements up to and including the last defined one -
    Kvasir's heap-array probe: back from the end to the last initialised slot."""
    if mask is None or not stride:
        return None
    n = len(mask) // stride
    for i in range(n - 1, -1, -1):
        if any(mask[i * stride:(i + 1) * stride]):
            return i + 1
    return 0
