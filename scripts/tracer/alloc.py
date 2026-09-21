"""Emulated heap allocator.

Pure - no third-party imports, so allocation policy is unit-testable without an
emulator. The caller performs the actual memory effects (zeroing for calloc,
copying for realloc); this module only decides addresses and tracks sizes.

Without it, a call to malloc is an unresolved import: the tracer skips it and
forces the return register to zero, so every heap pointer in the trace is null,
the allocated object lives on the zero page that the unmapped-memory hook
lazily maps, and the trace asserts things about the program that are not true.

FREED BLOCKS ARE NEVER REISSUED, and that is deliberate. The obvious objection
is that glibc recycles, so a realistic model should too - but the oracle here is
Kvasir, which runs under Valgrind, and Valgrind's allocator adds redzones and
delays reuse for error detection. Measured on tests/test08.c, which allocates
and frees an 8-byte struct ten times, Kvasir observed ten DISTINCT addresses
(0x4a7a040, 0x4a7a090, 0x4a7a0e0, ... stepping by 0x50). A recycling model would
hand back one address ten times and manufacture a spurious
`arg0 has only one value` that the oracle does not report. Non-reuse is both
simpler and closer to ground truth.
"""

# SysV guarantees malloc results are suitably aligned for any type; 16 bytes
# covers long double and SSE.
ALIGNMENT = 16


def _round_up(n, to=ALIGNMENT):
    return ((n + to - 1) // to) * to


class Arena:
    """Bump allocator over a fixed address range."""

    def __init__(self, base, size):
        self.base = base
        self.size = size
        self.cursor = base
        self.sizes = {}        # addr -> requested size, kept after free
        self.dead = set()      # freed addresses
        self.exhausted = False

    # ---- allocation ----
    def malloc(self, nbytes):
        """Return a fresh address, or 0 when the arena is exhausted.

        Returning 0 makes exhaustion degrade to exactly the pre-tier-5
        behavior rather than handing out addresses past the mapped region,
        where writes would silently succeed via the lazy-map hook.
        """
        if nbytes < 0:
            return 0
        # malloc(0) must return a unique non-null pointer that free() accepts.
        need = _round_up(nbytes if nbytes > 0 else 1)
        if self.cursor + need > self.base + self.size:
            self.exhausted = True
            return 0
        addr = self.cursor
        self.cursor += need
        self.sizes[addr] = nbytes
        return addr

    def calloc(self, count, each):
        """Return (addr, nbytes_to_zero). The caller does the zeroing."""
        total = count * each
        if count and each and total // count != each:      # overflow
            return 0, 0
        addr = self.malloc(total)
        return addr, (total if addr else 0)

    def realloc(self, ptr, nbytes):
        """Return (addr, nbytes_to_copy). The caller does the copying.

        Safe to copy AFTER this returns: the old block is never reissued, so
        its contents are still intact.
        """
        if ptr == 0:
            return self.malloc(nbytes), 0
        old = self.sizes.get(ptr)
        addr = self.malloc(nbytes)
        if addr == 0:
            return 0, 0
        ncopy = min(old, nbytes) if old is not None else 0
        if old is not None:
            self.free(ptr)
        return addr, ncopy

    def free(self, ptr):
        """True if the pointer was a live allocation.

        Never raises. A traced program may double-free or free a foreign
        pointer, and emulation must not abort on a bug in the target.
        """
        if ptr == 0:
            return True                      # free(NULL) is legal and a no-op
        if ptr not in self.sizes or ptr in self.dead:
            return False
        self.dead.add(ptr)
        return True

    # ---- queries ----
    def size_of(self, ptr):
        """Requested size of an allocation, or None.

        Answers for freed blocks too, since a trace may still reference them.
        This is the phase's real deliverable: tier 6 uses it to bound a
        dereference, and tier 7 to derive array element counts.
        """
        return self.sizes.get(ptr)

    def owns(self, addr):
        return self.base <= addr < self.base + self.size

    def live(self):
        return {a: s for a, s in self.sizes.items() if a not in self.dead}

    def stats(self):
        return {
            "allocations": len(self.sizes),
            "live": len(self.sizes) - len(self.dead),
            "bytes_used": self.cursor - self.base,
            "exhausted": self.exhausted,
        }
