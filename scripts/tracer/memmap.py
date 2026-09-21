"""Value classification against the emulated address space.

Pure - no third-party imports. The Tracer hands it the regions it already
computes in _setup_memory; nothing here touches Unicorn.

This is the CHEAP half of pointer detection: a value is pointer-shaped if it
lands inside a mapped region. Tier 4 replaces it with a covariance test -
relocate the stack and heap bases independently across --layouts runs and see
which base a value tracks - which is strictly stronger because it distinguishes
a real pointer from an integer that merely happens to fall in range.
"""

SCALAR = "scalar"
POINTER = "pointer"

# A null pointer is neither: it is a legal pointer value that carries no
# address. Kept distinct so aggregation can ignore it rather than being forced
# to call it one or the other.
NULL = "null"


class MemoryMap:
    """Address ranges of the emulated process, for value classification."""

    def __init__(self):
        self.regions = []      # list of (lo, hi_exclusive, kind)

    def add_region(self, lo, size, kind):
        if size > 0:
            self.regions.append((lo, lo + size, kind))

    def region_of(self, value):
        for lo, hi, kind in self.regions:
            if lo <= value < hi:
                return kind
        return None

    def classify(self, value):
        """POINTER if the value lands in a mapped region, else SCALAR.

        Null gets its own verdict rather than being called a scalar. It used to
        be SCALAR, on the reasoning that the malloc stub returned 0 for every
        heap allocation and calling that a pointer would mistype them all. Tier
        5 replaced the stub with a real allocator, so a null argument now means
        the program genuinely passed NULL - and lumping it in with scalars made
        one NULL call destroy pointee recovery for every OTHER call to the same
        function.

        Small non-zero values are scalars, since no region starts near 0.
        """
        if value == 0:
            return NULL
        return POINTER if self.region_of(value) is not None else SCALAR


def classify_slot(verdicts):
    """Aggregate the per-sample verdicts recorded for one slot.

    Takes verdicts, not values: classification happens at sample time, while
    the layout's memory map is live. --layouts relocates the stack, so a value
    cannot be re-classified later against a map that has since moved.

    A real SCALAR sighting still demotes the slot: a register reused for both a
    pointer and a counter is not safely a pointer, and over-claiming would
    suppress real comparisons against genuine integers.

    NULL is neutral - it neither promotes nor demotes. A function called once
    with a valid pointer and once with NULL is still taking a pointer, and
    treating the NULL as disqualifying cost the pointee for every call.
    """
    saw_pointer = False
    for v in verdicts:
        if v == SCALAR:
            return SCALAR
        if v == POINTER:
            saw_pointer = True
    return POINTER if saw_pointer else SCALAR
