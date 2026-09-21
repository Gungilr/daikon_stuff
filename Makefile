CC         = gcc
CFLAGS     = -g -gdwarf-3 -no-pie -fno-stack-protector
STRIP      = strip
STRIPFLAGS = --strip-all

TEST_SRCS  = $(wildcard tests/*.c)
TEST_BINS  = $(TEST_SRCS:.c=.exe)
STRIP_BINS = $(TEST_SRCS:.c=_stripped.exe)

.PHONY: tests stripped clean

# Build everything: symbol-bearing binaries AND their stripped counterparts.
tests: $(TEST_BINS) $(STRIP_BINS)

# Build only the stripped set.
stripped: $(STRIP_BINS)

# Tiers 1 & 2: compile with DWARF debug info + symbol table.
tests/%.exe: tests/%.c
	$(CC) $(CFLAGS) -o $@ $<

# Tier 3: fully-stripped copy - no DWARF, no symbol table.
# Static pattern rule so these targets derive from the compiled .exe,
# never from a .c. The -o flag writes a NEW file, leaving the original
# symbol-bearing binary untouched (in-place `strip` is what clobbered
# test02.exe before).
$(STRIP_BINS): tests/%_stripped.exe: tests/%.exe
	$(STRIP) $(STRIPFLAGS) -o $@ $<

clean:
	rm -f $(TEST_BINS) $(STRIP_BINS)