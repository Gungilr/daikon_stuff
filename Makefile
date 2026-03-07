CC     = gcc
CFLAGS = -Wall -g -gdwarf-3 -no-pie -fno-stack-protector

TEST_SRCS = $(wildcard tests/*.c)
TEST_BINS = $(TEST_SRCS:.c=.exe)

.PHONY: tests clean

tests: $(TEST_BINS)

tests/%.exe: tests/%.c
	$(CC) $(CFLAGS) -o $@ $

clean:
	rm -f $(TEST_BINS)