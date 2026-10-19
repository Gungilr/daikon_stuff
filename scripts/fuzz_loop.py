#!/usr/bin/env python3
"""Entry point for the Daikon/fuzzer loop; see scripts/fuzzloop/ and docs/FUZZ-LOOP.md."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fuzzloop.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
