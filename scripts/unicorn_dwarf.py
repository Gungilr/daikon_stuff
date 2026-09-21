#!/usr/bin/env python3
"""Compatibility shim - the implementation lives in scripts/tracer/.

Kept so existing callers (test.sh, muscle memory, anything scripted against
the old path) keep working unchanged. Python puts this file's directory on
sys.path[0], which is what makes `tracer` importable; scripts/ deliberately
stays a non-package so that stays true.

Run `python scripts/unicorn_dwarf.py --help` for usage.
"""
import sys

from tracer.cli import main

if __name__ == "__main__":
    sys.exit(main())
