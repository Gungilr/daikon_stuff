"""Minimal leveled logger.

Its own module so elfload.py can accept a `log` parameter without importing
cli.py (which would create a cycle). Pure - no third-party imports.
"""
from __future__ import print_function

import sys


class Logger:
    def __init__(self, quiet=False, verbose=False):
        self.quiet = quiet
        self.verbose_on = verbose

    def info(self, msg):
        if not self.quiet:
            print(msg, file=sys.stderr)

    def verbose(self, msg):
        if self.verbose_on and not self.quiet:
            print(msg, file=sys.stderr)

    def error(self, msg):
        print(f"[!] {msg}", file=sys.stderr)
