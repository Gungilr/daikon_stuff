"""Daikon-in-the-loop fuzzing over source-available C targets.

Keep this file free of imports: dtrace, invariants and mutate are pure and
are unit-tested without a compiler, Valgrind or a JVM, and any re-export here
would run first on every one of those imports.
"""
