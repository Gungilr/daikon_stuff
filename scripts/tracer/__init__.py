"""Black-box Daikon front-end for stripped x86-64 ELF binaries.

Deliberately EMPTY of re-exports. Importing a package runs its __init__ first,
so re-exporting anything from emulate.py here would make `import tracer.writer`
pull in unicorn and capstone - destroying the property that writer/schema/infer/
memmap are testable without an emulator. See tests_py/test_purity.py, which
enforces this.

Module map:
    log       Logger                                      pure
    schema    variable-name schemas, slot counts          pure
    writer    DaikonTraceWriter                           pure
    elfload   ELF parsing, function discovery             pyelftools
    emulate   Tracer, discover_main_via_emulation         unicorn + capstone
    cli       argument parsing and entry point
"""

__version__ = "0.1.0"
