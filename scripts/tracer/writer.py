"""Daikon .dtrace serialization.

Pure - no third-party imports, so it is unit-testable without an emulator.

Buffers every sample in memory and writes declarations before data on close(),
which is what Daikon's format requires.

Schema-driven: every program point carries its own list of VarSpec. Tier 0 is
not a special case in here, it is this API called with a flat list of untyped
int specs (see `legacy_specs`). One serializer, many callers.

Two format rules, both verified against Kvasir's output rather than inferred:

  * `this_invocation_nonce` is a SAMPLE PREFIX, not a variable. It is never
    declared, and it carries no modbit - two lines, not three. Daikon peeks the
    line after the ppt name and consumes only the header and the number
    (daikon/java/daikon/FileIO.java, read_data_trace_record). Declaring it
    shifts every following name/value/modbit triple by one line and silently
    desyncs the whole sample.

  * `orig(v)` variables are DERIVED by Daikon at exit points from the paired
    entry sample. A front-end must not emit them. Kvasir emits zero `orig(` and
    Daikon still reports orig() invariants.
"""

import gzip
from collections import OrderedDict
from dataclasses import dataclass
from typing import Optional

NONCE_HEADER = "this_invocation_nonce"

# Daikon's marker for a variable with no meaningful value here - a null or
# unreadable pointee, for instance. It carries modbit 2, not 1; writing 1
# would assert that the absent value had been freshly computed.
NONSENSICAL = "nonsensical"


def format_value(value):
    """Render a sample value in Daikon syntax.

    Sequences use bracket-and-space form - [ 1 2 ] - not Python's [1, 2].
    That is how a dereferenced pointee is represented. Kvasir models a
    pointer as a one-element sequence, and matching the representation is
    what makes the two sides comparable at all: it is why facts come out as
    `p[].a elements < return` rather than `return == p->a + p->b`.
    """
    if isinstance(value, (list, tuple)):
        return "[ " + " ".join(_scalar(v) for v in value) + " ]"
    return _scalar(value)


# Daikon's `int` rep-type is a signed 64-bit long. A value outside that range
# is not representable, and rendering it anyway relies on the consumer to wrap
# it - which Daikon does, silently, so it went unnoticed until the soundness
# audit compared our output against our own samples. Anything out of range is
# `nonsensical`, which is what that marker is for.
_INT64_MIN, _INT64_MAX = -(1 << 63), (1 << 63) - 1


def _scalar(value):
    if isinstance(value, int) and not (_INT64_MIN <= value <= _INT64_MAX):
        return NONSENSICAL
    return str(value)


def modbit_for(value):
    return "2" if value == NONSENSICAL else "1"


@dataclass(frozen=True)
class VarSpec:
    """One declared variable.

    Defaults reproduce the tier-0 shape (untyped int, comparability 22). The
    optional fields are unused until tier 3 (`flags is_param`) and tier 6
    (`enclosing_var`, `array` for dereferenced pointees).
    """

    name: str
    dec_type: str = "int"
    rep_type: str = "int"
    comparability: str = "22"
    var_kind: str = "variable"
    enclosing_var: Optional[str] = None
    array: Optional[int] = None
    flags: Optional[str] = None


def legacy_specs(var_names):
    """Build the flat, untyped schema tier 0 uses."""
    return [VarSpec(name) for name in var_names]


class DaikonTraceWriter:
    def __init__(self, filepath, var_comparability="none"):
        self.filepath = filepath
        self.var_comparability = var_comparability
        self.ppt_specs = OrderedDict()   # ppt -> (ppt_type, [VarSpec])
        self.data_samples = []           # list of (ppt, [values], nonce|None)
        self._next_nonce = 0

    # ---- Nonce allocation ----
    def next_nonce(self):
        """Allocate a globally unique invocation id.

        Deliberately owned by the writer, not the Tracer: `--layouts N` re-runs
        emulation N times into ONE trace, and a per-run counter would reissue
        ids across runs - reintroducing exactly the cross-run pairing ambiguity
        the nonce exists to remove.
        """
        n = self._next_nonce
        self._next_nonce += 1
        return n

    # ---- Declarations ----
    def declare(self, ppt_name, ppt_type, specs):
        """Register a program point. First declaration wins; repeats are no-ops
        so callers can declare lazily on every sample."""
        if ppt_name not in self.ppt_specs:
            self.ppt_specs[ppt_name] = (ppt_type, list(specs))

    def add_sample(self, ppt_name, values, nonce=None):
        if ppt_name not in self.ppt_specs:
            raise ValueError(f"{ppt_name}: sample added before declare()")
        _, specs = self.ppt_specs[ppt_name]
        # Guard against silent truncation: the writer zips specs against values,
        # so a length mismatch would quietly drop trailing variables and emit a
        # malformed .dtrace that Daikon may still parse. Cheap to catch here,
        # near-impossible to diagnose from the output - and the risk grows once
        # every ppt carries its own schema.
        if len(values) != len(specs):
            raise ValueError(
                f"{ppt_name}: got {len(values)} values for "
                f"{len(specs)} declared variables"
            )
        self.data_samples.append((ppt_name, values, nonce))

    # ---- Validation ----
    def validate(self):
        """Structural rules Daikon enforces, checked before we write.

        Violating any of these does not degrade the output - it makes Daikon
        reject the ENTIRE trace file, while the run still exits 0 and produces
        a report that looks merely sparse. That has now happened twice:
        `enclosing-var` naming an undeclared variable (phase 9, nine binaries
        silently reduced to 8-fact stubs) and `var-kind field` without its
        relative name (phase 10, two binaries to zero). Both were found from
        the far end, by disbelieving a score.

        Raises ValueError on the first violation.
        """
        for ppt, (_ptype, specs) in self.ppt_specs.items():
            names = [sp.name for sp in specs]
            present = set(names)
            seen = set()
            for spec in specs:
                # PRESENCE, not order. Daikon resolves enclosing variables
                # after reading every declaration in the ppt, so a forward
                # reference is legal - `return[..]` has preceded `return`
                # since phase 8 and Daikon has always accepted it. Requiring
                # declaration order made this validator reject five binaries
                # that Daikon is perfectly happy with.
                if spec.enclosing_var is not None and                         spec.enclosing_var not in present:
                    raise ValueError(
                        f"{ppt}: '{spec.name}' has enclosing-var "
                        f"'{spec.enclosing_var}', which is never declared")
                if spec.var_kind.startswith("field") and                         len(spec.var_kind.split()) < 2:
                    raise ValueError(
                        f"{ppt}: '{spec.name}' has var-kind 'field' with no "
                        f"relative name")
                if spec.name in seen:
                    raise ValueError(f"{ppt}: '{spec.name}' declared twice")
                seen.add(spec.name)

    # ---- Serialization ----
    def _write_var_decl(self, f, spec):
        f.write(f"variable {spec.name}\n")
        f.write(f"  var-kind {spec.var_kind}\n")
        if spec.enclosing_var is not None:
            f.write(f"  enclosing-var {spec.enclosing_var}\n")
        if spec.array is not None:
            f.write(f"  array {spec.array}\n")
        f.write(f"  dec-type {spec.dec_type}\n")
        f.write(f"  rep-type {spec.rep_type}\n")
        if spec.flags is not None:
            f.write(f"  flags {spec.flags}\n")
        f.write(f"  comparability {spec.comparability}\n")

    def close(self):
        """Serialize. Compresses when the path ends in `.gz`.

        The rule is deliberately the same one Daikon uses to decide whether to
        decompress (`FileIO.java:1418`, `raw_filename.endsWith(".gz")`), so a
        path that this writes is a path Daikon reads, with no flag on either
        side.

        Worth it because the output is extremely repetitive - measured on `bc`,
        every one of 154,550 array-global samples was byte-identical to the one
        before it - so 131.5 MB becomes 1.09 MB, 120x, in four seconds, with
        not one fact lost.
        """
        self.validate()
        opener = gzip.open if str(self.filepath).endswith(".gz") else open
        with opener(self.filepath, 'wt') as f:
            f.write("decl-version 2.0\n")
            f.write(f"var-comparability {self.var_comparability}\n\n")

            for ppt_name, (ppt_type, specs) in self.ppt_specs.items():
                f.write(f"ppt {ppt_name}\n")
                f.write(f"ppt-type {ppt_type}\n")
                for spec in specs:
                    self._write_var_decl(f, spec)
                f.write("\n")

            for ppt_name, values, nonce in self.data_samples:
                _, specs = self.ppt_specs[ppt_name]
                f.write(f"{ppt_name}\n")
                # Must be the FIRST line after the ppt name - Daikon peeks
                # exactly one line ahead to detect it. No modbit.
                if nonce is not None:
                    f.write(f"{NONCE_HEADER}\n{nonce}\n")
                for spec, val in zip(specs, values):
                    f.write(f"{spec.name}\n")
                    f.write(f"{format_value(val)}\n")
                    f.write(f"{modbit_for(val)}\n")
                f.write("\n")
