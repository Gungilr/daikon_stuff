#!/usr/bin/env bash
#
# run_corpus.sh - For every ELF executable in ./tests/, run BOTH the
# emulation tracer and Kvasir, then run Daikon on each. Trace artifacts go
# to ./traces/; invariant reports go to ./invariants/.
#
# Kvasir requires DWARF debug info, so it runs only on the -g binaries
# (tests/*.exe). Stripped binaries (tests/*_stripped.exe) are traced by the
# emulator only; Kvasir is reported as skipped for them.
#
# Per binary <name> (basename without a trailing .exe):
#   traces/<name>.tracer.t<N>.dtrace  tracer's Daikon trace at tier N
#   traces/<name>.tracer.t<N>.log     tracer stdout/stderr
#   traces/<name>.kvasir.dtrace      Kvasir's trace (copied from daikon-output/)
#   traces/<name>.kvasir.decls       Kvasir's declarations
#   traces/<name>.kvasir.log         Kvasir stdout/stderr
#   invariants/<name>.tracer.t<N>.txt Daikon invariants from the tracer
#   invariants/<name>.kvasir.txt     Daikon invariants from Kvasir (the oracle)
#
# Usage:
#   ./run_corpus.sh [options] [-- EXTRA_TRACER_ARGS...]
#
# Options:
#   --tests DIR            Directory to scan          (default: ./tests)
#   --out DIR             Trace output directory      (default: ./traces)
#   --inv DIR             Invariant output directory  (default: ./invariants)
#   --tracer PATH         Tracer script               (default: ./scripts/unicorn_dwarf.py)
#   --kvasir PATH         kvasir-dtrace               (default: $DAIKONDIR/scripts/kvasir-dtrace)
#   --start-func NAME     Tracer start function       (default: main)
#   --tier N              Tracer heuristic tier 0-9   (default: 0)
#                         Outputs are named per tier, so tiers never clobber
#                         each other and can be compared side by side:
#                           ./test.sh --tier 0
#                           ./test.sh --tier 2 --no-kvasir
#                         Kvasir output is tier-independent and keeps its name;
#                         pass --no-kvasir on repeat runs to skip re-running it.
#   --stop-on-empty-stack Pass --stop-on-empty-stack to the tracer (for recursion)
#   --no-kvasir           Run the tracer only; skip Kvasir entirely
#   -h, --help            Show this help and exit
#
# Anything after a literal `--` is forwarded to the tracer, e.g.:
#   ./run_corpus.sh -- --max-insns 500000 -v
#
# Environment:
#   DAIKONDIR   path to your built Daikon tree (required)
#   PYTHON      python interpreter             (default: ./venv/bin/python if present, else python3)
#
# Note: scripts/daikon_test.py (the PE/Windows tracer) has no CLI argument
# parsing - it hardcodes test.exe/trace.dtrace paths - so it cannot be driven
# through --tracer here. This harness is for the ELF corpus tracer only.

set -u
# Intentionally no `set -e`: one binary/tool failing must not abort the batch.

shopt -s nullglob

# ---- Defaults -------------------------------------------------------------
TESTS_DIR="./tests"
TRACES_DIR="./traces"
INV_DIR="./invariants"
TRACER="./scripts/unicorn_dwarf.py"
KVASIR=""                     # resolved after DAIKONDIR check
START_FUNC="main"
TIER=0
if [[ -z "${PYTHON:-}" ]]; then
    if [[ -x "./venv/bin/python" ]]; then
        PYTHON="./venv/bin/python"
    else
        PYTHON="python3"
    fi
fi
RUN_KVASIR=1
TRACER_ARGS=()

print_help() { sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; }

# ---- Argument parsing -----------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tests)               TESTS_DIR="$2"; shift 2 ;;
        --out)                 TRACES_DIR="$2"; shift 2 ;;
        --inv)                 INV_DIR="$2"; shift 2 ;;
        --tracer)              TRACER="$2"; shift 2 ;;
        --kvasir)              KVASIR="$2"; shift 2 ;;
        --start-func)          START_FUNC="$2"; shift 2 ;;
        --tier)                TIER="$2"; shift 2 ;;
        --stop-on-empty-stack) TRACER_ARGS+=("--stop-on-empty-stack"); shift ;;
        --no-kvasir)           RUN_KVASIR=0; shift ;;
        -h|--help)             print_help; exit 0 ;;
        --)                    shift; TRACER_ARGS+=("$@"); break ;;
        *) echo "[!] Unknown option: $1" >&2
           echo "    Run with --help for usage." >&2; exit 2 ;;
    esac
done

if [[ ! "$TIER" =~ ^[0-9]$ ]]; then
    echo "[!] --tier must be 0-9 (got: $TIER)" >&2; exit 2
fi
for a in ${TRACER_ARGS+"${TRACER_ARGS[@]}"}; do
    if [[ "$a" == "--tier" || "$a" == --tier=* ]]; then
        echo "[!] Pass --tier before '--', not through it." >&2
        echo "    Output filenames are derived from it, so a passthrough copy" >&2
        echo "    would silently mislabel the results." >&2
        exit 2
    fi
done

# ---- Sanity checks --------------------------------------------------------
if [[ -z "${DAIKONDIR:-}" ]]; then
    echo "[!] DAIKONDIR is not set." >&2
    echo "    export DAIKONDIR=/path/to/your/daikon" >&2
    exit 1
fi
[[ -d "$TESTS_DIR" ]] || { echo "[!] Tests dir not found: $TESTS_DIR" >&2; exit 1; }
[[ -f "$TRACER"    ]] || { echo "[!] Tracer not found: $TRACER (use --tracer)" >&2; exit 1; }
command -v "$PYTHON" >/dev/null 2>&1 || { echo "[!] '$PYTHON' not on PATH (activate your venv?)" >&2; exit 1; }
command -v java      >/dev/null 2>&1 || { echo "[!] 'java' not on PATH." >&2; exit 1; }

# Resolve kvasir-dtrace and decide availability.
[[ -n "$KVASIR" ]] || KVASIR="$DAIKONDIR/scripts/kvasir-dtrace"
KVASIR_AVAILABLE=1
if [[ "$RUN_KVASIR" -eq 0 ]]; then
    KVASIR_AVAILABLE=0
elif [[ ! -x "$KVASIR" ]]; then
    KVASIR_AVAILABLE=0
    echo "[!] kvasir-dtrace not found/executable at: $KVASIR"
    echo "    Continuing with the tracer only (pass --kvasir PATH to point at it,"
    echo "    or build it with 'make kvasir')."
    echo
fi

DAIKON_CP="$DAIKONDIR/java:$DAIKONDIR/java/lib/*"

mkdir -p "$TRACES_DIR" "$INV_DIR"

# Daikon ALWAYS writes a serialized <dtrace-basename>.inv.gz, and with no -o it
# drops it in the current directory (daikon/java/daikon/Daikon.java, "Always
# output an invariant file by default"). There is no flag to turn that off, so
# point -o at a scratch directory and delete it on exit rather than littering
# the repo root. If you later want these for daikon.Diff-based scoring, change
# SERIAL_DIR to a real path and drop the trap.
SERIAL_DIR="$(mktemp -d)"
trap 'rm -rf "$SERIAL_DIR"' EXIT

# ---- Helpers --------------------------------------------------------------
is_elf_executable() {
    local f="$1"
    [[ -f "$f" ]] || return 1
    if command -v file >/dev/null 2>&1; then
        file -b "$f" | grep -qE '^ELF.*executable'
        return $?
    fi
    local hdr
    hdr=$(head -c 18 "$f" 2>/dev/null | od -An -tx1 | tr -d ' \n')
    [[ "$hdr" == 7f454c46* ]] || return 1
    local et="${hdr:32:4}"
    [[ "$et" == "0200" || "$et" == "0300" ]]
}

has_dwarf() {
    local f="$1"
    if command -v readelf >/dev/null 2>&1; then
        readelf -S "$f" 2>/dev/null | grep -q '\.debug_info'
        return $?
    fi
    if command -v file >/dev/null 2>&1; then
        file -b "$f" | grep -q 'with debug_info'
        return $?
    fi
    return 1   # can't tell -> assume no DWARF, skip Kvasir
}

daikon_empty() { grep -qE 'No samples found|No program point' "$1"; }

# Run the emulation tracer + Daikon. Echoes a status token: ok|S|P, empty|S, fail
run_tracer() {
    local bin="$1" name="$2"
    local dtrace="$TRACES_DIR/$name.tracer.t$TIER.dtrace"
    local log="$TRACES_DIR/$name.tracer.t$TIER.log"
    local inv="$INV_DIR/$name.tracer.t$TIER.txt"

    if ! "$PYTHON" "$TRACER" "$bin" \
            -o "$dtrace" --start-func "$START_FUNC" --tier "$TIER"             "${TRACER_ARGS[@]}" \
            >"$log" 2>&1 || [[ ! -s "$dtrace" ]]; then
        echo "fail"; return
    fi

    local samples
    samples=$(grep -oE 'Samples:[[:space:]]*[0-9]+' "$log" | grep -oE '[0-9]+' | tail -1)
    samples="${samples:-?}"

    java -cp "$DAIKON_CP" daikon.Daikon -o "$SERIAL_DIR/$name.tracer.t$TIER.inv.gz" "$dtrace" >"$inv" 2>&1
    if daikon_empty "$inv"; then echo "empty|$samples"; return; fi

    local ppts; ppts=$(grep -cE ':::' "$inv")
    echo "ok|$samples|$ppts"
}

# Run Kvasir + Daikon. Echoes: ok|P, skip, fail, na
run_kvasir() {
    local bin="$1" base="$2" name="$3"
    [[ "$KVASIR_AVAILABLE" -eq 1 ]] || { echo "na"; return; }
    has_dwarf "$bin" || { echo "skip"; return; }

    local log="$TRACES_DIR/$name.kvasir.log"
    local inv="$INV_DIR/$name.kvasir.txt"

    if ! "$KVASIR" "$bin" >"$log" 2>&1; then echo "fail"; return; fi

    # Kvasir names its output after the full basename (incl. .exe).
    local kd="daikon-output/$base.dtrace"
    local kc="daikon-output/$base.decls"
    [[ -f "$kd" ]] || kd=$(ls -t daikon-output/*.dtrace 2>/dev/null | head -1)
    [[ -n "$kd" && -f "$kd" ]] || { echo "fail"; return; }

    local kd_local="$TRACES_DIR/$name.kvasir.dtrace"
    local kc_local="$TRACES_DIR/$name.kvasir.decls"
    cp "$kd" "$kd_local" 2>/dev/null
    [[ -f "$kc" ]] && cp "$kc" "$kc_local" 2>/dev/null

    if [[ -f "$kc_local" ]]; then
        java -cp "$DAIKON_CP" daikon.Daikon -o "$SERIAL_DIR/$name.kvasir.inv.gz" "$kc_local" "$kd_local" >"$inv" 2>&1
    else
        java -cp "$DAIKON_CP" daikon.Daikon -o "$SERIAL_DIR/$name.kvasir.inv.gz" "$kd_local" >"$inv" 2>&1
    fi
    if daikon_empty "$inv"; then echo "fail"; return; fi

    local ppts; ppts=$(grep -cE ':::' "$inv")
    echo "ok|$ppts"
}

# ---- Banner ---------------------------------------------------------------
echo "[+] Tests dir : $TESTS_DIR"
echo "[+] Traces    : $TRACES_DIR"
echo "[+] Invariants: $INV_DIR"
echo "[+] Tracer    : $TRACER"
if [[ "$KVASIR_AVAILABLE" -eq 1 ]]; then
    echo "[+] Kvasir    : $KVASIR"
else
    echo "[+] Kvasir    : (disabled)"
fi
echo "[+] Start func: $START_FUNC"
echo "[+] Tier      : $TIER"
[[ ${#TRACER_ARGS[@]} -gt 0 ]] && echo "[+] Extra args: ${TRACER_ARGS[*]}"
echo

# ---- Main loop ------------------------------------------------------------
total=0; skipped=0
t_ok=0; t_empty=0; t_fail=0
k_ok=0; k_skip=0; k_fail=0; k_na=0

for bin in "$TESTS_DIR"/*; do
    [[ -f "$bin" ]] || continue
    total=$((total + 1))
    base="$(basename "$bin")"
    name="${base%.exe}"

    if ! is_elf_executable "$bin"; then
        printf '[ -- ] %-26s (not an ELF executable)\n' "$base"
        skipped=$((skipped + 1))
        continue
    fi

    ts=$(run_tracer "$bin" "$name")
    ks=$(run_kvasir "$bin" "$base" "$name")

    # --- format tracer column ---
    IFS='|' read -r tstate ta tb <<< "$ts"
    case "$tstate" in
        ok)    tracer_col=$(printf 'ok (samp=%s ppt=%s)' "$ta" "$tb"); t_ok=$((t_ok+1)) ;;
        empty) tracer_col=$(printf 'EMPTY (samp=%s)' "$ta");           t_empty=$((t_empty+1)) ;;
        *)     tracer_col="FAIL";                                      t_fail=$((t_fail+1)) ;;
    esac

    # --- format kvasir column ---
    IFS='|' read -r kstate ka <<< "$ks"
    case "$kstate" in
        ok)   kvasir_col=$(printf 'ok (ppt=%s)' "$ka"); k_ok=$((k_ok+1)) ;;
        skip) kvasir_col="skip (no DWARF)";             k_skip=$((k_skip+1)) ;;
        na)   kvasir_col="n/a";                         k_na=$((k_na+1)) ;;
        *)    kvasir_col="FAIL";                        k_fail=$((k_fail+1)) ;;
    esac

    printf '[run ] %-26s tracer: %-24s kvasir: %s\n' \
        "$base" "$tracer_col" "$kvasir_col"
done

# ---- Summary --------------------------------------------------------------
echo
echo "==================== summary ===================="
echo "  binaries scanned   : $total"
echo "  non-ELF skipped    : $skipped"
echo "  --- tracer ---"
echo "    invariants found : $t_ok"
echo "    empty            : $t_empty"
echo "    failures         : $t_fail"
echo "  --- kvasir ---"
echo "    invariants found : $k_ok"
echo "    skipped (no DWARF): $k_skip"
echo "    failures         : $k_fail"
[[ "$k_na" -gt 0 ]] && echo "    not run (disabled): $k_na"
echo
echo "  traces     -> $TRACES_DIR/"
echo "  invariants -> $INV_DIR/"
echo "  diff e.g.: diff $INV_DIR/test02.kvasir.txt $INV_DIR/test02.tracer.t$TIER.txt"
echo "================================================="

if [[ "$t_fail" -gt 0 ]]; then exit 1; fi
exit 0