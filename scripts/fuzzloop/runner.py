"""The impure half: compiling targets and running them, Kvasir and Daikon.

Two builds of every target, from the same source:

  <name>.cov   native, -fsanitize-coverage=trace-pc,trace-cmp, linked with
               fuzz/runtime/cov.c. Milliseconds per batch. Gives coverage,
               comparison constants, and crash detection.
  <name>.kv    -g -O0, no instrumentation, run under Kvasir. About a second
               per batch, almost all Valgrind start-up. Gives the variable
               values Daikon needs.

Every batch runs natively first. Inputs that crash or hang there are set
aside and never reach Kvasir, so one bad input cannot cost a whole batch of
traces.
"""
import json
import re
import os
import shutil
import signal
import subprocess
import sys

from . import bugs, dtrace
from .mutate import pack_batch

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RUNTIME = os.path.join(REPO, "fuzz", "runtime")
TRACER = os.path.join(REPO, "scripts", "unicorn_dwarf.py")

# Kept in step with the corpus Makefile so a target traces like tests/*.exe.
# -fwrapv makes signed overflow wrap instead of being undefined, so the
# overflow the fuzzer finds is the overflow Kvasir records.
KV_CFLAGS = ["-O0", "-g", "-gdwarf-3", "-no-pie", "-fno-stack-protector", "-fwrapv"]
COV_CFLAGS = ["-O0", "-g", "-fwrapv"]


class ToolError(RuntimeError):
    pass


def _subprocess_run(cmd, timeout=None, **kw):
    """subprocess.run, but a timeout kills the command's whole process group.

    kvasir-dtrace is a shell script around Valgrind. subprocess.run's timeout
    kills only the shell; Valgrind keeps the output pipes open and run()
    waits for it anyway, so a 40 s timeout on replace became 300 s.
    """
    with subprocess.Popen(cmd, start_new_session=True, **kw) as proc:
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            out, err = proc.communicate()
            raise subprocess.TimeoutExpired(cmd, timeout, output=out, stderr=err)
        except BaseException:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            raise
    return subprocess.CompletedProcess(cmd, proc.returncode, out, err)


def _run(cmd, **kw):
    p = _subprocess_run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)
    if p.returncode != 0:
        raise ToolError("%s failed (%d):\n%s" % (
            " ".join(cmd), p.returncode, p.stderr.decode(errors="replace")[-4000:]))
    return p


def build(target_c, workdir, cc=None):
    """(cov_exe, kv_exe) for a target source file."""
    cc = cc or os.environ.get("CC", "gcc")
    os.makedirs(workdir, exist_ok=True)
    name = os.path.splitext(os.path.basename(target_c))[0]
    harness = os.path.join(RUNTIME, "harness.c")
    cov_rt = os.path.join(RUNTIME, "cov.c")

    kv = os.path.join(workdir, name + ".kv")
    _run([cc] + KV_CFLAGS + [target_c, harness, "-o", kv, "-lm"])

    objs = []
    for src, flags in ((target_c, ["-fsanitize-coverage=trace-pc,trace-cmp"]),
                       (harness, ["-DFUZZ_COV"]),
                       (cov_rt, [])):
        obj = os.path.join(workdir, os.path.basename(src) + ".cov.o")
        _run([cc] + COV_CFLAGS + flags + ["-c", src, "-o", obj])
        objs.append(obj)
    cov = os.path.join(workdir, name + ".cov")
    _run([cc] + objs + ["-o", cov, "-lm"])
    return cov, kv


# --- native coverage runs ---------------------------------------------------

def _parse_cov(path):
    started, feats, consts, died = [], {}, {}, {}
    if not os.path.exists(path):
        return started, feats, consts, died
    with open(path) as f:
        for line in f:
            parts = line.split()
            if not parts:
                continue
            tag, ident = parts[0], int(parts[1])
            if tag == "S":
                started.append(ident)
            elif tag == "F":
                feats[ident] = frozenset(int(x) for x in parts[2:])
            elif tag == "C":
                consts[ident] = [int(x) for x in parts[2:]]
            elif tag == "X":
                died[ident] = int(parts[2])
    return started, feats, consts, died


def run_cov(cov_exe, inputs, workdir, timeout=10.0):
    """Run every input natively.

    Returns (results, crashes): results[i] = (features, constants) for each
    input that completed, crashes = [(i, reason)] for each that did not.
    """
    results, crashes = {}, []
    pending = list(range(len(inputs)))
    batch_path = os.path.join(workdir, "cov.batch")
    out_path = os.path.join(workdir, "cov.out")
    while pending:
        with open(batch_path, "wb") as f:
            f.write(pack_batch([inputs[i] for i in pending]))
        if os.path.exists(out_path):
            os.remove(out_path)
        reason = None
        try:
            p = _subprocess_run([cov_exe, batch_path, out_path], stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE, timeout=timeout,
                               env=dict(os.environ, FUZZ_FORK="1"))
            if p.returncode != 0:
                reason = _describe_exit(p.returncode)
        except subprocess.TimeoutExpired:
            reason = "timeout"
        started, feats, consts, died = _parse_cov(out_path)
        for local, fs in feats.items():
            results[pending[local]] = (fs, consts.get(local, []))
        # Records the fork server saw die (the process itself carried on).
        for local, code in sorted(died.items()):
            crashes.append((pending[local], _describe_code(code)))
        if reason is None:
            break
        # The last record that started but never reported is the culprit.
        unfinished = [s for s in started if s not in feats]
        if unfinished:
            bad = unfinished[-1]
        elif started:
            # Every started record finished, then the process died between
            # records or at exit: a memory bug in the last one corrupted the
            # heap or stack and the damage surfaced later (Juliet's heap
            # overflow did this). Blame that record and carry on after it.
            bad = max(started)
            results.pop(pending[bad], None)
        else:
            raise ToolError("coverage run failed (%s) outside any input" % reason)
        crashes.append((pending[bad], reason))
        pending = pending[bad + 1:]
    return results, crashes


# Native and sanitizer runs set FUZZ_FORK=1: the harness's fork server.
def _describe_code(code):
    """A fork-server death code: a signal number, or 1000 + exit status."""
    if code >= 1000:
        return "exit %d" % (code - 1000)
    return _describe_exit(-code)


def _describe_exit(rc):
    if rc < 0:
        try:
            return signal.Signals(-rc).name
        except ValueError:
            return "signal %d" % -rc
    return "exit %d" % rc


# --- the bug checker: a sanitizer build -------------------------------------

# Deliberately WITHOUT -fwrapv: with it, gcc drops the signed-overflow check.
# UBSan is recoverable so one input can report several problems and the batch
# continues; ASan aborts, and run_san restarts after the culprit.
SAN_CFLAGS = ["-O0", "-g", "-fsanitize=address,undefined",
              "-fsanitize-recover=address,undefined", "-fno-omit-frame-pointer"]
# Recover mode: every report is printed and the batch keeps going. Fatal
# signals are left to the harness, which reports and moves to the next input.
# Both runtimes print each distinct source location once per process, so a
# bug's `hits` counts the batches it fired in, not every input.
SAN_ENV = {"ASAN_OPTIONS": "detect_leaks=0:halt_on_error=0:symbolize=1:"
                           "handle_segv=0:handle_sigbus=0:handle_sigfpe=0:"
                           "handle_sigill=0",
           "UBSAN_OPTIONS": "print_stacktrace=0:halt_on_error=0"}


def build_san(target_c, workdir, cc=None):
    """Path of the sanitizer build of the target, with the batch harness.

    Prefers clang. gcc 13.3's ASan left copy_record() in
    fuzz/targets/packet.c with no checks at all (zero __asan_report calls in
    its machine code), so a 32-byte write into a 16-byte stack array went
    unreported. clang's ASan reports it. Falls back to $CC or gcc.
    """
    cc = cc or os.environ.get("SAN_CC") or (shutil.which("clang") and "clang") \
        or os.environ.get("CC", "gcc")
    os.makedirs(workdir, exist_ok=True)
    name = os.path.splitext(os.path.basename(target_c))[0]
    exe = os.path.join(workdir, name + ".san")
    _run([cc] + SAN_CFLAGS + ["-DFUZZ_SAN", target_c,
                              os.path.join(RUNTIME, "harness.c"), "-o", exe, "-lm"])
    return exe


def own_sources(target_c):
    """Basenames of the C sources that make up a target.

    A target may #include other .c files (Juliet's cases/, libpng's src/).
    ASan reports are keyed to the first frame in one of these, so with only
    the top file every memory error in an included case collapsed onto the
    dispatcher's call line, and Juliet's memcpy(-n) looked like a repeat of
    an earlier memset(-n).
    """
    top = os.path.dirname(os.path.abspath(target_c))
    names = {os.path.basename(target_c)}
    if os.path.basename(top) != "targets":      # not the shared top folder
        for root, _, files in os.walk(top):
            names.update(f for f in files if f.endswith((".c", ".h")))
    return tuple(sorted(names))


def run_san(san_exe, inputs, workdir, own_sources=(), timeout=60.0):
    """{input index: [bugs.Bug]} for every input that triggered a report.

    An input that kills the process (an ASan report, or a signal) is the last
    one to have printed its marker. Its bugs are recorded and the batch is
    re-run from the next input, as run_cov does for crashes.
    """
    found = {}
    pending = list(range(len(inputs)))
    batch_path = os.path.join(workdir, "san.batch")
    env = dict(os.environ, FUZZ_FORK="1", **SAN_ENV)
    while pending:
        with open(batch_path, "wb") as f:
            f.write(pack_batch([inputs[i] for i in pending]))
        try:
            p = _subprocess_run([san_exe, batch_path], stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE, env=env, timeout=timeout)
            err, rc = p.stderr.decode(errors="replace"), p.returncode
        except subprocess.TimeoutExpired as e:
            err = (e.stderr or b"").decode(errors="replace")
            rc = "timeout"
        per, last = bugs.parse_stderr(err, own_sources)
        for local, bs in per.items():
            found.setdefault(pending[local], []).extend(bs)
        if rc == 0:
            break
        if last is None:
            raise ToolError("sanitizer run failed (%s) before any input:\n%s"
                            % (rc, err[-2000:]))
        if last not in per:
            # Died without a parseable report: still a bug, by its exit status.
            kind = "timeout" if rc == "timeout" else _describe_exit(rc)
            found.setdefault(pending[last], []).append(
                bugs.Bug("signal", kind, "?", "process ended: %s" % kind))
        pending = pending[last + 1:]
    return found


# --- Kvasir -----------------------------------------------------------------

def kvasir_path(daikondir):
    return os.path.join(daikondir, "scripts", "kvasir-dtrace")


def write_ppt_list(kv_exe, workdir, daikondir):
    """Path of a --ppt-list-file naming only the program points worth tracing.

    Kvasir otherwise traces every function with debug info, including the
    harness and the fuzz.h helpers, which are called several times per input
    and cost more trace than the target itself. Two harness functions stay in:

      fuzz_input_begin  the marker; it is how samples are attributed to inputs.
      fuzz_target       Kvasir sizes a stack array only while the frame that
                        owns it is traced. Untraced, buffer.c's 16-byte `buf`
                        is reported as ONE element and every array invariant
                        downstream is about buf[0]. Its own samples are still
                        dropped by dtrace.keep_ppt before Daikon.
    """
    empty = os.path.join(workdir, "empty.batch")
    dump = os.path.join(workdir, "all.ppts")
    with open(empty, "wb"):
        pass
    _run([kvasir_path(daikondir), "--dump-ppt-file=" + dump,
          "--dtrace-file=/dev/null", "--decls-file=/dev/null", kv_exe, empty],
         cwd=workdir, timeout=120)
    with open(dump) as f:
        names = [line.strip() for line in f if line.strip()]
    keep = [n for n in names if dtrace.keep_ppt(n + ":::ENTER")
            or dtrace.is_marker(n + ":::ENTER") or n.endswith("fuzz_target()")]
    path = os.path.join(workdir, "trace.ppts")
    with open(path, "w") as f:
        f.write("\n".join(keep) + "\n")
    return path


def apply_call_budget(kv_exe, seeds, workdir, daikondir, ppt_list, budget):
    """(ppt list path, [(function, calls per input)] dropped).

    Kvasir pays about 1.4 ms per traced call, whatever the arrays involved.
    On replace, six helpers called once per character made 92% of 50,885
    calls for 100 inputs: 0.6 s per input. Tracing the seeds once and
    dropping every function that averages more than `budget` calls per input
    keeps the loop usable. It also means Daikon learns NOTHING about those
    functions, so the caller should report what was dropped.
    """
    if not budget or not seeds:
        return ppt_list, []
    dt = os.path.join(workdir, "calib.dtrace")
    dc = os.path.join(workdir, "calib.decls")
    batch = os.path.join(workdir, "calib.batch")
    with open(batch, "wb") as f:
        f.write(pack_batch(seeds))
    _run([kvasir_path(daikondir), "--no-dyncomp", "--dtrace-file=" + dt,
          "--decls-file=" + dc, "--ppt-list-file=" + ppt_list, kv_exe, batch],
         cwd=workdir, timeout=1800)
    counts = {}
    with open(dt, errors="replace") as f:
        for line in f:
            if line.endswith(":::ENTER\n"):
                fn = line[:-len(":::ENTER\n")]
                counts[fn] = counts.get(fn, 0) + 1
    with open(ppt_list) as f:
        names = [n.strip() for n in f if n.strip()]
    keep, dropped = [], []
    for n in names:
        per = counts.get(n, 0) / float(len(seeds))
        if per > budget and not (dtrace.is_marker(n + ":::ENTER")
                                 or n.endswith("fuzz_target()")):
            dropped.append((n, per))
        else:
            keep.append(n)
    path = os.path.join(workdir, "trace.budget.ppts")
    with open(path, "w") as f:
        f.write("\n".join(keep) + "\n")
    return path, sorted(dropped, key=lambda x: -x[1])


def _parse_var_dump(text):
    """[(section name, [variable lines])] from a --dump-var-file."""
    out = []
    for chunk in text.split("----SECTION----"):
        lines = [l.strip() for l in chunk.split("\n") if l.strip()]
        if lines:
            out.append((lines[0], lines[1:]))
    return out


def _global_base(entry):
    """`/x[]`, `/path_c@f/buf[].a` -> the C name: `x`, `buf`."""
    tail = entry.rsplit("/", 1)[-1]
    return re.split(r"\[|\.|->", tail, 1)[0]


def _function_globals(kv_exe):
    """{function name: set of global symbol names its own code touches},
    from the binary's disassembly.

    -no-pie and -O0 make every global access an absolute or RIP-relative
    address that objdump prints; matching those against the data symbols'
    ranges gives each function's globals without parsing C.
    """
    syms = []
    nm = subprocess.run(["nm", "-S", "--defined-only", kv_exe], stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, check=True).stdout.decode()
    for line in nm.splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[2] in "dDbBrR" and int(parts[1], 16) > 0:
            syms.append((int(parts[0], 16), int(parts[0], 16) + int(parts[1], 16),
                         re.sub(r"\.\d+$", "", parts[3])))
    out, cur = {}, None
    dis = subprocess.run(["objdump", "-d", "--no-show-raw-insn", kv_exe],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         check=True).stdout.decode(errors="replace")
    for line in dis.splitlines():
        m = re.match(r"^[0-9a-f]+ <([^>]+)>:$", line)
        if m:
            cur = m.group(1)
            out[cur] = set()
            continue
        if cur is None:
            continue
        for h in re.findall(r"(?:0x|# )([0-9a-f]+)", line):
            addr = int(h, 16)
            for lo, hi, name in syms:
                if lo <= addr < hi:
                    out[cur].add(name)
                    break
    return out


def _with_parents(vars_):
    """Insert the `p[]` entry each `p[].field` needs.

    --dump-var-file lists `p` and `p[].field` (or `p->field`) but not `p[]`
    (or `p[0]`), and when that list is read back Kvasir declares the field
    with no enclosing variable, which Daikon rejects ("enclosing-var not
    specified"). Adding the parents restores the declarations Kvasir writes
    without a list (checked on all six benchmark targets).
    """
    have, out = set(vars_), []
    for v in vars_:
        # `p[].f` needs `p[]`; `p->f` needs `p[0]` (Kvasir's name for *p).
        pres = [v[:m.end()] for m in re.finditer(r"\[\]", v)]
        pres += [v[:m.start()] + "[0]" for m in re.finditer(r"->", v)]
        for pre in sorted(pres, key=len):
            if pre != v and pre not in have:
                have.add(pre)
                out.append(pre)
        out.append(v)
    return out


def write_var_list(kv_exe, workdir, daikondir, ppt_list):
    """Path of a --var-list-file that traces only the globals some traced
    function touches directly, and none of the harness's statics.

    By default Kvasir writes EVERY global at EVERY sample: print_tokens'
    four 360-entry state tables (used only by next_state, which the call
    budget leaves untraced) went into each of its 25,000 samples per 300
    inputs, 72 MB; and the harness's own statics, a jmp_buf among them, went
    into every sample of every target.

    The list has to be one shared "globals" section: Kvasir's per-function
    global entries crash it (SIGSEGV) or, without the slash, are ignored.
    """
    kv_exe = os.path.abspath(kv_exe)
    dump = os.path.join(workdir, "all.vars")
    empty = os.path.join(workdir, "empty.batch")
    with open(empty, "wb"):
        pass
    _run([kvasir_path(daikondir), "--no-dyncomp", "--dump-var-file=" + dump,
          "--dtrace-file=/dev/null", "--decls-file=/dev/null", kv_exe, empty],
         cwd=workdir, timeout=120)
    with open(dump) as f:
        sections = _parse_var_dump(f.read())
    with open(ppt_list) as f:
        traced = {l.strip()[:-2].rsplit(".", 1)[-1] for l in f
                  if l.strip() and not dtrace.DEFAULT_OMIT.search(l.strip())}
    used = set()
    for fn, gl in _function_globals(kv_exe).items():
        if fn in traced:
            used |= gl
    parts = []
    for name, vars_ in sections:
        if name == "globals":
            # Function statics carry their owner: `.../x_c@run_prog/devnull_in`.
            vars_ = [g for g in vars_ if _global_base(g) in used
                     and not ("@" in g and dtrace.DEFAULT_OMIT.search(
                         ".%s()" % g.rsplit("@", 1)[1].split("/")[0]))]
        parts.append("----SECTION----\n%s\n%s\n" % (name, "\n".join(_with_parents(vars_))))
    path = os.path.join(workdir, "trace.vars")
    with open(path, "w") as f:
        f.write("\n".join(parts))
    return path


def run_kvasir(kv_exe, inputs, workdir, daikondir, ppt_list=None, timeout=600.0,
               crashed=None, var_list=None, dyncomp=True):
    """(decls, {i: [Sample]}) for a batch of inputs that run cleanly natively.

    decls is (header, {ppt: block}); samples are already split per input and
    stripped of harness program points.

    Running natively is no guarantee under Valgrind: on tcas, an
    out-of-bounds read that lands in mapped memory natively segfaults Kvasir.
    So a Kvasir failure costs the input it happened in, not the run. The
    last input whose marker reached the trace is the culprit; the inputs
    before it keep their samples, and the batch is re-run after it. Culprit
    indices are appended to `crashed` if given.
    """
    batch_path = os.path.join(workdir, "kv.batch")
    dt_path = os.path.join(workdir, "kv.dtrace")
    dc_path = os.path.join(workdir, "kv.decls")
    select = ["--ppt-list-file=" + ppt_list] if ppt_list else []
    if var_list:
        select.append("--var-list-file=" + var_list)
    if not dyncomp:
        # DynComp (comparability analysis) is 3-12x of Kvasir's time, and the
        # comparability it computes lands only in the .decls file. The loop
        # keeps the seed run's declarations, so later batches need none.
        select.append("--no-dyncomp")
    decls, kept = None, {}
    pending = list(range(len(inputs)))
    while pending:
        with open(batch_path, "wb") as f:
            f.write(pack_batch([inputs[i] for i in pending]))
        for p in (dt_path, dc_path):
            if os.path.exists(p):
                os.remove(p)
        cmd = [kvasir_path(daikondir), "--dtrace-file=" + dt_path,
               "--decls-file=" + dc_path] + select + [kv_exe, batch_path]
        try:
            p = _subprocess_run(cmd, cwd=workdir, timeout=timeout,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            failed = p.returncode != 0
            err = p.stderr.decode(errors="replace")
        except subprocess.TimeoutExpired:
            failed, err = "timeout", "timeout"
        if decls is None and os.path.exists(dc_path):
            with open(dc_path, errors="replace") as f:
                decls = dtrace.parse_decls(f.read())
        samples = []
        if os.path.exists(dt_path):
            with open(dt_path, errors="replace") as f:
                samples = dtrace.parse_dtrace(f.read())
        per_input = dtrace.split_by_input(samples)
        if not failed:
            for local, ss in per_input.items():
                kept[pending[local]] = [s for s in ss if dtrace.keep_ppt(s.ppt)]
            break
        if failed == "timeout":
            # Out of time, not a crash: keep the inputs that finished and drop
            # the rest of the batch rather than paying the timeout again.
            last = max(per_input) if per_input else -1
            for local, ss in per_input.items():
                if local < last:
                    kept[pending[local]] = [s for s in ss if dtrace.keep_ppt(s.ppt)]
            break
        if not per_input:
            raise ToolError("Kvasir failed before any input:\n%s" % err[-3000:])
        bad = max(per_input)
        for local, ss in per_input.items():
            if local < bad:
                kept[pending[local]] = [s for s in ss if dtrace.keep_ppt(s.ppt)]
        if crashed is not None:
            crashed.append(pending[bad])
        pending = pending[bad + 1:]
    if decls is None:
        raise ToolError("Kvasir wrote no declarations")
    return decls, kept


# --- Daikon -----------------------------------------------------------------

def daikon_jar(daikondir):
    jar = os.path.join(daikondir, "daikon.jar")
    if os.path.exists(jar):
        return jar
    # A source checkout built with `make` has classes, not a jar.
    return os.path.join(daikondir, "java") + os.pathsep + os.path.join(daikondir, "java", "lib", "*")


def run_daikon(decls_path, dtrace_path, workdir, daikondir, conf_limit=None,
               extra_args=(), timeout=1800.0):
    """Daikon's text report for one decls + dtrace pair."""
    inv_gz = os.path.join(workdir, "daikon.inv.gz")
    conf = [] if conf_limit is None else ["--conf_limit", str(conf_limit)]
    p = _run(["java", "-cp", daikon_jar(daikondir), "daikon.Daikon"] + conf
             + list(extra_args) + ["-o", inv_gz, decls_path, dtrace_path],
             cwd=workdir, timeout=timeout)
    return p.stdout.decode(errors="replace")


def check_tools(daikondir, frontend="kvasir"):
    """[problem] - empty when everything the loop needs is present."""
    problems = []
    if not daikondir:
        return ["DAIKONDIR is not set (or pass --daikon)."]
    if not os.path.isdir(daikondir):
        return ["DAIKONDIR does not exist: %s" % daikondir]
    if frontend == "tracer":
        try:
            import unicorn  # noqa: F401
            import capstone  # noqa: F401
            import elftools  # noqa: F401
        except ImportError as e:
            problems.append("the tracer front-end needs unicorn, capstone and "
                            "pyelftools: %s" % e)
        if not shutil.which("strip"):
            problems.append("strip is not on PATH")
    elif not os.path.exists(os.path.join(daikondir, "fjalar", "valgrind", "inst", "bin", "valgrind")):
        problems.append("Kvasir is not built: make -C %s kvasir "
                        "(needs binutils-dev for bfd.h)" % daikondir)
    if not shutil.which("java"):
        problems.append("java is not on PATH")
    jar = daikon_jar(daikondir).split(os.pathsep)[0]
    if not os.path.exists(jar):
        problems.append("no daikon.jar or java/ under %s" % daikondir)
    return problems



# --- the black-box front-end: the emulation tracer on a stripped binary ------
#
# Nothing below reads source, DWARF or symbols at trace time. The target is
# compiled once with fuzz/runtime/harness_bb.c and stripped, and from then on
# the stripped file is all the loop touches: the tracer finds the functions,
# finds the input buffer by its magic string, reports the values Daikon needs
# AND the edge coverage the fuzzer needs, from one emulation per input.

def build_blackbox(target_c, workdir, cc=None):
    """Path of a stripped (--strip-all) build of the target."""
    cc = cc or os.environ.get("CC", "gcc")
    os.makedirs(workdir, exist_ok=True)
    name = os.path.splitext(os.path.basename(target_c))[0]
    full = os.path.join(workdir, name + ".bb")
    stripped = os.path.join(workdir, name + ".stripped")
    # -Wno-unterminated-string-initialization: the 16-byte magic has no NUL,
    # deliberately; the tracer matches exactly 16 bytes.
    _run([cc, "-O0", "-no-pie", "-fno-stack-protector", "-fwrapv",
          "-Wno-unterminated-string-initialization",
          target_c, os.path.join(RUNTIME, "harness_bb.c"), "-o", full, "-lm"])
    _run(["strip", "--strip-all", "-o", stripped, full])
    return stripped


def run_tracer(binary, inputs, workdir, tier=7, extra_args=(), timeout=1800.0):
    """(decls, {i: [Sample]}, {i: (features, constants)}, [(i, status)],
    start_func).

    One tracer process for the whole batch; each input still runs in a
    fresh emulator. Inputs whose emulation did not finish cleanly are
    reported as crashes: an emulator error, or the instruction limit (the
    emulated equivalent of a hang).
    """
    batch_path = os.path.join(workdir, "bb.batch")
    dt_path = os.path.join(workdir, "bb.dtrace")
    cov_path = os.path.join(workdir, "bb.cov")
    with open(batch_path, "wb") as f:
        f.write(pack_batch(inputs))
    for p in (dt_path, cov_path):
        if os.path.exists(p):
            os.remove(p)
    try:
        _run([sys.executable, TRACER, binary, "-o", dt_path, "--tier", str(tier),
              "--scan-prologues", "--fuzz-batch", batch_path,
              "--fuzz-cov-out", cov_path] + list(extra_args),
             cwd=workdir, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ToolError("tracer timed out on a batch of %d inputs" % len(inputs))
    with open(dt_path, errors="replace") as f:
        text = f.read()
    decls = dtrace.parse_decls(text)
    per_input = dtrace.split_by_input(dtrace.parse_dtrace(text))
    feats, bad, start = {}, [], None
    with open(cov_path) as f:
        for line in f:
            rec = json.loads(line)
            start = rec.get("start_func") or start
            if rec["status"] != "ok":
                bad.append((rec["id"], rec["status"]))
            feats[rec["id"]] = (frozenset(rec["edges"]), rec.get("consts", []))
    if start:
        drop = "..%s()" % start
        per_input = {i: [s for s in ss if dtrace.func_of(s.ppt) != drop]
                     for i, ss in per_input.items()}
        header, blocks = decls
        decls = (header, {p: b for p, b in blocks.items()
                          if dtrace.func_of(p) != drop})
    return decls, per_input, feats, bad, start
