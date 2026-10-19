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
import os
import shutil
import signal
import subprocess

from . import dtrace
from .mutate import pack_batch

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RUNTIME = os.path.join(REPO, "fuzz", "runtime")

# Kept in step with the corpus Makefile so a target traces like tests/*.exe.
# -fwrapv makes signed overflow wrap instead of being undefined, so the
# overflow the fuzzer finds is the overflow Kvasir records.
KV_CFLAGS = ["-O0", "-g", "-gdwarf-3", "-no-pie", "-fno-stack-protector", "-fwrapv"]
COV_CFLAGS = ["-O0", "-g", "-fwrapv"]


class ToolError(RuntimeError):
    pass


def _run(cmd, **kw):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)
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
    _run([cc] + KV_CFLAGS + [target_c, harness, "-o", kv])

    objs = []
    for src, flags in ((target_c, ["-fsanitize-coverage=trace-pc,trace-cmp"]),
                       (harness, ["-DFUZZ_COV"]),
                       (cov_rt, [])):
        obj = os.path.join(workdir, os.path.basename(src) + ".cov.o")
        _run([cc] + COV_CFLAGS + flags + ["-c", src, "-o", obj])
        objs.append(obj)
    cov = os.path.join(workdir, name + ".cov")
    _run([cc] + objs + ["-o", cov])
    return cov, kv


# --- native coverage runs ---------------------------------------------------

def _parse_cov(path):
    started, feats, consts = [], {}, {}
    if not os.path.exists(path):
        return started, feats, consts
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
    return started, feats, consts


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
            p = subprocess.run([cov_exe, batch_path, out_path], stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE, timeout=timeout)
            if p.returncode != 0:
                reason = _describe_exit(p.returncode)
        except subprocess.TimeoutExpired:
            reason = "timeout"
        started, feats, consts = _parse_cov(out_path)
        for local, fs in feats.items():
            results[pending[local]] = (fs, consts.get(local, []))
        if reason is None:
            break
        # The last record that started but never reported is the culprit.
        unfinished = [s for s in started if s not in feats]
        if not unfinished:
            raise ToolError("coverage run failed (%s) outside any input" % reason)
        bad = unfinished[-1]
        crashes.append((pending[bad], reason))
        pending = pending[bad + 1:]
    return results, crashes


def _describe_exit(rc):
    if rc < 0:
        try:
            return signal.Signals(-rc).name
        except ValueError:
            return "signal %d" % -rc
    return "exit %d" % rc


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


def run_kvasir(kv_exe, inputs, workdir, daikondir, ppt_list=None, timeout=600.0):
    """(decls, {i: [Sample]}) for a batch of inputs that run cleanly natively.

    decls is (header, {ppt: block}); samples are already split per input and
    stripped of harness program points.
    """
    batch_path = os.path.join(workdir, "kv.batch")
    dt_path = os.path.join(workdir, "kv.dtrace")
    dc_path = os.path.join(workdir, "kv.decls")
    with open(batch_path, "wb") as f:
        f.write(pack_batch(inputs))
    for p in (dt_path, dc_path):
        if os.path.exists(p):
            os.remove(p)
    try:
        select = ["--ppt-list-file=" + ppt_list] if ppt_list else []
        _run([kvasir_path(daikondir), "--dtrace-file=" + dt_path,
              "--decls-file=" + dc_path] + select + [kv_exe, batch_path],
             cwd=workdir, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ToolError("Kvasir timed out on a batch of %d inputs" % len(inputs))
    with open(dc_path, errors="replace") as f:
        decls = dtrace.parse_decls(f.read())
    with open(dt_path, errors="replace") as f:
        samples = dtrace.parse_dtrace(f.read())
    per_input = dtrace.split_by_input(samples)
    kept = {i: [s for s in ss if dtrace.keep_ppt(s.ppt)] for i, ss in per_input.items()}
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


def check_tools(daikondir):
    """[problem] - empty when everything the loop needs is present."""
    problems = []
    if not daikondir:
        return ["DAIKONDIR is not set (or pass --daikon)."]
    if not os.path.isdir(daikondir):
        return ["DAIKONDIR does not exist: %s" % daikondir]
    if not os.path.exists(os.path.join(daikondir, "fjalar", "valgrind", "inst", "bin", "valgrind")):
        problems.append("Kvasir is not built: make -C %s kvasir "
                        "(needs binutils-dev for bfd.h)" % daikondir)
    if not shutil.which("java"):
        problems.append("java is not on PATH")
    jar = daikon_jar(daikondir).split(os.pathsep)[0]
    if not os.path.exists(jar):
        problems.append("no daikon.jar or java/ under %s" % daikondir)
    return problems

