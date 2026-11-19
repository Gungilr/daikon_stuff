"""Running the tracer (in-process, resident) and Daikon for the fuzz loop."""
import contextlib
import io
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
from tracer import cli  # noqa: E402

TRACER_FLAGS = ["--start-func", "main", "--tier", "10", "--model-libc"]


def trace_one(binary, argv, workdir, tag="cur"):
    """Trace one input. Returns (edges: set, dtrace path, exit code or None)."""
    dt = os.path.join(workdir, f"{tag}.dtrace")
    cov = os.path.join(workdir, f"{tag}.cov")
    args = [binary, "-o", dt, *TRACER_FLAGS, "--coverage-out", cov, "--quiet"]
    for a in argv:
        args += ["--program-arg", str(a)]
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        cli.main(args)
    d = json.load(open(cov))
    return {tuple(e) for e in d["edges"]}, dt, d.get("exit")


def trace_batch(binary, inputs, workdir, tag="batch"):
    """Trace many inputs into ONE dtrace (one schema). Returns its path."""
    lst = os.path.join(workdir, f"{tag}.jsonl")
    with open(lst, "w") as fh:
        for a in inputs:
            fh.write(json.dumps([str(x) for x in a]) + "\n")
    dt = os.path.join(workdir, f"{tag}.dtrace")
    args = [binary, "-o", dt, *TRACER_FLAGS, "--program-args-file", lst, "--quiet"]
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        cli.main(args)
    return dt


def daikon(dtrace, out_prefix, daikon_dir=os.path.join(ROOT, "daikon"), spinfo=None):
    """Run Daikon on one dtrace (optionally with splitting conditions).
    Returns the text report path."""
    cp = f"{daikon_dir}/java:{daikon_dir}/java/lib/*"
    txt = out_prefix + ".txt"
    cmd = ["java", "-cp", cp, "daikon.Daikon", "-o", out_prefix + ".inv.gz"]
    if spinfo:
        conf = out_prefix + ".conf"
        with open(conf, "w") as fh:
            # each condition only at the program point it was derived from
            fh.write("daikon.split.SplitterList.all_splitters = false\n")
        cmd += ["--config", conf]
    cmd.append(dtrace)
    if spinfo:
        cmd.append(spinfo)
    with open(txt, "w") as fh:
        subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT, check=False)
    return txt
