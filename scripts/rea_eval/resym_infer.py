"""Run ReSym's VarDecoder locally (CPU, no API tokens) on ReSym's own test prompts.

Mirrors the authors' training_src/vardecoder_inf.py (github.com/lt-asset/resym):
    prompt  = line['input'] + first_token + ':'    (first_token = the first
              variable's placeholder name, e.g. "a1" - the model completes
              "a1: <name>, <type>" lines for every variable asked about)
    input   truncated to 8192 - 1024 tokens
    decode  beam search, num_beams=4, greedy, eos = pad = 0
Differences, stated: runs on CPU; max_new_tokens is capped by the number of
variables asked (40 tokens each) instead of a flat 1024, which only cuts
generation the authors' run would have stopped anyway at EOS - a capped,
truncated answer is flagged `capped` in the output.

Model: the official checkpoint (Zenodo record 13923982, vardecoder.zip).
Tokenizer: bigcode/tiny_starcoder_py, byte-identical tokenizer files to the
gated bigcode/starcoderbase-3b the authors load (same git blob hashes).

Usage:
    python3 scripts/rea_eval/resym_infer.py TEST.jsonl OUT.jsonl MODEL_DIR TOKENIZER_DIR \
        [--n 200] [--seed 0] [--beams 4]
Resumable: entries already in OUT.jsonl are skipped.
"""
import argparse
import json
import os
import random
import re
import time

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer


def asked_vars(inp):
    m = re.search(r"variables (.*?)\?\n", inp)
    return re.findall(r"`([^`]+)`", m.group(1)) if m else []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("test")
    ap.add_argument("out")
    ap.add_argument("model")
    ap.add_argument("tokenizer")
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--beams", type=int, default=4)
    ap.add_argument("--dtype", default="bfloat16", choices=["bfloat16", "float32"])
    a = ap.parse_args()

    lines = open(a.test).read().splitlines()
    idx = sorted(random.Random(a.seed).sample(range(len(lines)), min(a.n, len(lines))))
    done = set()
    if os.path.exists(a.out):
        done = {json.loads(l)["idx"] for l in open(a.out) if l.strip()}

    tok = AutoTokenizer.from_pretrained(a.tokenizer)
    model = AutoModelForCausalLM.from_pretrained(a.model, torch_dtype=getattr(torch, a.dtype))
    model.eval()
    torch.set_num_threads(os.cpu_count() or 4)

    with open(a.out, "a") as wp, torch.inference_mode():
        for k, i in enumerate(idx):
            if i in done:
                continue
            line = json.loads(lines[i])
            first = line["output"].split(":")[0]
            prompt = line["input"] + first + ":"
            ids = tok.encode(prompt, return_tensors="pt")[:, : 8192 - 1024]
            n_vars = max(len(asked_vars(line["input"])), 1)
            cap = 40 * n_vars + 16
            t0 = time.time()
            out = model.generate(input_ids=ids, attention_mask=torch.ones_like(ids),
                                 max_new_tokens=cap, num_beams=a.beams,
                                 num_return_sequences=1, do_sample=False,
                                 early_stopping=False, pad_token_id=0, eos_token_id=0)[0]
            gen = out[ids.size(1):]
            text = first + ":" + tok.decode(gen, skip_special_tokens=True,
                                            clean_up_tokenization_spaces=True)
            rec = {"idx": i, "bin": line.get("bin"), "proj": line.get("proj"),
                   "funname": line.get("funname"), "output": line["output"],
                   "predict": text, "input_tokens": int(ids.size(1)),
                   "capped": bool(len(gen) >= cap and int(gen[-1]) != 0),
                   "seconds": round(time.time() - t0, 1)}
            wp.write(json.dumps(rec) + "\n")
            wp.flush()
            print(f"[{k + 1}/{len(idx)}] #{i} {rec['input_tokens']} tok, "
                  f"{n_vars} vars, {rec['seconds']}s", flush=True)


if __name__ == "__main__":
    main()
