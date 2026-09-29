#!/usr/bin/env python3
"""Idea 2 v2 driver: sweep single-path jcc sites, force the unobserved
structural alternative once each, union new coverage vs baseline.

- Executed jcc with exactly 1 observed successor (from baseline trace).
- Alternative from disasm (overlay bytes): observed==target -> fallthrough
  (site+len), else -> branch target.
- One force_edge run per site (FORCES=1, BOUND=2M), forced-only addrs counted.
- Ranks hot sites first; top-N via argv.

Usage: force_sweep.py <baseline-dir> <binary> <out-dir> [top-n]
Baseline dir holds open_trace.bin + open_bases.json + open_mem_*.bin.
"""
import json
import os
import struct
import subprocess
import sys
from collections import Counter, defaultdict
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

FORCE_EDGE = "/home/ciupix/vmp_devirt_prod/target/release/force_edge"
START = os.environ.get("START", "0x14077c26d")


def load_overlay(d):
    bases = json.load(open(d + "/open_bases.json"))
    secs = []
    for f in os.listdir(d):
        if f.startswith("open_mem_") and f.endswith(".bin"):
            tag = f[9:-4]
            if tag in bases:
                secs.append((int(bases[tag], 16),
                             open(d + "/" + f, "rb").read()))
    secs.sort()
    return secs


def read(secs, va, n):
    for b, data in secs:
        if b <= va < b + len(data) and va - b + n <= len(data):
            return data[va - b:va - b + n]
    return None


def main():
    bdir, binary, outdir = sys.argv[1], sys.argv[2], sys.argv[3]
    topn = int(sys.argv[4]) if len(sys.argv) > 4 else 30
    os.makedirs(outdir, exist_ok=True)
    raw = open(bdir + "/open_trace.bin", "rb").read()
    trs = struct.unpack("<%dQ" % (len(raw) // 8), raw)
    base = set(a for a in trs if 0x140000000 <= a < 0x142000000)
    succ = defaultdict(set)
    cnt = Counter()
    for a, b in zip(trs, trs[1:]):
        succ[a].add(b)
        cnt[a] += 1
    secs = load_overlay(bdir)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    cands = []
    for va, ss in succ.items():
        if len(ss) != 1:
            continue
        code = read(secs, va, 15)
        if not code:
            continue
        ins = list(md.disasm(code, va, count=1))
        if not ins:
            continue
        ins = ins[0]
        if not ins.mnemonic.startswith("j") or ins.mnemonic == "jmp":
            continue
        try:
            tgt = int(ins.op_str.strip().split(",")[0], 16)
        except Exception:
            continue
        obs = next(iter(ss))
        alt = va + ins.size if obs == tgt else tgt
        if alt in ss:
            continue
        cands.append((cnt[va], va, ins.mnemonic, obs, alt))
    cands.sort(reverse=True)
    print("single-path jcc with structural alt: %d (top %d)" % (len(cands), topn))
    new_total = set()
    for i, (c, va, mn, obs, alt) in enumerate(cands[:topn]):
        dd = "%s/site_%02d_%x" % (outdir, i, va)
        os.makedirs(dd, exist_ok=True)
        env = dict(os.environ, BIN_PATH=binary, DATA_DIR=dd,
                   BOUND="2000000", FORCES="1")
        try:
            r = subprocess.run(
                [FORCE_EDGE, START, hex(va), hex(alt)],
                env=env, capture_output=True, text=True, timeout=300)
            line = [l for l in r.stdout.splitlines() if l.startswith("forced ")]
            print("[%d] %s %s obs=%s alt=%s %s"
                  % (i, hex(va), mn, hex(obs), hex(alt),
                     line[0] if line else "NO-RUN"))
        except subprocess.TimeoutExpired:
            print("[%d] %s TIMEOUT" % (i, hex(va)))
            continue
        try:
            fraw = open(dd + "/open_trace_forced.bin", "rb").read()
            ftrs = struct.unpack("<%dQ" % (len(fraw) // 8), fraw)
            fset = set(a for a in ftrs if 0x140000000 <= a < 0x142000000)
            new = fset - base
            new_total |= new
            print("    forced-only=%d cum=%d" % (len(new), len(new_total)))
        except Exception as e:
            print("    no trace: %s" % e)
    print("TOTAL new addrs: %d" % len(new_total))
    json.dump(sorted(new_total), open(outdir + "/new_addrs.json", "w"))


main()
