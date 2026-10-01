#!/usr/bin/env python3
"""BB-granular lift list: split executed code at every branch so every
block exit lands on a block start (direct-linkable; indirect via
missing_block -> driver). Emits blocks.json {va: bytes_hex} + stats.
Usage: bb_split.py <baseline-dir> <out.json>"""
import json
import os
import struct
import sys
from collections import Counter, defaultdict
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

CF = {"jmp", "call", "ret"}  # + jcc*


def is_cf(m):
    return m in CF or (m.startswith("j") and m != "jmp" and len(m) > 1)


def main():
    d, out = sys.argv[1], sys.argv[2]
    raw = open(d + "/open_trace.bin", "rb").read()
    trs = struct.unpack("<%dQ" % (len(raw) // 8), raw)
    bases = json.load(open(d + "/open_bases.json"))
    # executable range from section manifest (PE 0x140… or ELF 0x40…,
    # never hardcoded): code = sections whose bytes disassemble, i.e.
    # any mapped base range except known data (stack/heap/staged).
    ranges = []
    for _tag, vs in bases.items():
        v = int(vs, 16)
        if 0x100000 <= v < 0x1000000000:
            ranges.append(v)
    ranges.sort()
    lo, hi = (min(ranges), max(ranges) + 0x1000000) if ranges else (0x140000000, 0x142000000)
    exe = set(a for a in trs if lo <= a < hi)
    imgs = []
    for f in os.listdir(d):
        if f.startswith("open_mem_") and f.endswith(".bin") and f[9:-4] in bases:
            imgs.append((int(bases[f[9:-4]], 16), open(d + "/" + f, "rb").read()))

    def rb(va, n):
        # span-aware + best-effort: concatenate across adjacent snapshots,
        # return what exists (blocks only need bytes to their first CF;
        # all callers tolerate short/empty). Empty only if VA unmapped.
        out = b""
        while len(out) < n:
            for b, dd in imgs:
                if b <= va < b + len(dd):
                    take = min(n - len(out), len(dd) - (va - b))
                    out += dd[va - b:va - b + take]
                    va += take
                    break
            else:
                break
        return out if out else None

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    starts = {trs[0]}
    # decode every executed addr once (cache)
    dec = {}
    for va in exe:
        code = rb(va, 15)
        if not code:
            continue
        ins = list(md.disasm(code, va, count=1))
        if ins:
            dec[va] = ins[0]
    for va, ins in dec.items():
        if not is_cf(ins.mnemonic):
            continue
        # fall-through + direct target are BB starts
        ft = va + ins.size
        if ft in exe:
            starts.add(ft)
        if ins.mnemonic in ("jmp", "call") or ins.mnemonic.startswith("j"):
            try:
                tgt = int(ins.op_str.strip().split(",")[0], 16)
                if tgt in exe:
                    starts.add(tgt)
            except Exception:
                pass
    # blocks: bytes from start to first CF inclusive (cap 32 insns);
    # worklist: cap-cut continuations (if executed) become new starts.
    # Plus: every observed successor of an indirect jump becomes a start
    # (replay lands on them via trampolines; static fallthrough logic
    # cannot see them). Single pass over trace edges.
    # Plus: non-fallthrough observed successors of ANY executed CF
    # (ret/ret-imm/call-reg/jcc-taken land off-corpus statically).
    observed_succ = defaultdict(set)
    for a, b in zip(trs, trs[1:]):
        if b in exe:
            observed_succ[a].add(b)
    for va, ss in observed_succ.items():
        code = rb(va, 15)
        if not code:
            continue
        ins = list(md.disasm(code, va, count=1))
        if not ins:
            continue
        ins = ins[0]
        if not is_cf(ins.mnemonic):
            continue
        ft = va + ins.size
        for b in ss:
            if b != ft:
                starts.add(b)
    ind_cache = {}

    def is_indjmp(va):
        if va in ind_cache:
            return ind_cache[va]
        code = rb(va, 6)
        r = False
        if code:
            ins = list(md.disasm(code, va, count=1))
            if ins:
                ins = ins[0]
                r = (ins.mnemonic == "jmp" and "[" not in ins.op_str
                     and "0x" not in ins.op_str)
        ind_cache[va] = r
        return r

    for a, b in zip(trs, trs[1:]):
        if b in exe and is_indjmp(a):
            starts.add(b)
    blocks = {}
    work = sorted(starts)
    seen = set(work)
    while work:
        va = work.pop(0)
        code = rb(va, 512)
        if not code:
            continue
        n = 0
        done = False
        for ins in md.disasm(code, va):
            n += 1
            if is_cf(ins.mnemonic) or n >= 32:
                end = ins.address + ins.size - va
                blocks[hex(va)] = code[:end].hex()
                if n >= 32 and not is_cf(ins.mnemonic):
                    cont = ins.address + ins.size
                    if cont in exe and cont not in seen:
                        seen.add(cont)
                        work.append(cont)
                done = True
                break
        if not done:
            continue
    starts = seen
    print("executed=%d decoded=%d bb_starts=%d blocks=%d"
          % (len(exe), len(dec), len(starts), len(blocks)))
    json.dump(blocks, open(out, "w"))


main()
