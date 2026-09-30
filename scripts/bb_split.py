#!/usr/bin/env python3
"""BB-granular lift list: split executed code at every branch so every
block exit lands on a block start (direct-linkable; indirect via
missing_block -> driver). Emits blocks.json {va: bytes_hex} + stats.
Usage: bb_split.py <baseline-dir> <out.json>"""
import json
import os
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

CF = {"jmp", "call", "ret"}  # + jcc*


def is_cf(m):
    return m in CF or (m.startswith("j") and m != "jmp" and len(m) > 1)


def main():
    d, out = sys.argv[1], sys.argv[2]
    raw = open(d + "/open_trace.bin", "rb").read()
    trs = struct.unpack("<%dQ" % (len(raw) // 8), raw)
    exe = set(a for a in trs if 0x140000000 <= a < 0x142000000)
    bases = json.load(open(d + "/open_bases.json"))
    imgs = []
    for f in os.listdir(d):
        if f.startswith("open_mem_") and f.endswith(".bin") and f[9:-4] in bases:
            imgs.append((int(bases[f[9:-4]], 16), open(d + "/" + f, "rb").read()))

    def rb(va, n):
        for b, dd in imgs:
            if b <= va < b + len(dd) and va - b + n <= len(dd):
                return dd[va - b:va - b + n]
        return None

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
    # blocks: bytes from start to first CF inclusive (cap 32 insns)
    blocks = {}
    for va in sorted(starts):
        code = rb(va, 256)
        if not code:
            continue
        n = 0
        for ins in md.disasm(code, va):
            n += 1
            if is_cf(ins.mnemonic) or n >= 32:
                end = ins.address + ins.size - va
                blocks[hex(va)] = code[:end].hex()
                break
    print("executed=%d decoded=%d bb_starts=%d blocks=%d"
          % (len(exe), len(dec), len(starts), len(blocks)))
    json.dump(blocks, open(out, "w"))


main()
