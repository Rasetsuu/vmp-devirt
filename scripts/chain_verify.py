#!/usr/bin/env python3
"""Differential chain verification (Claude's ask: mined => verified).

For each mined fetch site: group watch-hit visits by decoded opcode
(MinedCryptor.decode on live regs), check that equal opcodes predict
equal next-handlers (trace order). Necessary condition of chain
correctness; violations flag wrong chains. No disassembly, no oracles
beyond trace + hits.

Usage: chain_verify.py <hits-dir> <chain.json>
  hits-dir: open_hits.json + open_trace.bin
  chain.json: {site: {key: reg-or-null, steps, cmds:[[op, value]]}}
Writes report to stdout.
"""
import json
import os
import struct
import sys
from collections import defaultdict

OPS = {"Xor": lambda v, i: v ^ i, "Add": lambda v, i: (v + i) & 0xFF,
       "Sub": lambda v, i: (v - i) & 0xFF,
       "Rol": lambda v, i: ((v << (i % 8)) | (v >> (8 - (i % 8)))) & 0xFF if i % 8 else v,
       "Ror": lambda v, i: ((v >> (i % 8)) | (v << (8 - (i % 8)))) & 0xFF if i % 8 else v,
       "Inc": lambda v, i: (v + 1) & 0xFF, "Dec": lambda v, i: (v - 1) & 0xFF,
       "Neg": lambda v, i: (-v) & 0xFF, "Not": lambda v, i: (~v) & 0xFF}

# miner key regs are low8 (dil); hits carry full regs (rdi): compare low byte
LOW8 = {"al": "rax", "cl": "rcx", "dl": "rdx", "bl": "rbx",
        "spl": "rsp", "bpl": "rbp", "sil": "rsi", "dil": "rdi",
        "r8l": "r8", "r9l": "r9", "r10l": "r10", "r11l": "r11",
        "r12l": "r12", "r13l": "r13", "r14l": "r14", "r15l": "r15"}


def main():
    ddir, cpath = sys.argv[1], sys.argv[2]
    chains = json.load(open(cpath))
    h = json.load(open(ddir + "/open_hits.json"))
    raw = open(ddir + "/open_trace.bin", "rb").read()
    trs = struct.unpack("<%dQ" % (len(raw) // 8), raw)
    pos = defaultdict(list)
    for i, a in enumerate(trs):
        if len(pos) < 600000:
            pos[a].append(i)
    seen = defaultdict(int)
    total = ok = 0
    per_site = {}
    for site, ch in chains.items():
        key = ch.get("key") or ""
        if key.endswith("&") or not key:
            continue  # and-mix / keyless: no byte model to verify
        rows = [x for x in h if x.get("site") == site]
        occ = pos.get(int(site, 16), [])
        groups = defaultdict(set)
        n = 0
        for x in rows:
            k = seen[site]
            seen[site] += 1
            if k >= len(occ) or occ[k] + 1 >= len(trs):
                continue
            nx = trs[occ[k] + 1]
            rawb = x.get("raw")
            kv = x.get(LOW8.get(key, key), 0) or 0
            if rawb is None:
                continue
            v = (rawb ^ (kv & 0xFF)) & 0xFF
            for op, imm in ch.get("cmds", []):
                v = OPS[op](v, imm)
            groups[v].add(nx)
            n += 1
        bad = sum(1 for s in groups.values() if len(s) > 1)
        per_site[site] = (n, len(groups), bad)
        total += n
        ok += n - sum(len(s) - 1 for s in groups.values() if len(s) > 1)
    print("visits=%d consistent=%d (%.4f)" % (total, ok, ok / total if total else 0))
    for site, (n, g, bad) in sorted(per_site.items()):
        print("  %s visits=%d opcodes=%d inconsistent=%d" % (site, n, g, bad))


main()
