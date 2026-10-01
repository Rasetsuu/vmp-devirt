#!/usr/bin/env python3
"""Decode per-site opcode streams: for each mined fetch site, decode every
visit's raw byte (raw ^ keybyte through the chain) in trace order.
Usage: decode_stream.py <hits-dir> <mine-hits-output.txt>
hits-dir: open_hits.json + open_trace.bin.
Emits per-site visit counts + distinct opcode histograms (the recovered
bytecode stream, per fetch site). chain_verify.py judges consistency;
this shows the program.
"""
import json
import os
import re
import struct
import sys
from collections import Counter, defaultdict

LOW8 = {"al": "rax", "cl": "rcx", "dl": "rdx", "bl": "rbx",
        "spl": "rsp", "bpl": "rbp", "sil": "rsi", "dil": "rdi",
        "r8l": "r8", "r9l": "r9", "r10l": "r10", "r11l": "r11",
        "r12l": "r12", "r13l": "r13", "r14l": "r14", "r15l": "r15"}


def step(op, v, i):
    if op == "Xor":
        return v ^ i
    if op == "Add":
        return (v + i) & 0xFF
    if op == "Sub":
        return (v - i) & 0xFF
    if op == "Rol":
        return ((v << i) | (v >> (8 - i))) & 0xFF if i % 8 else v
    if op == "Ror":
        return ((v >> i) | (v << (8 - i))) & 0xFF if i % 8 else v
    if op == "Inc":
        return (v + 1) & 0xFF
    if op == "Dec":
        return (v - 1) & 0xFF
    if op == "Neg":
        return (-v) & 0xFF
    if op == "Not":
        return (~v) & 0xFF
    return v


def main():
    ddir, mpath = sys.argv[1], sys.argv[2]
    h = json.load(open(ddir + "/open_hits.json"))
    raw = open(ddir + "/open_trace.bin", "rb").read()
    trs = struct.unpack("<%dQ" % (len(raw) // 8), raw)
    chains = {}
    for line in open(mpath):
        if not line.startswith("site "):
            continue
        m = re.match(r"site (\S+) key=(\S+)", line)
        if not m:
            continue
        site, key = m.groups()
        cmds = re.findall(r"op: (\w+).*?value: (\d+)", line)
        chains[site] = (key, cmds)
    pos = defaultdict(list)
    for i, a in enumerate(trs):
        if len(pos) < 600000:
            pos[a].append(i)
    for site, (key, cmds) in chains.items():
        rows = [x for x in h if x["site"] == site]
        occ = pos.get(int(site, 16), [])
        ops = []
        for k, x in enumerate(rows):
            if k >= len(occ) or occ[k] + 1 >= len(trs):
                continue
            rawb = x.get("raw")
            if rawb is None:
                continue
            kv = (x.get(LOW8.get(key, key), 0) or 0) & 0xFF
            v = (rawb ^ kv) & 0xFF
            for op, imm in cmds:
                v = step(op, v, int(imm))
            ops.append(v)
        c = Counter(ops)
        print("%s visits=%d distinct=%d top=%s" %
              (site, len(ops), len(c),
               [(hex(k), v) for k, v in c.most_common(8)]))


main()
