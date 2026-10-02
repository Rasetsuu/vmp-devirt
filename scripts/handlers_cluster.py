#!/usr/bin/env python3
"""Batch handler semantics: lift handler entries with Triton, alpha-rename
refs by appearance order, cluster identical shapes -> empirical opcode map.
Usage: handlers_cluster.py <vas.txt> [max_ins]   (one hex VA per line)
Env: DATA_DIR (snapshot dir with open_bases.json + open_mem_*.bin).
Output: clusters (count, exemplar VA, shape hash, sample ASTs).
"""
import json
import os
import re
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from triton_handlers import lift_block

VAS = sys.argv[1]
MAXN = int(sys.argv[2]) if len(sys.argv) > 2 else 400


def canon(ast):
    # alpha-rename ref_N / SymVar_N by order of first appearance,
    # then abstract concrete constants (per-build immediates differ;
    order = {}
    idx = [0]

    def rep(m):
        k = m.group(0)
        if k not in order:
            order[k] = "in%d" % idx[0]
            idx[0] += 1
        return order[k]

    s = re.sub(r"(ref_\d+|SymVar_\d+)", rep, ast)
    # abstract hex literals (keep 0x0/0x1: identity elements shape semantics)
    def hexrep(m):
        v = m.group(0)
        if v in ("0x0", "0x1"):
            return v
        return "#C"
    return re.sub(r"0x[0-9a-fA-F]+", hexrep, s)


def main():
    vas = [l.strip() for l in open(VAS) if l.strip()][:MAXN]
    clusters = defaultdict(list)
    shapes = {}
    for i, vs in enumerate(vas):
        try:
            r = lift_block(int(vs, 16))
        except Exception as e:
            print("ERR %s %s" % (vs, str(e)[:60]), flush=True)
            continue
        if not r:
            clusters["<empty>"].append(vs)
            continue
        shape = tuple(sorted((k, canon(v)) for k, v in r.items()))
        h = str(hash(shape) & 0xFFFFFFFF)
        shapes[h] = shape
        clusters[h].append(vs)
        if (i + 1) % 20 == 0:
            print("... %d/%d clusters=%d" % (i + 1, len(vas), len(clusters)), flush=True)
    print("vas=%d clusters=%d" % (len(vas), len(clusters)))
    for h, members in sorted(clusters.items(), key=lambda kv: -len(kv[1]))[:25]:
        print("== cluster %s n=%d ex=%s" % (h, len(members), members[0]))
        if h != "<empty>":
            for k, v in shapes[h][:6]:
                print("   %s = %s" % (k, v[:150]))


main()
