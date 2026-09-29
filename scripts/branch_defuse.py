#!/usr/bin/env python3
"""Def-use over branch-watch hits: for each site, show reg deltas across
visits + taken/not-taken outcome (from trace order). Identifies the
condition registers driving each virtual branch."""
import json
import os
import struct
from collections import defaultdict

D = os.environ.get("DATA_DIR", "/home/ciupix/RE/vmp-research/data/gadd_br")
REGS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "rbp"]

h = json.load(open(D + "/open_hits.json"))
trs = struct.unpack("<%dQ" % (os.path.getsize(D + "/open_trace.bin") // 8),
                    open(D + "/open_trace.bin", "rb").read())
print("hits:", len(h))

# outcome per hit: next trace addr after this hit's position.
# hits are chronological; walk trace with pointer.
pos = defaultdict(list)
for i, a in enumerate(trs):
    if len(pos) < 300000:
        pos[a].append(i)
used = defaultdict(int)
for n, x in enumerate(h):
    site = int(x["site"], 16)
    occ = pos.get(site, [])
    k = sum(1 for m in h[:n] if m["site"] == x["site"])
    if k < len(occ) and occ[k] + 1 < len(trs):
        x["_next"] = trs[occ[k] + 1]
    else:
        x["_next"] = None

by_site = defaultdict(list)
for x in h:
    by_site[x["site"]].append(x)

for site, rows in sorted(by_site.items(), key=lambda kv: -len(kv[1]))[:8]:
    print("== %s x%d ==" % (site, len(rows)))
    # which regs vary across visits?
    vary = []
    for r in REGS:
        vals = set(x.get(r, 0) or 0 for x in rows)
        if len(vals) > 1:
            vary.append((r, len(vals)))
    print("  varying:", vary[:6])
    # outcome distribution
    outs = {}
    for x in rows:
        nx = x.get("_next")
        outs[nx] = outs.get(nx, 0) + 1
    print("  outcomes:", {hex(k) if k else None: v for k, v in list(outs.items())[:4]})
