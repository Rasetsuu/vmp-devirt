#!/usr/bin/env python3
"""One-command coverage loop (roadmap 2.2): sweep -> mine -> merge.

Runs force_sweep, mines promo fetch sites, merges baseline + largest
forced traces for divergence points, and writes report.json. Optional
learn stage (needs a branch-watch hits corpus): runs learn_dispatch
and attaches flip-region rules used to prioritize (v1: reported
alongside; sweep order stays heat-based).

Usage: loop_run.py <baseline-dir> <binary> <out-dir> [top-n] [offset] [learn-hits-dir]
"""
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEVIRT = "/home/ciupix/RE/vmp-devirt/target/debug/devirt"


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=kw.pop("timeout", 1800), **kw)


def main():
    bdir, binary, outdir = sys.argv[1], sys.argv[2], sys.argv[3]
    topn = sys.argv[4] if len(sys.argv) > 4 else "100"
    off = sys.argv[5] if len(sys.argv) > 5 else "0"
    learn = sys.argv[6] if len(sys.argv) > 6 else ""
    os.makedirs(outdir, exist_ok=True)
    report = {"baseline": bdir, "binary": binary, "topn": topn, "offset": off}

    # 0. learn (optional corpus) — flip regions reported, not yet ordering
    if learn:
        r = run([sys.executable, HERE + "/learn_dispatch.py", learn, "3"],
                timeout=900)
        report["learn_tail"] = r.stdout[-2000:] if r.stdout else ""
        print("learn done")

    # 1. sweep
    r = run([sys.executable, HERE + "/force_sweep.py", bdir, binary, outdir, topn, off],
            timeout=7200)
    print(r.stdout[-1500:] if r.stdout else "sweep silent")
    new_addrs = []
    try:
        new_addrs = json.load(open(outdir + "/new_addrs.json"))
    except Exception as e:
        print("no new_addrs:", e)
    report["new_addrs"] = len(new_addrs)

    # 2. mine promo fetch
    try:
        promo = json.load(open(outdir + "/promo_fetch.json"))
    except Exception:
        promo = []
    mined = []
    for va in promo:
        m = run([DEVIRT, "mine", binary, hex(va)], timeout=120)
        mm = re.match(r"site (0x[0-9a-f]+) key=(\S*) steps=(\d+) \[(.*)\]", (m.stdout or "").strip())
        if mm:
            mined.append(mm.group(1))
    report["promo"] = len(promo)
    report["promo_mined"] = len(mined)

    # 3. merge baseline + largest forced traces (bounded: 25 files)
    import struct
    cands = []
    for d in sorted(os.listdir(outdir)):
        p = os.path.join(outdir, d, "open_trace_forced.bin")
        if os.path.exists(p):
            try:
                cands.append((os.path.getsize(p), p))
            except Exception:
                pass
    cands.sort(reverse=True)
    tfiles = [bdir + "/open_trace.bin"] + [p for _, p in cands[:24]]
    existing = [p for p in tfiles if os.path.exists(p)]
    if len(existing) >= 2:
        m = run([DEVIRT, "merge"] + existing, timeout=1200)
        report["merge"] = (m.stdout or "")[:1500]
        print((m.stdout or "").splitlines()[:4])
    else:
        report["merge"] = "skipped (<2 traces)"

    json.dump(report, open(outdir + "/report.json", "w"), indent=1)
    print("REPORT new=%d promo=%d/%d" % (report["new_addrs"], report["promo_mined"], report["promo"]))


main()
