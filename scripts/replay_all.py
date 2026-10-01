#!/usr/bin/env python3
"""One-command replay: split -> lift -> gen -> link -> run -> align-check.
Usage: replay_all.py <trace-dir> <binary> <work-dir> [bound]
Env: REMILL_LIFT, LD_LIBRARY_PATH/PATH (LLVM 22), REPLAY_FRAME,
     REPLAY_ARGS, REPLAY_POOL, DATA envs as needed.
Work dir gets: blocks.json, obj/ (lift+.ll/.o + drv/), edge report.
Exit 0 = replay ran to return (missing=0x0) and legs align 100%.
"""
import json
import os
import struct
import subprocess
import sys

REPO = os.environ.get("REPO_ROOT", os.path.expanduser("~/RE/vmp-devirt"))


def sh(cmd, **kw):
    print("+ " + cmd, flush=True)
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                       cwd=kw.get("cwd", REPO), timeout=kw.get("timeout", 3600))
    if r.returncode != 0:
        print(r.stdout[-2000:] if r.stdout else "")
        print(r.stderr[-2000:] if r.stderr else "")
        sys.exit("FAILED: " + cmd)
    return r.stdout + r.stderr


def main():
    tdir, binary, work = sys.argv[1], sys.argv[2], sys.argv[3]
    bound = sys.argv[4] if len(sys.argv) > 4 else "200000"
    os.makedirs(work + "/obj", exist_ok=True)
    print("== split")
    print(sh("python3 scripts/bb_split.py %s %s/blocks.json" % (tdir, work))[-200:])
    print("== lift")
    print(sh("python3 scripts/bb_lift.py %s/blocks.json %s/obj" % (work, work))[-200:])
    print("== gen")
    print(sh("python3 tools/replay/gen_replay.py %s %s/obj" % (binary, work))[-300:])
    drv, rp = work + "/obj/drv", REPO + "/tools/replay"
    sh("g++ -O2 -I%s -c %s/runtime.cpp -o %s/runtime.o" % (drv, rp, drv))
    sh("g++ -O2 -I%s -c %s/plt_calls.cpp -o %s/plt.o" % (drv, drv, drv))
    sh("g++ -O2 -I%s -o %s/replay %s/driver.cpp %s/runtime.o %s/plt.o %s/obj/b_*.o -lz -ldl"
       % (drv, drv, rp, drv, drv, work))
    print("== run")
    out = sh(" ".join([
        "REPLAY_BIN=%s" % binary,
        "REPLAY_TRACE=%s/open_trace.bin" % tdir,
        "REPLAY_FRAME=${REPLAY_FRAME:-0}",
        "REPLAY_ARGS=${REPLAY_ARGS:-}",
        "REPLAY_POOL=${REPLAY_POOL:-0x140002000,0x3000}",
        "%s/replay %s %s %s/open_trace.bin" % (drv, bound, binary, tdir),
    ]), cwd=drv)
    print(out[-800:])
    # align check: replay legs as subsequence of trace
    trs = struct.unpack("<%dQ" % (os.path.getsize(tdir + "/open_trace.bin") // 8),
                        open(tdir + "/open_trace.bin", "rb").read())
    pcs = struct.unpack("<%dQ" % (os.path.getsize(drv + "/replay_pcs.bin") // 8),
                        open(drv + "/replay_pcs.bin", "rb").read())
    i = match = 0
    for p in pcs:
        while i < len(trs) and trs[i] != p:
            i += 1
        if i < len(trs):
            match += 1
            i += 1
        else:
            break
    print("edge alignment: %d/%d" % (match, len(pcs)))
    if match != len(pcs):
        sys.exit("DIVERGED")
    print("REPLAY OK")


main()
