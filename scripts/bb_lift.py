#!/usr/bin/env python3
"""Bulk-lift BBs to objects: remill-lift -> opt -O3 -> llc -> ld -r.
Resumable (skips existing .o). Usage: bb_lift.py <bb.json> <outdir>"""
import json
import os
import subprocess
import sys

LIFT = os.environ.get("REMILL_LIFT", "remill-lift-22")  # PATH lookup; override via REMILL_LIFT


def main():
    blocks = json.load(open(sys.argv[1]))
    out = sys.argv[2]
    os.makedirs(out, exist_ok=True)
    items = sorted(blocks.items(), key=lambda kv: int(kv[0], 16))
    ok = skip = fail = 0
    for i, (vas, hx) in enumerate(items):
        va = int(vas, 16)
        tag = "%08x" % va
        obj = "%s/b_%s.o" % (out, tag)
        if os.path.exists(obj):
            skip += 1
            continue
        ll = "%s/b_%s.ll" % (out, tag)
        try:
            r = subprocess.run(
                [LIFT, "--arch", "amd64", "--os", "linux",
                 "--bytes", hx, "--address", vas, "--ir_out", ll],
                capture_output=True, timeout=120)
            if r.returncode != 0:
                print("  lift fail %s: %s" % (vas, r.stderr.decode()[:120]))
                fail += 1
                continue
            body = open(ll).read()
            # Error *calls* that share the function with normal returns
            # are faithful fault paths (e.g. div-by-zero guards) — keep.
            # Fail only when the block cannot return normally at all.
            if "call ptr @__remill_error" in body and "ret ptr" not in body:
                print("  lift no-return %s" % vas)
                fail += 1
                continue
            subprocess.run(["opt", "-O3", "-S", ll, "-o", ll + ".bc"],
                           capture_output=True, timeout=120, check=True)
            subprocess.run(["llc", "-filetype=obj", "-relocation-model=pic",
                            ll + ".bc", "-o", obj],
                           capture_output=True, timeout=120, check=True)
            ok += 1
        except Exception:
            fail += 1
        if (i + 1) % 500 == 0:
            print("  %d/%d ok=%d skip=%d fail=%d" % (i + 1, len(items), ok, skip, fail), flush=True)
    print("LIFTED ok=%d skip=%d fail=%d / %d" % (ok, skip, fail, len(items)))


main()
