#!/usr/bin/env python3
"""Tier-2 golden check: static pipeline numbers vs tests/golden.json.

Local-only (needs samples). Missing paths skip with warning, never fail.
Usage: REPO_ROOT=. VMP_WORK=... VMP_DATA=... TIG_WORK=... python3 scripts/check_golden.py
Exit 0 = all present checks pass; 1 = regression.
"""
import json
import os
import re
import subprocess
import sys

REPO = os.environ.get("REPO_ROOT", ".")
HOME = os.path.expanduser("~")
VMP_WORK = os.environ.get("VMP_WORK", HOME + "/RE/vmp-research/samples/vmp_factory/work")
VMP_DATA = os.environ.get("VMP_DATA", HOME + "/RE/vmp-research/data")
TIG_WORK = os.environ.get("TIG_WORK", HOME + "/RE/tigress/work")
DEVIRT = os.environ.get("DEVIRT", REPO + "/target/debug/devirt")

G = json.load(open(REPO + "/tests/golden.json"))
fails, skips = [], []


def run(args, timeout=600):
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    return r.stdout + r.stderr


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (" " + detail if detail else ""))
    if not cond:
        fails.append(name)


def maybe(path):
    if not os.path.exists(path):
        print("SKIP missing " + path)
        skips.append(path)
        return False
    return True


# --- vmp_add2 scan+mine+synth ---
b = VMP_WORK + "/vmp_add2.exe"
if maybe(b) and maybe(DEVIRT):
    out = run([DEVIRT, "scan", b])
    n = sum(1 for l in out.splitlines() if "handler candidate" in l)
    check("add2.scan", n >= G["vmp_add2"]["scan_min_sites"], "sites=%d" % n)
    vas = [l.split()[2] for l in out.splitlines() if "handler candidate" in l][:G["vmp_add2"]["mine_sample"]]
    ok = 0
    for va in vas:
        if run([DEVIRT, "mine", b, va]).strip().splitlines():
            ok += 1
    check("add2.mine", ok >= G["vmp_add2"]["mine_min"], "mined=%d/40" % ok)

# --- diversity (scan+mine only; synth needs chains regen, covered by add2 path) ---
for tag in ["repro", "divA", "divB"]:
    exp = G["vmp_diversity"][tag]
    p = "/tmp/opencode/diversity/%s.exe" % tag
    if not maybe(p):
        continue
    out = run([DEVIRT, "scan", p])
    n = sum(1 for l in out.splitlines() if "handler candidate" in l)
    # capped display (500): >= for capped, == below cap (forces deliberate updates)
    ok = (n >= exp["scan"]) if exp["scan"] >= 500 else (n == exp["scan"])
    check(tag + ".scan", ok, "sites=%d want=%s%d" % (n, ">=" if exp["scan"] >= 500 else "", exp["scan"]))

# --- dispatch (needs banked traces) ---
def dispatch_multi(trace, binary):
    out = run([DEVIRT, "dispatch", trace, binary], timeout=900)
    m = re.search(r"multi-target dispatchers \(total\): (\d+) \(indirect (\d+), branch (\d+)\)", out)
    if not m:
        m2 = re.search(r"multi-target dispatchers \(total\): (\d+)", out)
        return (int(m2.group(1)), -1, -1) if m2 else None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


gd = G["vmp_dispatch_gadd"]
tp, bp = VMP_DATA + "/gadd/open_trace.bin", VMP_WORK + "/vmp_add2.exe"
if maybe(tp) and maybe(bp):
    r = dispatch_multi(tp, bp)
    check("gadd.dispatch", r == (109, 101, 8) or (r and r[0] == 109),
          "got=%s want=(109,101,8)" % (r,))

for mode in ["switch", "direct", "indirect", "call"]:
    exp = G["tigress"][mode]
    tp = VMP_DATA + "/tig_%s/open_trace.bin" % mode
    bp = TIG_WORK + "/tig_%s" % mode
    if not (maybe(tp) and maybe(bp)):
        continue
    r = dispatch_multi(tp, bp)
    ok = r and r[1] == exp["multi_indirect"] and r[2] == exp["multi_branch"]
    check("tig_%s.dispatch" % mode, bool(ok), "got=%s want=(%d,%d)" % (r, exp["multi_indirect"], exp["multi_branch"]))

# --- tigress fetch hits ---
hp = VMP_DATA + "/tig_switch/open_hits.json"
if maybe(hp):
    h = json.load(open(hp))
    check("tig_switch.hits", len(h) == G["tigress"]["switch"]["fetch_hits"], "hits=%d" % len(h))

print("fails=%d skips=%d" % (len(fails), len(skips)))
sys.exit(1 if fails else 0)
