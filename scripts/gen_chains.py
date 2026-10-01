#!/usr/bin/env python3
"""Mine N scan sites and save chains JSON for chain_verify.py.
Usage: gen_chains.py <binary> <out.json> [n]"""
import json
import re
import subprocess
import sys

BIN, OUT = sys.argv[1], sys.argv[2]
N = int(sys.argv[3]) if len(sys.argv) > 3 else 40
DEVIRT = os.environ.get("DEVIRT", "./target/debug/devirt")

scan = subprocess.run([DEVIRT, "scan", BIN], capture_output=True, text=True, timeout=300)
vas = re.findall(r"handler candidate (0x[0-9a-f]+)", scan.stdout)[:N]
chains = {}
for va in vas:
    r = subprocess.run([DEVIRT, "mine", BIN, va], capture_output=True, text=True, timeout=120)
    m = re.match(r"site (0x[0-9a-f]+) key=(\S*) aux=(\S+|None) steps=(\d+) \[(.*)\]", r.stdout.strip())
    if not m:
        continue
    cmds = re.findall(r"op: (\w+), size: \w+, value: (\d+)", m.group(5))
    chains[m.group(1)] = {"key": m.group(2), "aux": None if m.group(3) == "None" else m.group(3),
                          "steps": int(m.group(4)),
                          "cmds": [(op, int(v)) for op, v in cmds]}
json.dump(chains, open(OUT, "w"), indent=1)
print("mined %d/%d -> %s" % (len(chains), len(vas), OUT))
