#!/usr/bin/env python3
"""Idea 3 v1: learn dispatcher conditions from the branch-watch corpus.

For each divergent site (one trace successor varies across visits),
fit a shallow decision tree on live register values -> outcome.
Output is interpretable (prints rsi > rbp-style rules) and generative
(the rule's flip region feeds idea 2 forcing). Generalizes
branch_solve.py (hand flag-writer search) to learned rules.

Usage: learn_dispatch.py [data-dir] [max-depth] [out.json]
Corpus: <dir>/open_hits.json + <dir>/open_trace.bin (gadd_br).
With out.json: writes {site: {rule, acc, base}} for learned sites.
"""
import json
import os
import struct
import sys
from collections import defaultdict
from sklearn.tree import DecisionTreeClassifier, export_text

REGS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10",
        "r11", "rbp", "rsp"]


def load_dir(d):
    h = json.load(open(d + "/open_hits.json"))
    raw = open(d + "/open_trace.bin", "rb").read()
    return h, struct.unpack("<%dQ" % (len(raw) // 8), raw)


def main():
    # multi-dir merge (colon-separated): cross-run corpora for path-exclusive
    # branches (each run sees one outcome; merged, both appear). Single dir
    # behaves as before.
    ds = (sys.argv[1] if len(sys.argv) > 1 else
          os.environ.get("DATA_DIR", "./data/gadd_br")).split(":")
    depth = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    by_site = defaultdict(list)
    for d in ds:
        h, trs = load_dir(d)
        pos = defaultdict(list)
        for i, a in enumerate(trs):
            if len(pos) < 600000:
                pos[a].append(i)
        per = defaultdict(list)
        for x in h:
            per[x["site"]].append(x)
        for site, rows in per.items():
            va = int(site, 16)
            occ = pos.get(va, [])
            for k, x in enumerate(rows):
                if k < len(occ) and occ[k] + 1 < len(trs):
                    by_site[site].append((x, trs[occ[k] + 1]))
    print("sites=%d hits=%d" % (len(by_site), len(h)))
    learned = 0
    rules = {}
    for site, rows in sorted(by_site.items(), key=lambda kv: -len(kv[1])):
        X = [[x.get(r, 0) or 0 for r in REGS] for x, _ in rows]
        outs = [o for _, o in rows]
        if len(X) < 20:
            continue
        # binary labels: most-common successor vs rest
        top = max(set(outs), key=outs.count)
        y = [0 if o == top else 1 for o in outs]
        if sum(y) < 10 or sum(y) > len(y) - 10:
            continue  # single-path or too skewed
        clf = DecisionTreeClassifier(max_depth=depth, min_samples_leaf=5)
        clf.fit(X, y)
        acc = clf.score(X, y)
        print("== %s x%d base=%s acc=%.4f ==" % (site, len(X), hex(top), acc))
        print(export_text(clf, feature_names=REGS, max_depth=depth))
        # causal probe: flag conditions are *relations* (cmp rsi,rbp -> ja
        # needs rsi>rbp, which axis-aligned splits approximate poorly).
        # Search depth-1 over relational features; a 1.0 hit is causal.
        import itertools
        feats = {r: [row[j] for row in X] for j, r in enumerate(REGS)}
        for a, b in itertools.combinations(REGS, 2):
            ca, cb = feats[a], feats[b]
            feats["%s>%s" % (a, b)] = [1 if x > y else 0 for x, y in zip(ca, cb)]
            feats["%s==%s" % (a, b)] = [1 if x == y else 0 for x, y in zip(ca, cb)]
        # unary vs-zero (test-fed branches: je <=> reg==0). Tried first:
        # cheapest, most causal; relational proxies also score 1.0.
        for r in REGS:
            feats["%s==0" % r] = [1 if v == 0 else 0 for v in feats[r]]
        names = sorted(feats)
        scored = []
        for nm in names:
            col = [[v] for v in feats[nm]]
            s = DecisionTreeClassifier(max_depth=1, min_samples_leaf=5) \
                .fit(col, y).score(col, y)
            scored.append((s, nm))
        scored.sort(reverse=True)
        print("  top relational: %s" %
              ", ".join("%s=%.4f" % (nm, s) for s, nm in scored[:4]))
        uz = [(s, nm) for s, nm in scored if nm.endswith("==0")]
        if uz:
            uz.sort(reverse=True)
            print("  unary-zero: %s=%.4f" % (uz[0][1], uz[0][0]))
        if scored and scored[0][0] >= 0.99:
            rules[site] = {"rule": scored[0][1], "acc": round(scored[0][0], 4),
                           "base": top, "visits": len(X)}
        learned += 1
        if learned >= 10:
            break
    print("learned %d divergent sites" % learned)
    if len(sys.argv) > 3:
        json.dump(rules, open(sys.argv[3], "w"), indent=1)
        print("wrote %d rules -> %s" % (len(rules), sys.argv[3]))


main()
