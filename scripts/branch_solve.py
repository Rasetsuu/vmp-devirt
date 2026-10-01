#!/usr/bin/env python3
"""Solve every divergent branch: predecessors -> flag-writer -> condition.
Compares predicted vs actual outcomes using hit regs. Prints scoreboard."""
import json
import os
import struct
from collections import defaultdict
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import *

D = os.environ.get("DATA_DIR", os.environ.get("DATA_DIR", "./data/gadd_br"))

FLAG_WRITERS = {"add", "sub", "cmp", "and", "or", "xor", "test", "neg",
                "mul", "imul", "shl", "shr", "sal", "sar", "rol", "ror",
                "dec", "inc", "adc", "sbb"}
# NOTE: `not`, `mov`, `lea`, `push`, `pop` do NOT touch flags and must
# never be picked as writers. `dec`/`inc` preserve CF.
# Post-state rule (hit regs are POST-writer): writers with a register
# destination leave their result in that register, so ZF comes straight
# from the snapshot — re-applying the writer double-counts (off-by-one
# at counter wrap; e.g. `dec r9` + `jne` missed 2/3996 before this).
# `cmp`/`test` are pure (no reg write): evaluate from regs as before.
# `rol`/`ror` preserve ZF: excluded.
MODIFIES_REG = {"dec", "inc", "add", "sub", "and", "or", "xor", "neg",
                "shl", "shr", "sal", "sar", "adc", "sbb"}

REGFILE = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10",
           "r11", "r12", "r13", "r14", "r15", "rbp", "rsp"]


def load_snaps():
    bases = json.load(open(D + "/open_bases.json"))
    sn = {}
    for name, vs in bases.items():
        try:
            sn[int(vs, 16)] = open(D + "/open_mem_%s.bin" % name, "rb").read()
        except Exception:
            pass
    return sn


SN = None
MD = Cs(CS_ARCH_X86, CS_MODE_64)
MD.detail = True


def dis1(va):
    global SN
    if SN is None:
        SN = load_snaps()
    for b, d in SN.items():
        if b <= va < b + len(d):
            code = d[va - b:va - b + 15]
            for ins in MD.disasm(code, va, count=1):
                return ins
    return None


def sub_flags(a, b, bits):
    m = (1 << bits) - 1
    a &= m
    b &= m
    r = (a - b) & m
    return {"cf": a < b, "zf": r == 0, "sf": bool(r >> (bits - 1)),
            "of": bool(((a ^ b) & (a ^ r)) >> (bits - 1) & 1),
            "pf": bool(bin(r & 0xFF).count("1") % 2 == 0)}


def jcc_taken(mn, fl):
    c, z, s, o = fl["cf"], fl["zf"], fl["sf"], fl["of"]
    return {"je": z, "jne": not z, "ja": not c and not z,
            "jae": not c, "jb": c, "jbe": c or z,
            "jl": s != o, "jle": z or (s != o),
            "jg": (not z) and (s == o), "jge": s == o,
            "js": s, "jns": not s, "jo": o, "jno": not o,
            "jp": fl["pf"], "jnp": not fl["pf"]}.get(mn, None)


def op_val(ins, idx, regs):
    op = ins.operands[idx]
    if op.type == X86_OP_REG:
        return regs.get(ins.reg_name(op.value.reg), 0), op.size * 8
    if op.type == X86_OP_IMM:
        return op.value.imm & ((1 << (op.size * 8)) - 1), op.size * 8
    return None, 0


def post_state_zf(writer, regs):
    """ZF from hit-time (post-writer) regs, or None if inapplicable.

    Pushan-style merge insight in miniature: at a join the flags are a
    function of merged state, not of re-executing the writer on that
    state. For reg-destination writers the result IS the snapshot
    register, so ZF reads out directly. Pure writers (cmp/test) and
    exotic shapes return None -> caller falls back to evaluation."""
    if writer.mnemonic not in MODIFIES_REG:
        return None
    try:
        op0 = writer.operands[0]
    except Exception:
        return None
    if op0.type != X86_OP_REG:
        return None
    try:
        dest = writer.reg_name(op0.value.reg)
    except Exception:
        return None
    bits = max(op0.size * 8, 8)
    return ((regs.get(dest, 0) or 0) & ((1 << bits) - 1)) == 0


def main():
    h = json.load(open(D + "/open_hits.json"))
    trs = struct.unpack("<%dQ" % (os.path.getsize(D + "/open_trace.bin") // 8),
                        open(D + "/open_trace.bin", "rb").read())
    pos = defaultdict(list)
    for i, a in enumerate(trs):
        if len(pos) < 600000:
            pos[a].append(i)
    by_site = defaultdict(list)
    for x in h:
        by_site[x["site"]].append(x)
    results = []
    for site, rows in by_site.items():
        # outcomes
        seen = 0
        outs = []
        va = int(site, 16)
        occ = pos.get(va, [])
        for x in rows:
            if seen >= len(occ) or occ[seen] + 1 >= len(trs):
                outs.append(None)
            else:
                outs.append(trs[occ[seen] + 1])
            seen += 1
        targets = set(o for o in outs if o is not None)
        if len(targets) < 2:
            continue  # single-path site
        # find flag writer: walk back from first occurrence
        first = occ[0] if occ else None
        writer = None
        if first is not None:
            for a in trs[max(0, first - 10):first]:
                ins = dis1(a)
                if ins is None:
                    continue
                if ins.mnemonic in FLAG_WRITERS:
                    writer = ins
        if writer is None:
            results.append((site, 0, 0, "no-writer", None))
            continue
        # branch insn at site
        bi = dis1(va)
        if bi is None:
            results.append((site, 0, 0, "no-branch", None))
            continue
        mn = bi.mnemonic
        # branch target for taken/fall classification
        tgt = None
        try:
            if len(bi.operands) == 1 and bi.operands[0].type == X86_OP_IMM:
                tgt = bi.operands[0].value.imm
        except Exception:
            pass
        ok = tot = 0
        for x, nx in zip(rows, outs):
            if nx is None:
                continue
            regs = {r: (x.get(r, 0) or 0) for r in REGFILE}
            # je/jne fast path: ZF straight from post-writer snapshot
            # (no double-apply of modifying writers).
            if mn in ("je", "jne"):
                zf = post_state_zf(writer, regs)
                if zf is not None and tgt is not None:
                    tot += 1
                    if ((not zf if mn == "jne" else zf) == (nx == tgt)):
                        ok += 1
                    continue
            # evaluate writer on current regs
            try:
                if writer.mnemonic in ("cmp", "sub"):
                    a0, bits0 = op_val(writer, 0, regs)
                    b0, bits1 = op_val(writer, 1, regs)
                    fl = sub_flags(a0, b0, max(bits0, bits1, 8))
                    cf_known = True
                elif writer.mnemonic in ("dec", "inc"):
                    a0, bits0 = op_val(writer, 0, regs)
                    d = -1 if writer.mnemonic == "dec" else 1
                    bits = max(bits0, 8)
                    m = (1 << bits) - 1
                    r = (a0 + d) & m
                    fl = {"cf": False, "zf": r == 0,
                          "sf": bool(r >> (bits - 1)),
                          "of": bool(((a0 ^ m) & (a0 ^ r)) >> (bits - 1) & 1) if d < 0 else bool(((~a0) & r) >> (bits - 1) & 1),
                          "pf": bool(bin(r & 0xFF).count("1") % 2 == 0)}
                    cf_known = False  # dec/inc preserve CF
                elif writer.mnemonic in ("test", "and"):
                    a0, bits0 = op_val(writer, 0, regs)
                    b0, bits1 = op_val(writer, 1, regs)
                    r = (a0 & b0) & ((1 << max(bits0, bits1, 8)) - 1)
                    fl = {"cf": False, "zf": r == 0,
                          "sf": bool(r >> (max(bits0, bits1, 8) - 1)),
                          "of": False,
                          "pf": bool(bin(r & 0xFF).count("1") % 2 == 0)}
                else:
                    continue
                # CF-dependent branches need known CF.
                if not cf_known and mn in ("jb", "jae", "ja", "jbe"):
                    continue
                pred = jcc_taken(mn, fl)
                if pred is None:
                    continue
                tot += 1
                if tgt is not None and (pred == (nx == tgt)):
                    ok += 1
            except Exception:
                continue
        results.append((site, ok, tot, writer.mnemonic if writer else None, mn))
    # report
    print("sites with divergence:", len(results))
    perfect = sum(1 for _, ok, tot, _, _ in results if tot > 0 and ok == tot)
    print("perfect:", perfect)
    for site, ok, tot, w, mn in results[:30]:
        print(" ", site, mn, "via", w, "%d/%d" % (ok, tot))


main()
