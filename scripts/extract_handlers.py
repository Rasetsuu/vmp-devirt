#!/usr/bin/env python3
"""Paper step 3 (VMPredator §III): per-handler symbolic extraction.

Emulates one handler block (jump-to-jump segment from `devirt handlers`)
under Triton with symbolic registers, concrete stack/overlay memory.
Keeps only ASTs feeding stack-region (vctx) stores — garbage and
decode routines drop out the same way the paper's Semantic Extractor
describes. Compare op-mix against rule-mined chains.

Usage: extract_handlers.py <snapdir> <handler-va> [max-insns] [trace.bin]
  With trace.bin: handler entry = most common trace successor of the
  dispatcher (the jump itself is the dispatch, not the body).
"""
import json
import os
import struct
import sys
from collections import Counter
import json
import os
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from triton import (TritonContext, ARCH, Instruction, MemoryAccess,
                    AST_REPRESENTATION, CPUSIZE)

STACK_BASE, STACK_SIZE = 0x7F000000, 0x1000000
HEAP_BASE, HEAP_SIZE = 0x71000000, 0x100000


def load_overlay(d):
    bases = json.load(open(d + "/open_bases.json"))
    secs = []
    for f in os.listdir(d):
        if f.startswith("open_mem_") and f.endswith(".bin"):
            tag = f[9:-4]
            if tag in bases:
                secs.append((int(bases[tag], 16),
                             open(d + "/" + f, "rb").read()))
    return secs


def main():
    snapdir, hva = sys.argv[1], int(sys.argv[2], 16)
    max_ins = int(sys.argv[3]) if len(sys.argv) > 3 else 200
    entry = hva
    if len(sys.argv) > 4:
        raw = open(sys.argv[4], "rb").read()
        trs = struct.unpack("<%dQ" % (len(raw) // 8), raw)
        succ = Counter(b for a, b in zip(trs, trs[1:]) if a == hva)
        if succ:
            entry = succ.most_common(1)[0][0]
            print("dispatcher %#x -> entry %#x (x%d, %d targets)"
                  % (hva, entry, succ[entry], len(succ)))
    ctx = TritonContext(ARCH.X86_64)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    # concrete memory: overlay sections + zeroed stack/heap
    for base, data in load_overlay(snapdir):
        ctx.setConcreteMemoryAreaValue(base, data)
    ctx.setConcreteMemoryAreaValue(STACK_BASE, b"\x00" * STACK_SIZE)
    ctx.setConcreteMemoryAreaValue(HEAP_BASE, b"\x00" * HEAP_SIZE)
    # symbolic regs, concrete rsp/rip
    for r in ["rax", "rbx", "rcx", "rdx", "rsi", "rdi",
              "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]:
        ctx.symbolizeRegister(getattr(ctx.registers, r))
    ctx.setConcreteRegisterValue(ctx.registers.rsp, 0x7FFE0000)
    ctx.setConcreteRegisterValue(ctx.registers.rbp, 0x42)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    rip, n, stop = entry, 0, "limit"
    stores, jmps = [], []
    while n < max_ins:
        try:
            raw = ctx.getConcreteMemoryAreaValue(rip, 15)
        except Exception:
            stop = "unmapped:%#x" % rip
            break
        ins = list(md.disasm(bytes(raw), rip, count=1))
        if not ins:
            stop = "bad-decode:%#x" % rip
            break
        ins = ins[0]
        t = Instruction(bytes(raw[:ins.size]))
        t.setAddress(rip)
        try:
            ctx.processing(t)
        except Exception as e:
            stop = "triton-err:%s" % str(e)[:40]
            break
        n += 1
        for sa in t.getStoreAccess():
            # Shape varies by Triton build: (MemoryAccess, ast) or
            # (ast, MemoryAccess). Detect by attribute.
            elems = list(sa) if isinstance(sa, tuple) else [sa]
            ma = next((e for e in elems if hasattr(e, "getAddress")), None)
            ast = next((e for e in elems if hasattr(e, "getHash")), None)
            if ma is None:
                continue
            try:
                s = ast
            except Exception:
                s = None
            a = ma.getAddress()
            if STACK_BASE <= a < STACK_BASE + STACK_SIZE:
                stores.append((a, s))
        m = ins.mnemonic
        if m in ("jmp", "call", "ret"):
            stop = "%s %s" % (m, ins.op_str[:24])
            break
        if m.startswith("j"):
            jmps.append((hex(rip), m, ins.op_str[:24]))
            # follow fall-through only (v1 linear path)
        rip += ins.size
    print("handler %#x: insns=%d stop=%s stack_stores=%d jcc=%d"
          % (hva, n, stop, len(stores), len(jmps)))

    from triton import AST_NODE as _AN
    _TN = {v: k for k, v in vars(_AN).items() if not k.startswith("_")}

    def show(node, depth=0):
        if node is None or depth > 8:
            return "?"
        try:
            t = _TN.get(node.getType(), "?")
        except Exception:
            return "?"
        if t == "VARIABLE":
            try:
                return node.getSymbolicVariable().getName()
            except Exception:
                return "sym"
        if t in ("BV", "INTEGER"):
            try:
                return hex(node.evaluate())
            except Exception:
                return "const"
        try:
            kids = list(node.getChildren())
        except Exception:
            return t
        if not kids:
            try:
                return hex(node.evaluate())
            except Exception:
                return t
        return "(%s %s)" % (t, " ".join(show(k, depth + 1) for k in kids[:5]))

    for a, ast in stores[:10]:
        print("  store %#x <- %s" % (a, show(ast)[:300]))
    for j in jmps[:6]:
        print("  jcc %s %s %s" % j)


main()
