#!/usr/bin/env python3
"""Path-sensitive symbolic lift: process an exact executed path
(trace slice) with Triton, symbolizing chosen regs, concretizing memory
from snapshots. Reports output regs + branch predicates (ZF/CF ASTs at
each jcc) — the raw material for path composition (Phase A).
Usage: path_lift.py <trace.bin> <start_idx> <end_idx> <reg,reg..>
Env: DATA_DIR (open_bases.json + open_mem_*.bin).
Output: JSON {regs: {r: ast}, preds: [{va, taken, zf, cf}]}.
"""
import json
import os
import struct
import sys

DATA = os.environ.get("DATA_DIR", "./data")

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
from triton_handlers import arm_snapshot_callback, rmem
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from triton import TritonContext, ARCH, Instruction, MemoryAccess, AST_REPRESENTATION, CPUSIZE

WIDTH = {1: CPUSIZE.BYTE, 2: CPUSIZE.WORD, 4: CPUSIZE.DWORD, 8: CPUSIZE.QWORD}
JCC = {"ja", "jae", "jb", "jbe", "jc", "je", "jz", "jg", "jge", "jl", "jle",
       "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng", "jnge", "jnl", "jnle",
       "jno", "jnp", "jns", "jnz", "jo", "jp", "jpe", "jpo", "js"}


def main():
    tpath, start, end = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    syms = sys.argv[4].split(",") if len(sys.argv) > 4 else ["rdi", "rsi"]
    raw = open(tpath, "rb").read()
    trs = struct.unpack("<%dQ" % (len(raw) // 8), raw)
    seg = trs[start:end]
    ctx = TritonContext(ARCH.X86_64)
    arm_snapshot_callback(ctx)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    for r in syms:
        ctx.symbolizeRegister(getattr(ctx.registers, r))
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    preds = []
    n = 0
    for va in seg:
        code = rmem(va, 15)
        if not code:
            continue
        ins = next(md.disasm(code, va, count=1), None)
        if ins is None:
            continue
        i = Instruction(bytes(ins.bytes))
        i.setAddress(ins.address)
        try:
            ctx.processing(i)
        except Exception as e:
            preds.append({"va": hex(va), "error": str(e)[:80]})
            break
        pass  # concrete memory via arm_snapshot_callback

        if ins.mnemonic in JCC and len(seg) > 1:
            try:
                zf = str(ctx.getSymbolicRegister(ctx.registers.zf))
                cf = str(ctx.getSymbolicRegister(ctx.registers.cf))
            except Exception:
                zf, cf = "?", "?"
            preds.append({"va": hex(va), "mn": ins.mnemonic, "zf": zf[:200], "cf": cf[:200]})
        n += 1
        if n > 200000:
            break
    regs = {}
    for r in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9",
              "r10", "r11", "rbp"):
        try:
            ast = ctx.getSymbolicRegister(getattr(ctx.registers, r))
            if ast is None:
                continue
            s = str(ctx.simplify(ast.getAst()))
            if len(s) < 600:
                regs[r] = s
        except Exception:
            pass
    print(json.dumps({"insns": n, "regs": regs, "preds": preds}, indent=1))


main()
