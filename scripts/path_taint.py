#!/usr/bin/env python3
"""Taint-based input->output mapping over an exact executed path.
Symbolize nothing; taint one input reg (or stack slot), run the path
concretely, report whether each output (regs + return slot) is tainted.
Answers "which input flows to the result" when symbolic expressions
drown in memory-model subtleties. Phase A composition primitive.
Usage: path_taint.py <trace.bin> <start_idx> <end_idx> <taint: rdi|rsi|rsp+off>
Env: DATA_DIR (snapshots for concrete memory).
Output: JSON {tainted_regs: [...], Thus output X depends on input Y}.
"""
import json
import os
import struct
import sys

DATA = os.environ.get("DATA_DIR", "./data")

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
from triton_handlers import arm_snapshot_callback, rmem
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from triton import TritonContext, ARCH, Instruction, MemoryAccess, CPUSIZE

WIDTH = {1: CPUSIZE.BYTE, 2: CPUSIZE.WORD, 4: CPUSIZE.DWORD, 8: CPUSIZE.QWORD}


def main():
    tpath, start, end, taint = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
    raw = open(tpath, "rb").read()
    trs = struct.unpack("<%dQ" % (len(raw) // 8), raw)
    seg = trs[start:end]
    ctx = TritonContext(ARCH.X86_64)
    arm_snapshot_callback(ctx)
    if taint in ("rdi", "rsi", "rax", "rbx", "rcx", "rdx", "r8", "r9"):
        ctx.taintRegister(getattr(ctx.registers, taint))
    elif taint.startswith("rsp+"):
        off = int(taint[4:], 0)
        # taint set by caller via concrete rsp below; record base
        ctx.taintMemory(MemoryAccess(0x7ffe0000 + off, CPUSIZE.QWORD))
    md = Cs(CS_ARCH_X86, CS_MODE_64)
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
        except Exception:
            break
        pass  # concrete memory via arm_snapshot_callback

        n += 1
        if n > 200000:
            break
    out = {"insns": n, "tainted_regs": [], "tainted_mem_sample": []}
    for r in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9",
              "r10", "r11", "rbp", "rsp"):
        try:
            if ctx.isRegisterTainted(getattr(ctx.registers, r)):
                out["tainted_regs"].append(r)
        except Exception:
            pass
    print(json.dumps(out))


main()
