#!/usr/bin/env python3
"""Triton symbolic handler semantics (MBA simplifier).
Disassemble a block, symbolize chosen regs, concretize memory from a
snapshot dir, process, print simplified AST per output reg.
Env: DATA_DIR (default ./data), snapshot files open_mem_<sec>.bin with
open_bases.json mapping section -> base VA.
"""
import json
import os
import sys

DATA = os.environ.get("DATA_DIR", "./data")

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from triton import (TritonContext, ARCH, Instruction, MemoryAccess,
                        AST_REPRESENTATION, CPUSIZE)
except ImportError as e:
    sys.exit("missing dep (pip install triton-library capstone): %s" % e)

_snaps = None


def snaps():
    global _snaps
    if _snaps is None:
        _snaps = {}
        try:
            bases = json.load(open(os.path.join(DATA, "open_bases.json")))
        except Exception:
            bases = {}
        for name, base_s in bases.items():
            try:
                base = int(base_s, 16)
            except Exception:
                continue
            p = os.path.join(DATA, "open_mem_%s.bin" % name)
            if os.path.exists(p):
                _snaps[base] = open(p, "rb").read()
    return _snaps


def rmem(va, n):
    for base, data in snaps().items():
        if base <= va and va - base + n <= len(data):
            return data[va - base:va - base + n]
    return None


def lift_block(va, max_ins=24, sym_regs=("rsi", "rdi", "r9", "rcx")):
    """Return {reg: simplified AST str} for touched output regs."""
    ctx = TritonContext(ARCH.X86_64)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    for r in sym_regs:
        ctx.symbolizeRegister(getattr(ctx.registers, r))
    code = rmem(va, 96)
    if not code:
        return None
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for ins in md.disasm(code, va):
        if max_ins <= 0:
            break
        max_ins -= 1
        i = Instruction(bytes(ins.bytes))
        i.setAddress(ins.address)
        ctx.processing(i)
        for le in i.getLoadAccess():
            ma = le[0] if isinstance(le, tuple) else le
            a, s = ma.getAddress(), ma.getSize()
            b = rmem(a, s)
            if b is not None:
                width = {1: CPUSIZE.BYTE, 2: CPUSIZE.WORD,
                         4: CPUSIZE.DWORD, 8: CPUSIZE.QWORD}.get(s, CPUSIZE.QWORD)
                ctx.setConcreteMemoryValue(
                    MemoryAccess(a, width), int.from_bytes(b[:s], "little"))
        if ins.mnemonic in ("jmp", "call", "ret"):
            break
    out = {}
    for r in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9",
              "r10", "r11", "rbp"):
        try:
            ast = ctx.getSymbolicRegister(getattr(ctx.registers, r))
            if ast is None:
                continue
            s = str(ctx.simplify(ast.getAst()))
            if len(s) < 400:
                out[r] = s
        except Exception:
            pass
    return out


if __name__ == "__main__":
    va = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x140001000
    r = lift_block(va)
    if not r:
        print("no mem")
    else:
        for k, v in r.items():
            print("%s = %s" % (k, v[:240]))
