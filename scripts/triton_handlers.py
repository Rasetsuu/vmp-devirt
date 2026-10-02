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



try:
    from triton import CALLBACK as _CB
except Exception:
    _CB = None


def arm_snapshot_callback(ctx):
    """Feed snapshot bytes on concrete reads WITHOUT clobbering
    symbolic memory (the post-load setConcrete pattern overwrote
    VM-written symbolic cells with stale dump bytes and fed
    uninitialized zeros on first touch — both wrong)."""
    if _CB is None:
        return

    def cb(c, ma):
        try:
            if c.isMemorySymbolized(ma):
                return
            a = ma.getAddress()
            b = rmem(a, 8)
            if b is None:
                return
            w = {1: CPUSIZE.BYTE, 2: CPUSIZE.WORD, 4: CPUSIZE.DWORD, 8: CPUSIZE.QWORD}.get(ma.getSize(), CPUSIZE.QWORD)
            c.setConcreteMemoryValue(MemoryAccess(ma.getAddress(), w),
                                     int.from_bytes(b[:ma.getSize()], "little"))
        except Exception:
            pass

    try:
        ctx.addCallback(_CB.GET_CONCRETE_MEMORY_VALUE, cb)
    except Exception:
        pass

def lift_block(va, max_ins=24, sym_regs=("rsi", "rdi", "r9", "rcx")):
    """Return {reg: simplified AST str} for touched output regs."""
    ctx = TritonContext(ARCH.X86_64)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    for r in sym_regs:
        ctx.symbolizeRegister(getattr(ctx.registers, r))
    arm_snapshot_callback(ctx)
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
        pass  # concrete memory via arm_snapshot_callback
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
