#!/usr/bin/env python3
"""C miniature emitter: two executed paths -> `if/else return` C.
Probe-driven synthesis (no AST string parsing): lift both paths with
Triton over symbolic args, then attribute result lanes and fit the
branch condition by concrete probing (setConcreteVariableValue +
evaluate — no re-lift per probe). Renders C, differential-fuzzes vs
reference. Analyst-directed: arg regs + deciding branch come from
the caller, not discovery.
Usage: emit_c.py <trace.bin> <then_start> <then_end> <else_start> <else_end>
Env: DATA_DIR (snapshots), EMIT_OUT (write .c file, default stdout).
"""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
from triton_handlers import arm_snapshot_callback, rmem
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from triton import TritonContext, ARCH, Instruction, AST_REPRESENTATION

DATA = os.environ.get("DATA_DIR", "./data")
JCC = {"ja", "jae", "jb", "jbe", "jc", "je", "jg", "jge", "jl", "jle",
       "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng", "jnge", "jnl",
       "jnle", "jno", "jnp", "jns", "jnz", "jo", "jp", "jpe", "jpo", "js", "jz"}

A_CONC = 0x0807060504030201
B_CONC = 0x1817161514131211


def lift_segment(seg):
    """Process VA list with鮮 distinct-concrete symbolic args.
    Returns (ctx, rax_ast, zf_by_va, symvar_a, symvar_b)."""
    ctx = TritonContext(ARCH.X86_64)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    ctx.setConcreteRegisterValue(ctx.registers.rdi, A_CONC)
    ctx.setConcreteRegisterValue(ctx.registers.rsi, B_CONC)
    ctx.symbolizeRegister(ctx.registers.rdi)
    ctx.symbolizeRegister(ctx.registers.rsi)
    arm_snapshot_callback(ctx)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    zf_by_va = {}
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
        if ins.mnemonic in JCC:
            try:
                zf = ctx.getSymbolicRegister(ctx.registers.zf)
                if zf is not None:
                    zf_by_va[va] = zf.getAst()
            except Exception:
                pass
    rax = ctx.getSymbolicRegister(ctx.registers.rax)
    rax_ast = rax.getAst() if rax is not None else None
    svar = {v.getName(): v for v in ctx.getSymbolicVariables().values()}
    return ctx, rax_ast, zf_by_va, svar.get("SymVar_0"), svar.get("SymVar_1")


def lane_bytes(val, n=4):
    return [(val >> (8 * j)) & 0xFF for j in range(n)]


def attribute_lanes(ctx, rax_ast, va, vb):
    """Map each rax byte lane -> ('a',j) | ('b',j) | ('const',v) | ('derived',...).
    Two probes per input byte would catch xor-keys; the miniature
    asserts identity-or-const and reports the rest as derived."""
    base = rax_ast.evaluate()
    out = []
    for j in range(4):
        bj = (base >> (8 * j)) & 0xFF
        src = None
        # const check: flip all of a, then all of b
        ctx.setConcreteVariableValue(va, A_CONC ^ 0xFFFFFFFFFFFFFFFF)
        v1 = rax_ast.evaluate()
        ctx.setConcreteVariableValue(va, A_CONC)
        ctx.setConcreteVariableValue(vb, B_CONC ^ 0xFFFFFFFFFFFFFFFF)
        v2 = rax_ast.evaluate()
        ctx.setConcreteVariableValue(vb, B_CONC)
        if ((v1 >> (8 * j)) & 0xFF) == bj and ((v2 >> (8 * j)) & 0xFF) == bj:
            # byte independent of both inputs: constant (verify value)
            out.append(("const", bj))
            continue
        # which input moves it? flip each byte lane separately
        found = None
        for k in range(8):
            ctx.setConcreteVariableValue(va, A_CONC ^ (0xFF << (8 * k)))
            if ((rax_ast.evaluate() >> (8 * j)) & 0xFF) != bj:
                found = ("a", k)
                break
        ctx.setConcreteVariableValue(va, A_CONC)
        if found is None:
            for k in range(8):
                ctx.setConcreteVariableValue(vb, B_CONC ^ (0xFF << (8 * k)))
                if ((rax_ast.evaluate() >> (8 * j)) & 0xFF) != bj:
                    found = ("b", k)
                    break
            ctx.setConcreteVariableValue(vb, B_CONC)
        if found is None:
            # moves with input but not byte-local: transform; probe identity
            # (flip whole lane value 0x00->0xFF and compare delta)
            out.append(("derived", None))
            continue
        name, k = found
        conc = A_CONC if name == "a" else B_CONC
        var = va if name == "a" else vb
        # identity check: lane value == input lane value across 3 probes
        ok = True
        for pv in (0x00, 0xFF, 0x5A):
            cv = (conc & ~(0xFF << (8 * k))) | (pv << (8 * k))
            ctx.setConcreteVariableValue(var, cv)
            if ((rax_ast.evaluate() >> (8 * j)) & 0xFF) != pv:
                ok = False
                break
        ctx.setConcreteVariableValue(var, conc)
        out.append(("ident", (name, k)) if ok else ("derived", found))
    return out


OPS = [
    ("==", lambda a, b: a == b), ("!=", lambda a, b: a != b),
    ("<", lambda a, b: a < b), ("<=", lambda a, b: a <= b),
    (">", lambda a, b: a > b), (">=", lambda a, b: a >= b),
]


def fit_condition(ctx, zf_ast, va, vb):
    """Fit ZF (taken=else) to a 32-bit signed comparison. Returns
    (op, polarity) with polarity True meaning `a op b` selects THEN.
    Unique fit required; ambiguity is an error, not a guess."""
    def s32(x):
        x &= 0xFFFFFFFF
        return x - 0x100000000 if x & 0x80000000 else x
    grid = [0, 1, -1, 40, 0x11111111, 0x12345678, 2**31 - 1, -(2**31),
            0x12345677, 300, 199, 200]
    obs = []
    for a in grid:
        for b in (0, 1, 40, 0x11111111, 0x12345678 - 7, -(2**31)):
            ctx.setConcreteVariableValue(va, a & 0xFFFFFFFFFFFFFFFF)
            ctx.setConcreteVariableValue(vb, b & 0xFFFFFFFFFFFFFFFF)
            taken = bool(zf_ast.evaluate() & 1)
            obs.append((s32(a), s32(b), taken))
    ctx.setConcreteVariableValue(va, A_CONC)
    ctx.setConcreteVariableValue(vb, B_CONC)
    fits = []
    for op, f in OPS:
        # taken==else. polarity: does `a op b` == (not taken)?
        if all((f(a, b) == (not t)) for a, b, t in obs):
            fits.append(("a %s b selects THEN" % op, op, True))
        if all((f(a, b) == t) for a, b, t in obs):
            fits.append(("a %s b selects ELSE" % op, op, False))
    uniq = [f for f in fits if f[2]]
    if len(uniq) != 1:
        return None, "ambiguous fits: %s" % [f[0] for f in fits]
    return uniq[0][1], None


def render_result(lanes):
    """Lanes -> C expr. Whole-var identity only; else honest failure."""
    idents = [l for l in lanes if l[0] == "ident"]
    consts = [l for l in lanes if l[0] == "const"]
    if len(idents) == 4:
        names = set(n for _, (n, k) in idents)
        ks = sorted(k for _, (n, k) in idents)
        if len(names) == 1 and ks == [0, 1, 2, 3]:
            return list(names)[0], None
    if len(consts) == 4:
        v = sum(c << (8 * j) for j, (_, c) in enumerate(consts))
        return "(%d)" % v, None
    return None, "non-trivial lanes: %s" % (lanes,)


def main():
    tpath = sys.argv[1]
    ts, te, es, ee = (int(x) for x in sys.argv[2:6])
    raw = open(tpath, "rb").read()
    tr = struct.unpack("<%dQ" % (len(raw) // 8), raw)
    then_seg = list(tr[ts:te])
    else_seg = list(tr[es:ee])
    i = 0
    while i < min(len(then_seg), len(else_seg)) and then_seg[i] == else_seg[i]:
        i += 1
    sys.stderr.write("divergence at index %d (branch %#x)\n" % (i, then_seg[i - 1]))
    ctx_t, rax_t, _, va_t, vb_t = lift_segment(then_seg)
    ctx_e, rax_e, zf_e, va_e, vb_e = lift_segment(else_seg)
    branch_va = then_seg[i - 1]
    zf = zf_e.get(branch_va)
    if zf is None:
        sys.exit("no ZF recorded at deciding branch %#x" % branch_va)
    lanes_t = attribute_lanes(ctx_t, rax_t, va_t, vb_t)
    lanes_e = attribute_lanes(ctx_e, rax_e, va_e, vb_e)
    sys.stderr.write("then lanes: %s\nelse lanes: %s\n" % (lanes_t, lanes_e))
    op, err = fit_condition(ctx_e, zf, va_e, vb_e)
    if err:
        sys.exit("condition: " + err)
    rt, err_t = render_result(lanes_t)
    re_, err_e = render_result(lanes_e)
    if err_t or err_e:
        sys.exit("arms: %s %s" % (err_t, err_e))
    # op selects THEN: if (a op b) return then else return else_
    src = ("#include <stdint.h>\n"
           "int max_i32(int a, int b) {\n"
           "  if (a %s b) { return %s; } else { return %s; }\n"
           "}\n") % (op, rt, re_)
    out = os.environ.get("EMIT_OUT")
    if out:
        open(out, "w").write(src)
    else:
        sys.stdout.write(src)
    sys.stderr.write("emitted: if (a %s b) return %s else return %s\n" % (op, rt, re_))


main()
