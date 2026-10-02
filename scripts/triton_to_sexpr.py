#!/usr/bin/env python3
"""Triton python-AST repr -> prefix S-expr for `devirt mba`.
Handles the shapes triton_handlers.py emits: ints (0x../decimal),
ref_N/SymVar_N (alpha-renamed v0,v1.. by appearance), parens,
infix + - * & | ^ >> <<, unary ~, sx(n,x)/zx(n,x).
Usage: triton_to_sexpr.py <ast-file>  (one raw AST per line)
  prints: <line-no> ||| <s-expr>
"""
import re
import sys

# NOTE: ">>" treated as logical (Triton prints ashr separately;
# our samples only show logical use on masked values).


class P:
    def __init__(self, s):
        self.toks = []
        i = 0
        while i < len(s):
            c = s[i]
            if c.isspace():
                i += 1
            elif c in "()":
                self.toks.append(c)
                i += 1
            elif c == ",":
                self.toks.append(",")
                i += 1
            elif s.startswith(">>", i) or s.startswith("<<", i):
                self.toks.append(s[i:i + 2])
                i += 2
            elif c in "+-*&|^~":
                self.toks.append(c)
                i += 1
            elif c == "0" and i + 1 < len(s) and s[i + 1] in "xX":
                m = re.match(r"0[xX][0-9a-fA-F]+", s[i:])
                self.toks.append(m.group(0))
                i += len(m.group(0))
            elif c.isdigit():
                m = re.match(r"\d+", s[i:])
                self.toks.append(m.group(0))
                i += len(m.group(0))
            elif c.isalpha() or c == "_":
                m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", s[i:])
                self.toks.append(m.group(0))
                i += len(m.group(0))
            else:
                raise ValueError("bad char %r in %r" % (c, s))
        self.p = 0
        self.vars = {}
        self.nv = [0]

    def peek(self):
        return self.toks[self.p] if self.p < len(self.toks) else None

    def next(self):
        t = self.peek()
        self.p += 1
        return t

    def var(self, name):
        if name not in self.vars:
            self.vars[name] = "v%d" % self.nv[0]
            self.nv[0] += 1
        return self.vars[name]

    def parse(self):
        e = self.expr()
        if self.peek() is not None:
            raise ValueError("trailing %r" % self.peek())
        return e

    def expr(self):
        return self.bor()

    def bor(self):
        e = self.bxor()
        while self.peek() == "|":
            self.next()
            e = "(or %s %s)" % (e, self.bxor())
        return e

    def bxor(self):
        e = self.band()
        while self.peek() == "^":
            self.next()
            e = "(xor %s %s)" % (e, self.band())
        return e

    def band(self):
        e = self.shift()
        while self.peek() == "&":
            self.next()
            e = "(and %s %s)" % (e, self.shift())
        return e

    def shift(self):
        e = self.add()
        while self.peek() in (">>", "<<"):
            op = self.next()
            e = "(%s %s %s)" % ("shru" if op == ">>" else "shl", e, self.add())
        return e

    def add(self):
        e = self.mul()
        while self.peek() in ("+", "-"):
            op = self.next()
            e = "(%s %s %s)" % ("add" if op == "+" else "sub", e, self.mul())
        return e

    def mul(self):
        e = self.unary()
        while self.peek() == "*":
            self.next()
            e = "(mul %s %s)" % (e, self.unary())
        return e

    def unary(self):
        if self.peek() == "~":
            self.next()
            return "(not %s)" % self.unary()
        return self.atom()

    def atom(self):
        t = self.next()
        if t == "(":
            e = self.expr()
            assert self.next() == ")", "want )"
            return e
        if t in ("sx", "zx"):
            assert self.next() == "("
            n = self.next()
            assert self.next() == ","
            e = self.expr()
            assert self.next() == ")"
            return "(%s %s %s)" % ("sx" if t == "sx" else "zx", e, n)
        if re.fullmatch(r"(ref_\d+|SymVar_\d+)", t or ""):
            return self.var(t)
        if re.fullmatch(r"0[xX][0-9a-fA-F]+|\d+", t or ""):
            return str(int(t, 0))
        raise ValueError("atom %r" % t)


def main():
    for i, line in enumerate(open(sys.argv[1])):
        line = line.strip()
        if not line:
            continue
        try:
            print("%d ||| %s" % (i, P(line).parse()))
        except Exception as e:
            print("%d ||| PARSE-FAIL %s" % (i, str(e)[:80]))


if __name__ == "__main__":
    main()
