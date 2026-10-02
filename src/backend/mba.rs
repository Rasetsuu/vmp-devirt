//! MBA-Blast subset: 1-bit-normal-form simplification of Mixed
//! Boolean-Arithmetic expressions (Liu et al., USENIX Security '21).
//!
//! Core insight ported here ("two-way feature"): any 2-variable 1-bit
//! expression equals `c1*x + c2*y + c3*(x&y) - c4`, so every bitwise
//! node rewrites to a linear form (Table 2 of the paper, reproduced
//! below), like terms combine, and the normal form maps back to a
//! minimal bitwise expression. Identities proved on truth tables lift
//! to any width, so verification is exhaustive testing, not sampling.
//!
//! Table 2 (bitwise -> linear), with `~t = -t-1` and De Morgan applied
//! first so every And/Or/Xor/Not node matches exactly one row:
//! ```text
//! 0 -> 0 | x&y -> x&y | x&~y -> x-(x&y) | x -> x | ~x&y -> y-(x&y)
//! y -> y | x^y -> x+y-2(x&y) | x|y -> x+y-(x&y)
//! ~(x|y) -> -x-y+(x&y)-1 | ~(x^y) -> -x-y+2(x&y)-1
//! ~y -> -y-1 | x|~y -> -y+(x&y)-1 | ~x -> -x-1
//! ~x|y -> -x+(x&y)-1 | ~(x&y) -> -(x&y)-1 | -1 -> -1
//! ```
//! Scope: two variables per reduction step (paper §5.2 recurses over
//! sub-expression pairs for wider expressions; same here). Arithmetic
//! is wrapping (ring), matching x86/LLVM integer semantics.
//!
//! Application points in this pipeline: opaque-predicate guards and
//! jump-target computations (MBA-shaped on both VMP and Tigress),
//! plus a stronger-than-sampling equivalence oracle for `synth`.

use std::collections::BTreeMap;

/// Opaque operations (shifts, extends): structural, never Table-2
/// matched. They normalize to [`Atom::Opaque`] keyed by their
/// normalized operand, so identical shapes cluster without claiming
/// false linear equivalences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Const(u64),
    Var(String),
    Add(Box<Expr>, Box<Expr>),
    Sub(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Xor(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Shl(Box<Expr>, u32),
    Shru(Box<Expr>, u32),
    Sx(Box<Expr>, u32),
    Zx(Box<Expr>, u32),
    Rol(Box<Expr>, Box<Expr>),
    Ror(Box<Expr>, Box<Expr>),
    Mod(Box<Expr>, Box<Expr>),
}

fn var(s: &str) -> Expr {
    Expr::Var(s.to_string())
}

impl Expr {
    /// Tree node count (paper's DAG complexity, tree version).
    pub fn nodes(&self) -> usize {
        match self {
            Expr::Const(_) | Expr::Var(_) => 1,
            Expr::Add(a, b) | Expr::Sub(a, b) | Expr::Mul(a, b)
            | Expr::And(a, b) | Expr::Or(a, b) | Expr::Xor(a, b) => 1 + a.nodes() + b.nodes(),
            Expr::Not(a) => 1 + a.nodes(),
            Expr::Shl(a, _) | Expr::Shru(a, _) | Expr::Sx(a, _) | Expr::Zx(a, _) => 1 + a.nodes(),
            Expr::Rol(a, b) | Expr::Ror(a, b) | Expr::Mod(a, b) => 1 + a.nodes() + b.nodes(),
        }
    }

    /// True when MBA-obfuscated structure remains. The linear basis
    /// atom `x&y` (And of two variables) is NOT MBA — it is the normal
    /// form's irreducible; likewise no `Not` survives Table 2 (all
    /// become `-t-1`). So: any Or/Xor/Not, or And over non-variables.
    pub fn is_mba(&self) -> bool {
        match self {
            Expr::Const(_) | Expr::Var(_) => false,
            Expr::Add(a, b) | Expr::Sub(a, b) | Expr::Mul(a, b) => {
                a.is_mba() || b.is_mba()
            }
            Expr::And(a, b) => match (a.as_ref(), b.as_ref()) {
                (Expr::Var(_), Expr::Var(_)) => false,
                _ => true,
            },
            Expr::Or(..) | Expr::Xor(..) | Expr::Not(_) => true,
            Expr::Shl(..) | Expr::Shru(..) | Expr::Sx(..) | Expr::Zx(..) => false,
            Expr::Rol(..) | Expr::Ror(..) | Expr::Mod(..) => false,
        }
    }

    /// Wrapping evaluation under a variable assignment.
    pub fn eval(&self, env: &BTreeMap<String, u64>) -> u64 {
        match self {
            Expr::Const(v) => *v,
            Expr::Var(n) => env.get(n).copied().unwrap_or(0),
            Expr::Add(a, b) => a.eval(env).wrapping_add(b.eval(env)),
            Expr::Sub(a, b) => a.eval(env).wrapping_sub(b.eval(env)),
            Expr::Mul(a, b) => a.eval(env).wrapping_mul(b.eval(env)),
            Expr::And(a, b) => a.eval(env) & b.eval(env),
            Expr::Or(a, b) => a.eval(env) | b.eval(env),
            Expr::Xor(a, b) => a.eval(env) ^ b.eval(env),
            Expr::Not(a) => !a.eval(env),
            Expr::Shl(a, k) => a.eval(env).wrapping_shl(*k),
            Expr::Shru(a, k) => a.eval(env).wrapping_shr(*k),
            Expr::Sx(a, n) => {
                // sign-extend to n BITS (Triton sx(nbits, e) units)
                let v = a.eval(env) & (if *n >= 64 { u64::MAX } else { (1u64 << n) - 1 });
                let shift = 64 - (*n).min(64);
                ((v << shift) as i64 >> shift) as u64
            }
            Expr::Rol(a, b) => {
                let (v, k) = (a.eval(env), b.eval(env) & 63);
                v.rotate_left(k as u32)
            }
            Expr::Ror(a, b) => {
                let (v, k) = (a.eval(env), b.eval(env) & 63);
                v.rotate_right(k as u32)
            }
            Expr::Mod(a, b) => {
                let d = b.eval(env);
                if d == 0 { 0 } else { a.eval(env) % d }
            }
            Expr::Zx(a, n) => {
                // zero-extend to n BITS: low-bits mask
                let v = a.eval(env);
                if *n >= 64 {
                    v
                } else {
                    v & ((1u64 << n) - 1)
                }
            }
        }
    }
}

/// Strip one `Not` layer: (inner, negated?).
fn unnot(e: &Expr) -> (&Expr, bool) {
    match e {
        Expr::Not(x) => (x, true),
        _ => (e, false),
    }
}

/// Tiny builders (keep Table-2 rows readable).
fn e_add(l: Expr, r: Expr) -> Expr {
    Expr::Add(Box::new(l), Box::new(r))
}
fn e_sub(l: Expr, r: Expr) -> Expr {
    Expr::Sub(Box::new(l), Box::new(r))
}
fn e_mul(l: Expr, r: Expr) -> Expr {
    Expr::Mul(Box::new(l), Box::new(r))
}
fn e_neg(l: Expr) -> Expr {
    Expr::Sub(Box::new(Expr::Const(0)), Box::new(l))
}
fn e_and(l: Expr, r: Expr) -> Expr {
    Expr::And(Box::new(l), Box::new(r))
}
const ONE: Expr = Expr::Const(1);

/// Strip double negations recursively (cheap, always safe).
/// NOTE: no De Morgan expansion here on purpose — Table 2 already
/// covers every negated pair (`~x&~y`, `~x|~y`) directly, and pushing
/// `Not` inward first would destroy those rows.
fn strip_double_neg(e: &Expr) -> Expr {
    match e {
        Expr::Shl(a, k) => Expr::Shl(re_box(strip_double_neg(a)), *k),
        Expr::Shru(a, k) => Expr::Shru(re_box(strip_double_neg(a)), *k),
        Expr::Sx(a, k) => Expr::Sx(re_box(strip_double_neg(a)), *k),
        Expr::Zx(a, k) => Expr::Zx(re_box(strip_double_neg(a)), *k),
        Expr::Rol(a, b) => Expr::Rol(re_box(strip_double_neg(a)), re_box(strip_double_neg(b))),
        Expr::Ror(a, b) => Expr::Ror(re_box(strip_double_neg(a)), re_box(strip_double_neg(b))),
        Expr::Mod(a, b) => Expr::Mod(re_box(strip_double_neg(a)), re_box(strip_double_neg(b))),
        Expr::Not(x) => match x.as_ref() {
            Expr::Not(y) => strip_double_neg(y),
            _ => Expr::Not(Box::new(strip_double_neg(x))),
        },
        Expr::Add(a, b) => Expr::Add(re_box(strip_double_neg(a)), re_box(strip_double_neg(b))),
        Expr::Sub(a, b) => Expr::Sub(re_box(strip_double_neg(a)), re_box(strip_double_neg(b))),
        Expr::Mul(a, b) => Expr::Mul(re_box(strip_double_neg(a)), re_box(strip_double_neg(b))),
        Expr::And(a, b) => Expr::And(re_box(strip_double_neg(a)), re_box(strip_double_neg(b))),
        Expr::Or(a, b) => Expr::Or(re_box(strip_double_neg(a)), re_box(strip_double_neg(b))),
        Expr::Xor(a, b) => Expr::Xor(re_box(strip_double_neg(a)), re_box(strip_double_neg(b))),
        leaf => leaf.clone(),
    }
}

fn re_box(e: Expr) -> Box<Expr> {
    Box::new(e)
}

/// Try one Table-2 row match on the node's CURRENT shape (Nots
/// intact — this is what makes parent rows match before children
/// linearize away the evidence).
fn match_node(e: &Expr) -> Option<Expr> {
    let (op, a, b) = match e {
        Expr::And(x, y) => ("and", x.as_ref(), Some(y.as_ref())),
        Expr::Or(x, y) => ("or", x.as_ref(), Some(y.as_ref())),
        Expr::Xor(x, y) => ("xor", x.as_ref(), Some(y.as_ref())),
        Expr::Not(x) => ("not", x.as_ref(), None),
        _ => return None,
    };
    table2(op, a, b)
}

/// Table-2 substitution for a single bitwise node whose operands are
/// variables or negated variables. Returns the linear replacement, or
/// `None` when not Table-2 shaped (driver recurses into operands first).
fn table2(op: &str, a: &Expr, b: Option<&Expr>) -> Option<Expr> {
    if op == "not" {
        return match a {
            // ~v -> -v-1 ; double negation handled by demorgan pass
            Expr::Var(_) | Expr::Const(_) => {
                Some(e_sub(e_neg(a.clone()), ONE))
            }
            // ~(x&y) -> -(x&y)-1
            Expr::And(x, y) => match (x.as_ref(), y.as_ref()) {
                (Expr::Var(_), Expr::Var(_)) => {
                    Some(e_sub(e_neg(a.clone()), ONE))
                }
                _ => None,
            },
            // ~(x|y) -> -x-y+(x&y)-1
            Expr::Or(x, y) => match (x.as_ref(), y.as_ref()) {
                (Expr::Var(xn), Expr::Var(yn)) => {
                    let xv = var(xn);
                    let yv = var(yn);
                    Some(e_sub(
                        e_sub(e_sub(e_neg(xv.clone()), yv.clone()), ONE),
                        e_neg(e_and(xv, yv)),
                    ))
                }
                _ => None,
            },
            // ~(x^y) -> -x-y+2(x&y)-1
            Expr::Xor(x, y) => match (x.as_ref(), y.as_ref()) {
                (Expr::Var(xn), Expr::Var(yn)) => {
                    let xv = var(xn);
                    let yv = var(yn);
                    Some(e_sub(
                        e_sub(e_sub(e_neg(xv.clone()), yv.clone()), ONE),
                        e_neg(e_mul(Expr::Const(2), e_and(xv, yv))),
                    ))
                }
                _ => None,
            },
            _ => None,
        };
    }
    let bb = b?;
    let (ai, an) = unnot(a);
    let (bi, bn) = unnot(bb);
    let (xn, yn) = match (ai, bi) {
        (Expr::Var(x), Expr::Var(y)) => (x.clone(), y.clone()),
        _ => return None,
    };
    let xv = var(&xn);
    let yv = var(&yn);
    let xy = e_and(xv.clone(), yv.clone());
    let two_xy = e_mul(Expr::Const(2), xy.clone());
    Some(match (op, an, bn) {
        // x&y | x&~y = x-(x&y) | ~x&y = y-(x&y) | ~x&~y = ~(x|y)
        ("and", false, false) => xy.clone(),
        ("and", false, true) => e_sub(xv.clone(), xy.clone()),
        ("and", true, false) => e_sub(yv.clone(), xy.clone()),
        ("and", true, true) => e_sub(
            e_sub(e_sub(e_neg(xv.clone()), yv.clone()), ONE),
            e_neg(xy.clone()),
        ),
        // x|y = x+y-(x&y) | x|~y = -y+(x&y)-1 | ~x|y = -x+(x&y)-1
        // ~x|~y = ~(x&y)
        ("or", false, false) => e_sub(e_add(xv.clone(), yv.clone()), xy.clone()),
        ("or", false, true) => e_sub(e_sub(e_neg(yv), ONE), e_neg(xy.clone())),
        ("or", true, false) => e_sub(e_sub(e_neg(xv), ONE), e_neg(xy.clone())),
        ("or", true, true) => e_sub(e_neg(xy), ONE),
        // x^y = x+y-2(x&y) ; x^~y and ~x^y = ~(x^y) ; ~x^~y = x^y
        ("xor", false, false) => e_sub(e_add(xv.clone(), yv.clone()), two_xy.clone()),
        ("xor", false, true) | ("xor", true, false) => e_sub(
            e_sub(e_sub(e_neg(xv), yv), ONE),
            e_neg(two_xy),
        ),
        ("xor", true, true) => e_sub(e_add(xv, yv), two_xy),
        _ => return None,
    })
}

/// Normal form: sum of monomials over atoms, coefficients wrapping.
/// Monomial key = sorted atom list; empty = constant term.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Atom {
    Var(String),
    Band(String, String),
    /// Opaque structural leaf: shifts/extends (and anything outside
    /// the linear basis), keyed by a canonical string. Never splits
    /// or combines — identical shapes cluster, nothing false merges.
    Opaque(String),
}

/// Signed view of a wrapping coefficient (for pattern matching).
fn scoeff(v: u64) -> i128 {
    if v >= (1 << 63) {
        v as i128 - (1 << 64)
    } else {
        v as i128
    }
}

/// Render a normal form deterministically (shared by Opaque keys
/// and [`cluster_key`]).
fn onf_key(nf: &BTreeMap<Vec<Atom>, u64>) -> String {
    let mut parts: Vec<String> = nf
        .iter()
        .map(|(m, c)| {
            let ms: Vec<String> = m
                .iter()
                .map(|x| match x {
                    Atom::Var(v) => format!("v:{}", v),
                    Atom::Band(x, y) => format!("b:{},{}", x, y),
                    Atom::Opaque(k) => format!("o:{}", k),
                })
                .collect();
            format!("[{}]={}", ms.join("*"), c)
        })
        .collect();
    parts.sort();
    parts.join("+")
}

/// Linear combination; `None` = not normalizable (residual bitwise
/// nodes — the driver must Table-2 replace those first).
pub fn normalize(e: &Expr) -> Option<BTreeMap<Vec<Atom>, u64>> {
    fn atom_var(n: &str) -> Vec<Atom> {
        vec![Atom::Var(n.to_string())]
    }
    match e {
        Expr::Const(v) => {
            let mut m = BTreeMap::new();
            if *v != 0 {
                m.insert(Vec::new(), *v);
            }
            Some(m)
        }
        Expr::Var(n) => {
            let mut m = BTreeMap::new();
            m.insert(atom_var(n), 1);
            Some(m)
        }
        Expr::Add(a, b) | Expr::Sub(a, b) => {
            let (mut l, r) = (normalize(a)?, normalize(b)?);
            let sub = matches!(e, Expr::Sub(..));
            for (k, v) in r {
                let c = l.get(&k).copied().unwrap_or(0);
                let nv = if sub { c.wrapping_sub(v) } else { c.wrapping_add(v) };
                if nv == 0 {
                    l.remove(&k);
                } else {
                    l.insert(k, nv);
                }
            }
            Some(l)
        }
        Expr::Mul(a, b) => {
            let (l, r) = (normalize(a)?, normalize(b)?);
            if l.len() * r.len() > 256 {
                return None; // blowup guard
            }
            let mut m = BTreeMap::new();
            for (ka, va) in &l {
                for (kb, vb) in &r {
                    let mut k = ka.clone();
                    k.extend(kb.iter().cloned());
                    k.sort();
                    let nv = m.get(&k).copied().unwrap_or(0u64).wrapping_add(va.wrapping_mul(*vb));
                    if nv == 0 {
                        m.remove(&k);
                    } else {
                        m.insert(k, nv);
                    }
                }
            }
            Some(m)
        }
        Expr::Shl(a, k) | Expr::Shru(a, k) | Expr::Sx(a, k) | Expr::Zx(a, k) => {
            let tag = match e {
                Expr::Shl(..) => "shl",
                Expr::Shru(..) => "shru",
                Expr::Sx(..) => "sx",
                _ => "zx",
            };
            // Opaque key embeds the NORMALIZED operand: identical
            // computation shapes share keys, junk-folded inner sums
            // compare equal. Non-normalizable operand -> whole None.
            let inner = normalize(a)?;
            let mut parts: Vec<String> = inner
                .iter()
                .map(|(m, c)| format!("{:?}:{}", m, c))
                .collect();
            parts.sort();
            let mut m = BTreeMap::new();
            m.insert(
                vec![Atom::Opaque(format!("{}:{}:[{}]", tag, k, parts.join(",")))],
                1,
            );
            Some(m)
        }
        // And: variable pairs become Band atoms; anything else
        // becomes an opaque structural atom (nested combines like
        // byte-assembly `(a&b)&c` keep their shape for clustering).
        Expr::And(a, b) => match (a.as_ref(), b.as_ref()) {
            (Expr::Var(x), Expr::Var(y)) => {
                let (l, r) = if x <= y {
                    (x.clone(), y.clone())
                } else {
                    (y.clone(), x.clone())
                };
                let mut m = BTreeMap::new();
                m.insert(vec![Atom::Band(l, r)], 1);
                Some(m)
            }
            _ => {
                let na = normalize(a)?;
                let nb = normalize(b)?;
                let mut m = BTreeMap::new();
                m.insert(
                    vec![Atom::Opaque(format!("and:{}:{}", onf_key(&na), onf_key(&nb)))],
                    1,
                );
                Some(m)
            }
        },
        // Opaque structural fallback: Or/Xor/Rol/Ror/Mod with
        // non-Table operands normalize to Opaque atoms keyed by
        // operator + normalized operand keys. Identical computation
        // shapes share keys (clustering); nothing combines or splits
        // (no false equivalences).
        Expr::Or(a, b) | Expr::Xor(a, b) | Expr::Rol(a, b)
        | Expr::Ror(a, b) | Expr::Mod(a, b) => {
            let op = match e {
                Expr::Or(..) => "or",
                Expr::Xor(..) => "xor",
                Expr::Rol(..) => "rol",
                Expr::Ror(..) => "ror",
                _ => "mod",
            };
            let na = normalize(a)?;
            let nb = normalize(b)?;
            let mut m = BTreeMap::new();
            m.insert(vec![Atom::Opaque(format!("{}:{}:{}", op, onf_key(&na), onf_key(&nb)))], 1);
            Some(m)
        }
        // Other bitwise nodes must be Table-2 replaced before normalizing.
        _ => None,
    }
}

/// Reverse map: normal form -> simplest bitwise/linear expression.
/// Matches Table-2 right-hand sides (up to the expression's own var
/// names, one or two vars). Returns `None` when no row matches, in
/// which case the caller keeps the linear sum as-is.
fn denormalize(nf: &BTreeMap<Vec<Atom>, u64>) -> Option<Expr> {
    let mut lin: BTreeMap<String, i128> = BTreeMap::new();
    let mut band_c: Option<(String, String, i128)> = None;
    let mut konst: i128 = 0;
    let mut other = false;
    for (k, v) in nf {
        let c = scoeff(*v);
        match k.as_slice() {
            [] => konst = konst.wrapping_add(c),
            [Atom::Var(x)] => {
                *lin.entry(x.clone()).or_insert(0) =
                    lin.get(x).copied().unwrap_or(0).wrapping_add(c)
            }
            [Atom::Band(x, y)] => {
                if band_c.is_some() {
                    other = true;
                } else {
                    band_c = Some((x.clone(), y.clone(), c));
                }
            }
            _ => other = true, // higher products: no Table row
        }
    }
    if other {
        return None;
    }
    let vars: Vec<String> = lin.keys().cloned().collect();
    let band_e = |x: &str, y: &str| e_and(var(x), var(y));
    let not_e = |e: Expr| Expr::Not(Box::new(e));
    match (vars.as_slice(), band_c, konst) {
        ([], None, c) => Some(Expr::Const(c as u64)),
        ([x], None, 0) if lin[x] == 1 => Some(var(x)),
        ([x], None, c) if lin[x] == -1 && c == -1 => Some(not_e(var(x))),
        ([x, y], None, 0) if lin[x] == 1 && lin[y] == 1 => Some(e_add(var(x), var(y))),
        ([x, y], Some((bx, by, bc)), 0)
            if lin.get(x) == Some(&1) && lin.get(y) == Some(&1) && bc == -2
                && ((bx.as_str() == x.as_str() && by.as_str() == y.as_str()) || (bx.as_str() == y.as_str() && by.as_str() == x.as_str())) =>
        {
            Some(Expr::Xor(Box::new(var(x)), Box::new(var(y))))
        }
        ([x, y], Some((bx, by, bc)), 0)
            if lin.get(x) == Some(&1) && lin.get(y) == Some(&1) && bc == -1
                && ((bx.as_str() == x.as_str() && by.as_str() == y.as_str()) || (bx.as_str() == y.as_str() && by.as_str() == x.as_str())) =>
        {
            Some(Expr::Or(Box::new(var(x)), Box::new(var(y))))
        }
        ([x], Some((bx, by, bc)), 0)
            if lin.get(x) == Some(&1) && bc == -1
                && ((bx.as_str() == x.as_str() && by.as_str() != x.as_str()) || (by.as_str() == x.as_str() && bx.as_str() != x.as_str())) =>
        {
            let other = if bx.as_str() == x.as_str() { by } else { bx };
            Some(e_and(var(x), Expr::Not(Box::new(var(&other)))))
        }
        ([y], Some((bx, by, bc)), 0)
            if lin.get(y) == Some(&1) && bc == -1
                && ((bx.as_str() == y.as_str() && by.as_str() != y.as_str()) || (by.as_str() == y.as_str() && bx.as_str() != y.as_str())) =>
        {
            let other = if bx.as_str() == y.as_str() { by } else { bx };
            Some(e_and(Expr::Not(Box::new(var(&other))), var(y)))
        }
        ([], Some((bx, by, bc)), c) if bc == -1 && c == -1 => {
            Some(not_e(band_e(&bx, &by)))
        }
        ([x], Some((bx, by, bc)), c)
            if lin.get(x) == Some(&-1) && bc == 1 && c == -1
                && ((bx.as_str() == x.as_str() && by.as_str() != x.as_str()) || (by.as_str() == x.as_str() && bx.as_str() != x.as_str())) =>
        {
            let other = if bx.as_str() == x.as_str() { by } else { bx };
            Some(Expr::Or(Box::new(not_e(var(x))), Box::new(var(&other))))
        }
        ([y], Some((bx, by, bc)), c)
            if lin.get(y) == Some(&-1) && bc == 1 && c == -1
                && ((bx.as_str() == y.as_str() && by.as_str() != y.as_str()) || (by.as_str() == y.as_str() && bx.as_str() != y.as_str())) =>
        {
            let other = if bx.as_str() == y.as_str() { by } else { bx };
            Some(Expr::Or(Box::new(var(&other)), Box::new(not_e(var(y)))))
        }
        ([x, y], Some((bx, by, bc)), c)
            if lin.get(x) == Some(&-1) && lin.get(y) == Some(&-1) && c == -1
                && ((bx.as_str() == x.as_str() && by.as_str() == y.as_str()) || (bx.as_str() == y.as_str() && by.as_str() == x.as_str())) =>
        {
            if bc == 1 {
                Some(not_e(Expr::Or(Box::new(var(x)), Box::new(var(y)))))
            } else if bc == 2 {
                Some(not_e(Expr::Xor(Box::new(var(x)), Box::new(var(y)))))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Translate a byte-chain op list to an [`Expr`] (rotation-free subset).
/// `ops`: (op-name, imm) with names Xor/Add/Sub/Neg/Not/Inc/Dec.
/// Returns `None` for chains containing rotates, Bswap, or And
/// (outside the linear basis). Variable is always `"x"`.
pub fn from_chain(ops: &[(String, u64)]) -> Option<Expr> {
    let mut e = Expr::Var("x".to_string());
    for (op, imm) in ops {
        e = match op.as_str() {
            "Xor" => Expr::Xor(Box::new(e), Box::new(Expr::Const(*imm & 0xFF))),
            "Add" => Expr::Add(Box::new(e), Box::new(Expr::Const(*imm & 0xFF))),
            "Sub" => Expr::Sub(Box::new(e), Box::new(Expr::Const(*imm & 0xFF))),
            "Inc" => Expr::Add(Box::new(e), Box::new(Expr::Const(1))),
            "Dec" => Expr::Sub(Box::new(e), Box::new(Expr::Const(1))),
            "Neg" => Expr::Sub(Box::new(Expr::Const(0)), Box::new(e)),
            "Not" => Expr::Not(Box::new(e)),
            _ => return None,
        };
    }
    Some(e)
}
/// Bottom-up Table-2 replacement (paper's ReplaceBoolWithMBA).
/// Order matters: strip double negation, try the row on the CURRENT
/// shape first (parents before children — recursing first would
/// linearize `Not` children and destroy parent rows), recurse only
/// when no row matches, then retry on the rebuilt node.
fn replace_bool(e: &Expr) -> Expr {
    let clean = strip_double_neg(e);
    if let Some(r) = match_node(&clean) {
        return r;
    }
    let rebuilt = match &clean {
        Expr::Add(a, b) => Expr::Add(Box::new(replace_bool(a)), Box::new(replace_bool(b))),
        Expr::Sub(a, b) => Expr::Sub(Box::new(replace_bool(a)), Box::new(replace_bool(b))),
        Expr::Mul(a, b) => Expr::Mul(Box::new(replace_bool(a)), Box::new(replace_bool(b))),
        Expr::And(a, b) => Expr::And(Box::new(replace_bool(a)), Box::new(replace_bool(b))),
        Expr::Or(a, b) => Expr::Or(Box::new(replace_bool(a)), Box::new(replace_bool(b))),
        Expr::Xor(a, b) => Expr::Xor(Box::new(replace_bool(a)), Box::new(replace_bool(b))),
        Expr::Not(a) => Expr::Not(Box::new(replace_bool(a))),
        Expr::Shl(a, k) => Expr::Shl(Box::new(replace_bool(a)), *k),
        Expr::Shru(a, k) => Expr::Shru(Box::new(replace_bool(a)), *k),
        Expr::Sx(a, k) => Expr::Sx(Box::new(replace_bool(a)), *k),
        Expr::Zx(a, k) => Expr::Zx(Box::new(replace_bool(a)), *k),
        Expr::Rol(a, b) => Expr::Rol(Box::new(replace_bool(a)), Box::new(replace_bool(b))),
        Expr::Ror(a, b) => Expr::Ror(Box::new(replace_bool(a)), Box::new(replace_bool(b))),
        Expr::Mod(a, b) => Expr::Mod(Box::new(replace_bool(a)), Box::new(replace_bool(b))),
        leaf => return leaf.clone(),
    };
    match_node(&rebuilt).unwrap_or(rebuilt)
}

/// Simplify per MBA-Blast Algorithm 1: replace bitwise by Table 2,
/// arithmetically reduce, map back to bitwise when simpler.
/// Iterates while the node count drops (cap 32 rounds).
pub fn simplify(e: &Expr) -> Expr {
    let mut cur = e.clone();
    for _ in 0..32 {
        let lin = replace_bool(&cur);
        let next = match normalize(&lin) {
            Some(nf) => {
                // from_normal fabricates zeros for Opaque leaves: it is
                // clustering display only, NEVER a simplification result.
                let has_opaque = nf.keys().any(|k| {
                    k.iter().any(|a| matches!(a, Atom::Opaque(_)))
                });
                let back = if has_opaque {
                    None
                } else {
                    Some(denormalize(&nf).unwrap_or_else(|| from_normal(&nf)))
                };
                match back {
                    Some(b) if b.nodes() < cur.nodes() => b,
                    _ => {
                        if lin.nodes() < cur.nodes() {
                            lin
                        } else {
                            cur.clone()
                        }
                    }
                }
            }
            None => {
                if lin.nodes() < cur.nodes() {
                    lin
                } else {
                    cur.clone()
                }
            }
        };
        if next.nodes() >= cur.nodes() {
            return cur;
        }
        cur = next;
    }
    cur
}

/// Rebuild a linear sum expression from a normal form (fallback when
/// no Table-2 row matches: the sum itself is the simple form).
fn from_normal(nf: &BTreeMap<Vec<Atom>, u64>) -> Expr {
    let mut acc: Option<Expr> = None;
    let atom_e = |a: &Atom| -> Expr {
        match a {
            Atom::Var(x) => var(x),
            Atom::Band(x, y) => e_and(var(x), var(y)),
            // Opaque leaves cannot rebuild (key only); emit 0 so the
            // sum stays shape-honest without inventing semantics.
            // NOTE: from_normal output with Opaque is for CLUSTERING,
            // never for equivalence claims.
            Atom::Opaque(_) => Expr::Const(0),
        }
    };
    // Deterministic order: consts last (matches paper's -c4 shape).
    let mut keys: Vec<&Vec<Atom>> = nf.keys().collect();
    keys.sort_by_key(|k| (k.is_empty(), format!("{:?}", k)));
    for k in keys {
        let c = scoeff(nf[k]);
        if c == 0 {
            continue;
        }
        let mut term: Option<Expr> = None;
        for a in k {
            term = Some(match term {
                None => atom_e(a),
                Some(t) => e_mul(t, atom_e(a)),
            });
        }
        // Negative coefficients fold into one wrapped constant factor.
        let te = match term {
            None => Expr::Const(c as u64),
            Some(t) if c == 1 => t,
            Some(t) => e_mul(Expr::Const(c as u64), t),
        };
        acc = Some(match acc {
            None => te,
            Some(a) => e_add(a, te),
        });
    }
    acc.unwrap_or(Expr::Const(0))
}

/// Proof-grade result: `Proven`/`Refuted` come from exact normal
/// forms; `TestedOnly` from deterministic input testing; `Unknown`
/// from internal guards. Callers must never present `TestedOnly` as
/// proof — the type makes the confusion a compile-time decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofResult {
    Proven,
    Refuted,
    TestedOnly(bool),
    Unknown,
}

/// Unified check: exact path first, tested path labeled as such.
pub fn check(a: &Expr, b: &Expr) -> ProofResult {
    if let Some(exact) = equiv_exact(a, b) {
        return if exact { ProofResult::Proven } else { ProofResult::Refuted };
    }
    match equiv(a, b) {
        Some(v) => ProofResult::TestedOnly(v),
        None => ProofResult::Unknown,
    }
}

/// Exact-only equivalence: `Some(true/false)` when the difference
/// normalizes after Table-2 replacement, `None` when it does not
/// (residual bitwise — caller must fall back to testing, never claim).
pub fn equiv_exact(a: &Expr, b: &Expr) -> Option<bool> {
    let diff = Expr::Sub(Box::new(a.clone()), Box::new(b.clone()));
    let lin = replace_bool(&diff);
    if lin.is_mba() {
        return None;
    }
    normalize(&lin).map(|nf| nf.is_empty())
}

/// Equivalence: exact when the difference normalizes to zero after
/// Table-2 replacement, otherwise deterministic random testing.
/// Returns `Some(true/false)`; `None` only on internal blowup guard.
pub fn equiv(a: &Expr, b: &Expr) -> Option<bool> {    let mut varset = std::collections::BTreeSet::new();
    fn walk(e: &Expr, v: &mut std::collections::BTreeSet<String>) {
        match e {
            Expr::Var(x) => {
                v.insert(x.clone());
            }
            Expr::Add(x, y) | Expr::Sub(x, y) | Expr::Mul(x, y)
            | Expr::And(x, y) | Expr::Or(x, y) | Expr::Xor(x, y) => {
                walk(x, v);
                walk(y, v);
            }
            Expr::Not(x) | Expr::Shl(x, _) | Expr::Shru(x, _) | Expr::Sx(x, _) | Expr::Zx(x, _) => walk(x, v),
            Expr::Rol(x, y) | Expr::Ror(x, y) | Expr::Mod(x, y) => {
                walk(x, v);
                walk(y, v);
            }
            Expr::Const(_) => {}
        }
    }
    walk(a, &mut varset);
    walk(b, &mut varset);
    let vars: Vec<String> = varset.into_iter().collect();
    // Exact path: replace bitwise, then normalize the difference.
    let diff = Expr::Sub(Box::new(a.clone()), Box::new(b.clone()));
    let lin = replace_bool(&diff);
    if !lin.is_mba() {
        if let Some(nf) = normalize(&lin) {
            return Some(nf.is_empty());
        }
    }
    // Tested path: deterministic inputs (LCG + edge values).
    let mut x: u64 = 0x9E3779B97F4A7C15;
    let mut inputs: Vec<u64> = vec![0, 1, 2, 0xFF, 0xFFFF, u64::MAX, 0x8000_0000_0000_0000];
    for _ in 0..57 {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        inputs.push(x);
    }
    let grid: Vec<Vec<u64>> = if vars.len() >= 2 {
        inputs
            .iter()
            .flat_map(|p| inputs.iter().map(move |q| vec![*p, *q]))
            .take(4096)
            .collect()
    } else {
        inputs.iter().map(|p| vec![*p]).collect()
    };
    for g in &grid {
        let env: BTreeMap<String, u64> = vars
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let val = if i < g.len() {
                    g[i]
                } else {
                    0x12345678 + i as u64
                };
                (v.clone(), val)
            })
            .collect();
        if a.eval(&env) != b.eval(&env) {
            return Some(false);
        }
    }
    // Tested-equal (high-confidence, not proof). The exact path above
    // is proof; callers needing proof must ensure inputs normalize.
    Some(true)
}

/// Canonical clustering key: normalized form rendered
/// deterministically (consts kept — callers abstract them when they
/// want family grouping; keys with Opaque leaves group structure).
pub fn cluster_key(e: &Expr) -> Option<String> {
    let lin = replace_bool(e);
    let nf = normalize(&lin)?;
    let mut parts: Vec<String> = nf
        .iter()
        .map(|(m, c)| {
            let ms: Vec<String> = m
                .iter()
                .map(|a| match a {
                    Atom::Var(x) => format!("v:{}", x),
                    Atom::Band(x, y) => format!("b:{},{}", x, y),
                    Atom::Opaque(k) => format!("o:{}", k),
                })
                .collect();
            format!("[{}]={}", ms.join("*"), c)
        })
        .collect();
    parts.sort();
    Some(parts.join("+"))
}

/// Parse prefix S-expressions: `(add x 3)`, `(and x y)`, `(not x)`,
/// `(shl x 8)`, `(shru x 1)`, `(sx x 4)`, bare vars, decimal/0x consts.
pub fn parse_sexpr(s: &str) -> Option<Expr> {
    fn tok(s: &str, p: &mut usize) -> Option<String> {
        let b = s.as_bytes();
        while *p < b.len() && (b[*p] == b' ' || b[*p] == b'\t' || b[*p] == b'\n') {
            *p += 1;
        }
        if *p >= b.len() {
            return None;
        }
        if b[*p] == b'(' || b[*p] == b')' {
            let t = (b[*p] as char).to_string();
            *p += 1;
            return Some(t);
        }
        let st = *p;
        while *p < b.len() && !b" \t\n()".contains(&b[*p]) {
            *p += 1;
        }
        Some(s[st..*p].to_string())
    }
    fn num(t: &str) -> Option<u64> {
        if let Some(h) = t.strip_prefix("0x") {
            u64::from_str_radix(h, 16).ok()
        } else {
            t.parse::<u64>().ok().or_else(|| t.parse::<i64>().ok().map(|v| v as u64))
        }
    }
    fn expr(s: &str, p: &mut usize) -> Option<Expr> {
        match tok(s, p)?.as_str() {
            "(" => {
                let op = tok(s, p)?;
                let mut args = Vec::new();
                loop {
                    let save = *p;
                    match tok(s, p) {
                        Some(t) if t == ")" => break,
                        Some(_) => {
                            *p = save;
                            args.push(expr(s, p)?);
                        }
                        None => return None,
                    }
                }
                let mut mkbin = |f: fn(Box<Expr>, Box<Expr>) -> Expr| -> Option<Expr> {
                    if args.len() == 2 {
                        let b = args.pop().unwrap();
                        let a = args.pop().unwrap();
                        Some(f(Box::new(a), Box::new(b)))
                    } else {
                        None
                    }
                };
                match op.as_str() {
                    "add" => mkbin(Expr::Add),
                    "sub" => mkbin(Expr::Sub),
                    "mul" => mkbin(Expr::Mul),
                    "and" => mkbin(Expr::And),
                    "or" => mkbin(Expr::Or),
                    "xor" => mkbin(Expr::Xor),
                    "not" if args.len() == 1 => {
                        Some(Expr::Not(Box::new(args.pop().unwrap())))
                    }
                    "shl" | "shru" | "sx" | "zx" if args.len() == 2 => {
                        let a = args.remove(0);
                        match args.pop().unwrap() {
                            Expr::Const(k) => {
                                let f = match op.as_str() {
                                    "shl" => Expr::Shl as fn(Box<Expr>, u32) -> Expr,
                                    "shru" => Expr::Shru as fn(Box<Expr>, u32) -> Expr,
                                    "sx" => Expr::Sx as fn(Box<Expr>, u32) -> Expr,
                                    _ => Expr::Zx as fn(Box<Expr>, u32) -> Expr,
                                };
                                Some(f(Box::new(a), k as u32))
                            }
                            _ => None,
                        }
                    }
                    _ => None,
                }
            }
            ")" => None,
            t => Some(num(t).map(Expr::Const).unwrap_or_else(|| var(t))),
        }
    }
    let mut p = 0;
    expr(s, &mut p)
}

/// Render back to S-expr (inverse of [`parse_sexpr`]).
pub fn render(e: &Expr) -> String {
    match e {
        Expr::Const(v) => format!("{}", v),
        Expr::Var(x) => x.clone(),
        Expr::Add(a, b) => format!("(add {} {})", render(a), render(b)),
        Expr::Sub(a, b) => format!("(sub {} {})", render(a), render(b)),
        Expr::Mul(a, b) => format!("(mul {} {})", render(a), render(b)),
        Expr::And(a, b) => format!("(and {} {})", render(a), render(b)),
        Expr::Or(a, b) => format!("(or {} {})", render(a), render(b)),
        Expr::Xor(a, b) => format!("(xor {} {})", render(a), render(b)),
        Expr::Not(a) => format!("(not {})", render(a)),
        Expr::Shl(a, k) => format!("(shl {} {})", render(a), k),
        Expr::Shru(a, k) => format!("(shru {} {})", render(a), k),
        Expr::Sx(a, k) => format!("(sx {} {})", render(a), k),
        Expr::Zx(a, k) => format!("(zx {} {})", render(a), k),
        Expr::Rol(a, b) => format!("(rol {} {})", render(a), render(b)),
        Expr::Ror(a, b) => format!("(ror {} {})", render(a), render(b)),
        Expr::Mod(a, b) => format!("(mod {} {})", render(a), render(b)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic 64-value input stream (LCG + edges).
    fn vals() -> Vec<u64> {
        let mut v = vec![0, 1, 2, 0xFF, 0xFFFF, u64::MAX, 0x8000_0000_0000_0000];
        let mut x: u64 = 0x9E3779B97F4A7C15;
        for _ in 0..57 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            v.push(x);
        }
        v
    }

    fn env2(x: u64, y: u64) -> BTreeMap<String, u64> {
        BTreeMap::from([("x".to_string(), x), ("y".to_string(), y)])
    }

    fn check_pair(a: &Expr, b: &Expr) {
        for vx in vals() {
            for vy in vals().iter().take(8) {
                let e = env2(vx, *vy);
                assert_eq!(a.eval(&e), b.eval(&e), "mismatch at x={:#x} y={:#x}", vx, vy);
            }
        }
    }

    #[test]
    fn table2_rows_hold() {
        let x = var("x");
        let y = var("y");
        let nx = Expr::Not(Box::new(x.clone()));
        let ny = Expr::Not(Box::new(y.clone()));
        // (pattern, table2(op, a, b)) checked by evaluation
        let patterns: Vec<Expr> = vec![
            Expr::Xor(Box::new(x.clone()), Box::new(y.clone())),
            Expr::Or(Box::new(x.clone()), Box::new(y.clone())),
            Expr::And(Box::new(x.clone()), Box::new(ny.clone())),
            Expr::And(Box::new(nx.clone()), Box::new(y.clone())),
            Expr::Or(Box::new(x.clone()), Box::new(ny.clone())),
            Expr::Or(Box::new(nx.clone()), Box::new(y.clone())),
            Expr::Xor(Box::new(x.clone()), Box::new(ny.clone())),
            Expr::Not(Box::new(Expr::And(Box::new(x.clone()), Box::new(y.clone())))),
            Expr::Not(Box::new(Expr::Or(Box::new(x.clone()), Box::new(y.clone())))),
            Expr::Not(Box::new(Expr::Xor(Box::new(x.clone()), Box::new(y.clone())))),
            Expr::Not(Box::new(x.clone())),
            Expr::Or(Box::new(nx.clone()), Box::new(ny.clone())),
            Expr::And(Box::new(nx.clone()), Box::new(ny.clone())),
        ];
        for p in &patterns {
            let lin = replace_bool(p);
            assert!(!lin.is_mba(), "residual bitwise in {:?}", p);
            check_pair(p, &lin);
        }
    }

    #[test]
    fn paper_example_collapses() {
        // §5.1: 2(x|y) - (~x&y) - (x&~y) === x+y
        let x = var("x");
        let y = var("y");
        let nx = Expr::Not(Box::new(x.clone()));
        let ny = Expr::Not(Box::new(y.clone()));
        let or = Expr::Or(Box::new(x.clone()), Box::new(y.clone()));
        let t1 = Expr::And(Box::new(nx), Box::new(y.clone()));
        let t2 = Expr::And(Box::new(x.clone()), Box::new(ny));
        let e = Expr::Sub(
            Box::new(Expr::Sub(
                Box::new(Expr::Mul(Box::new(Expr::Const(2)), Box::new(or))),
                Box::new(t1),
            )),
            Box::new(t2),
        );
        let target = Expr::Add(Box::new(x.clone()), Box::new(y.clone()));
        assert_eq!(equiv(&e, &target), Some(true));
        let s = simplify(&e);
        assert!(s.nodes() <= target.nodes() + 2, "nodes={} expr={:?}", s.nodes(), s);
        assert_eq!(equiv(&s, &target), Some(true));
    }

    #[test]
    fn demorgan_pair_shrinks() {
        // ~x|~y (5 nodes) -> ~(x&y) (4 nodes)
        let x = var("x");
        let y = var("y");
        let e = Expr::Or(
            Box::new(Expr::Not(Box::new(x))),
            Box::new(Expr::Not(Box::new(y))),
        );
        let n0 = e.nodes();
        let s = simplify(&e);
        assert!(s.nodes() < n0, "{} !< {}", s.nodes(), n0);
    }

    #[test]
    fn equiv_says_no() {
        let x = var("x");
        let y = var("y");
        let or = Expr::Or(Box::new(x.clone()), Box::new(y.clone()));
        let xor = Expr::Xor(Box::new(x.clone()), Box::new(y.clone()));
        assert_eq!(equiv(&or, &xor), Some(false));
    }

    #[test]
    fn chain_neg_not_is_dec() {
        // Miner discovery (gate-zero: Neg->Not == Dec), now PROVED
        // instead of pair-tested.
        let e = from_chain(&[("Neg".to_string(), 0), ("Not".to_string(), 0)]).unwrap();
        let d = from_chain(&[("Dec".to_string(), 0)]).unwrap();
        assert_eq!(equiv(&e, &d), Some(true));
        let s = simplify(&e);
        assert!(s.nodes() <= 4, "nodes={} expr={:?}", s.nodes(), s);
        assert_eq!(equiv(&s, &d), Some(true));
    }

    #[test]
    fn chain_with_rotate_declines() {
        // Rotates are outside the linear basis: honest None, not garbage.
        assert!(from_chain(&[("Ror".to_string(), 1)]).is_none());
        assert!(from_chain(&[("And".to_string(), 0xFF)]).is_none());
    }

    #[test]
    fn sexpr_roundtrip_and_key() {
        let e = parse_sexpr("(add x (mul 2 (and x y)))").unwrap();
        assert_eq!(render(&e), "(add x (mul 2 (and x y)))");
        // x + 2(x&y): normalizes, key stable across renames is caller's job
        let k = cluster_key(&e).unwrap();
        assert!(k.contains("v:x") && k.contains("b:x,y"));
        // junk folds: (add x 0) keys like x
        let j = parse_sexpr("(add x 0)").unwrap();
        assert_eq!(cluster_key(&j).unwrap(), cluster_key(&var("x")).unwrap());
    }
}
