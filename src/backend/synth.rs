//! Enumerative synthesizer for byte-chain semantics (idea: Souper-lite).
//!
//! The rule miner reads CODE; synthesis reads BEHAVIOR: given I/O pairs,
//! search program skeletons over the chain alphabet and solve immediates
//! by brute force with early pruning. First match in simplicity order
//! (shorter first) wins.
//!
//! Current role: independent cross-validator for mined chains (two
//! methods agreeing beats one), and readiness for output oracles that
//! rule mining cannot use (call-hidden bodies). Fetch-opcode outputs
//! are unobserved in traces, so live-pair application waits on
//! dispatch-target labels (queued); synthetic pairs gate correctness.
use crate::backend::value_cryptor::{CryptOp, CryptSize, ValueCryptor};

/// One input/output example: (input byte, expected output byte).
#[derive(Debug, Clone, Copy)]
pub struct IoPair {
    pub input: u8,
    pub output: u8,
}

const SKEL_OPS: &[CryptOp] = &[
    CryptOp::Xor,
    CryptOp::Add,
    CryptOp::Sub,
    CryptOp::Rol,
    CryptOp::Ror,
    CryptOp::Inc,
    CryptOp::Dec,
    CryptOp::Neg,
    CryptOp::Not,
];

/// Solve immediates for a fixed skeleton against pairs.
/// Domains are tight: rotate amounts only 0..=7 are distinct on bytes;
/// wide immediates (Xor/Add/Sub) search 0..=255, capped at 2 positions
/// (mined 3.9 chains carry <=2; keys come from registers, and more
/// needs pair-guided solving, queued).
fn solve_skeleton(skel: &[CryptOp], pairs: &[IoPair]) -> Option<ValueCryptor> {
    let mut chain = ValueCryptor::new(CryptSize::Byte);
    for op in skel {
        chain.add(*op, 0);
    }
    // (position, domain-max): amounts 0..=7, wide imms 0..=255
    let doms: Vec<(usize, u64)> = skel
        .iter()
        .enumerate()
        .filter_map(|(i, op)| match op {
            CryptOp::Rol | CryptOp::Ror => Some((i, 7)),
            CryptOp::Xor | CryptOp::Add | CryptOp::Sub => Some((i, 255)),
            _ => None,
        })
        .collect();
    if doms.iter().filter(|(_, m)| *m == 255).count() > 2 {
        return None;
    }
    // recursive brute force with fail-fast pair checking
    fn rec(chain: &mut ValueCryptor, doms: &[(usize, u64)], pairs: &[IoPair]) -> bool {
        if doms.is_empty() {
            return pairs.iter().all(|p| chain.encrypt(p.input as u64) as u8 == p.output);
        }
        let (idx, maxv) = doms[0];
        for v in 0..=maxv {
            chain.cmds[idx].value = v;
            if rec(chain, &doms[1..], pairs) {
                return true;
            }
        }
        false
    }
    if rec(&mut chain, &doms, pairs) {
        Some(chain)
    } else {
        None
    }
}

/// Canonical simplifier for linear chains, adapted from the VTIL
/// Project's table-driven rules (`VTIL-SymEx/simplifier/directives.hpp`,
/// BSD-3-Clause, (c) 2020 Can Bölük). VTIL's rules target binary
/// expression trees; chains here are unary pipelines, so only the
/// linear subset ports: double-inverse cancel, identity drop, adjacent
/// same-family folding, and the Neg/Not pair identities
/// (`-(~A)=A+1`, `~(-A)=A-1`). No reordering across families
/// (rotates/arithmetic do not commute). Fixed-point, bounded.
/// Returns an equivalent chain with minimal op count.
pub fn simplify_chain(chain: &ValueCryptor) -> ValueCryptor {
    let (mask, bits) = match chain.size {
        CryptSize::Byte => (0xFFu64, 8u32),
        CryptSize::Word => (0xFFFFu64, 16u32),
        CryptSize::DWord => (0xFFFF_FFFFu64, 32u32),
        CryptSize::QWord => (0xFFFF_FFFF_FFFF_FFFFu64, 64u32),
    };
    // Work on (op, value) pairs; fixed ops carry 0.
    let mut ops: Vec<(CryptOp, u64)> =
        chain.cmds.iter().map(|c| (c.op, c.value & mask)).collect();
    for _ in 0..16 {
        let mut out: Vec<(CryptOp, u64)> = Vec::with_capacity(ops.len());
        let mut changed = false;
        let mut i = 0;
        while i < ops.len() {
            // Two-op peephole on (ops[i], ops[i+1]).
            if i + 1 < ops.len() {
                let (a, av) = ops[i];
                let (b, bv) = ops[i + 1];
                // Double-inverse cancel (VTIL: -(-A)=A, ~(~A)=A).
                if (a == CryptOp::Neg && b == CryptOp::Neg)
                    || (a == CryptOp::Not && b == CryptOp::Not)
                    || (a == CryptOp::Inc && b == CryptOp::Dec)
                    || (a == CryptOp::Dec && b == CryptOp::Inc)
                {
                    changed = true;
                    i += 2;
                    continue;
                }
                // Neg/Not pairs (VTIL: -(~A)=A+1, ~(-A)=A-1).
                if a == CryptOp::Neg && b == CryptOp::Not {
                    changed = true;
                    out.push((CryptOp::Dec, 0));
                    i += 2;
                    continue;
                }
                if a == CryptOp::Not && b == CryptOp::Neg {
                    changed = true;
                    out.push((CryptOp::Inc, 0));
                    i += 2;
                    continue;
                }
                // Same-family Xor fold (VTIL identity A^0=A, const A^A=0).
                if a == CryptOp::Xor && b == CryptOp::Xor {
                    changed = true;
                    let v = (av ^ bv) & mask;
                    if v != 0 {
                        out.push((CryptOp::Xor, v));
                    }
                    i += 2;
                    continue;
                }
                // Add/Sub/Inc/Dec net folding (VTIL: A+0=A, A+(-B)=A-B).
                if matches!(a, CryptOp::Add | CryptOp::Sub | CryptOp::Inc | CryptOp::Dec)
                    && matches!(b, CryptOp::Add | CryptOp::Sub | CryptOp::Inc | CryptOp::Dec)
                {
                    changed = true;
                    let to_signed = |o: CryptOp, v: u64| -> i64 {
                        match o {
                            CryptOp::Add => (v & mask) as i64,
                            CryptOp::Inc => 1,
                            CryptOp::Sub => -((v & mask) as i64),
                            _ => -1, // Dec
                        }
                    };
                    let net = to_signed(a, av) + to_signed(b, bv);
                    let m = mask as i64 + 1;
                    let net = ((net % m) + m) % m;
                    if net != 0 {
                        if net == mask as i64 {
                            out.push((CryptOp::Dec, 0));
                        } else {
                            out.push((CryptOp::Add, net as u64));
                        }
                    }
                    i += 2;
                    continue;
                }
                // Rotate merge (VTIL: rot-count modulo width).
                if matches!(a, CryptOp::Rol | CryptOp::Ror)
                    && matches!(b, CryptOp::Rol | CryptOp::Ror)
                {
                    changed = true;
                    let signed = |o: CryptOp, v: u64| -> i64 {
                        let r = ((v & 0xFF) % bits as u64) as i64;
                        if o == CryptOp::Rol { r } else { -r }
                    };
                    let net = signed(a, av) + signed(b, bv);
                    let net = ((net % bits as i64) + bits as i64) % bits as i64;
                    if net != 0 {
                        out.push((CryptOp::Rol, net as u64));
                    }
                    i += 2;
                    continue;
                }
            }
            // Single-op identities (VTIL: A^0=A, rotl(A,0)=A).
            let (a, av) = ops[i];
            match a {
                CryptOp::Xor | CryptOp::Add | CryptOp::Sub if av & mask == 0 => {
                    changed = true;
                }
                CryptOp::Rol | CryptOp::Ror if av % bits as u64 == 0 => {
                    changed = true;
                }
                _ => out.push((a, av)),
            }
            i += 1;
        }
        ops = out;
        if !changed {
            break;
        }
    }
    let mut c = ValueCryptor::new(chain.size);
    for (op, v) in ops {
        c.add(op, v);
    }
    c
}

/// Synthesize the simplest chain (up to `max_len` ops) matching all pairs.
/// Budget-bounded: at most `budget` skeleton evaluations, then None.
/// Pass `budget = usize::MAX` for exhaustive (may hang on long chains).
pub fn synthesize_budget(
    pairs: &[IoPair], max_len: usize, budget: usize,
) -> Option<ValueCryptor> {
    if pairs.is_empty() {
        return None;
    }
    let mut spent = 0usize;
    for len in 0..=max_len {
        if len == 0 {
            let id = ValueCryptor::new(CryptSize::Byte);
            if pairs.iter().all(|p| p.input == p.output) {
                return Some(id);
            }
            continue;
        }
        let total = SKEL_OPS.len().pow(len as u32);
        for n in 0..total {
            if spent >= budget {
                return None;
            }
            spent += 1;
            let mut skel = Vec::with_capacity(len);
            let mut x = n;
            for _ in 0..len {
                skel.push(SKEL_OPS[x % SKEL_OPS.len()]);
                x /= SKEL_OPS.len();
            }
            if let Some(c) = solve_skeleton(&skel, pairs) {
                return Some(c);
            }
        }
    }
    None
}

/// Synthesize the simplest chain (up to `max_len` ops) matching all pairs.
/// Returns None when nothing matches within budget.
pub fn synthesize(pairs: &[IoPair], max_len: usize) -> Option<ValueCryptor> {
    synthesize_budget(pairs, max_len, usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs_of(chain: &ValueCryptor, inputs: &[u8]) -> Vec<IoPair> {
        inputs
            .iter()
            .map(|b| IoPair { input: *b, output: chain.encrypt(*b as u64) as u8 })
            .collect()
    }

    #[test]
    fn rederives_known_chain() {
        // Gate zero: miner's Neg->Not->Neg->Ror1 (0x140eb8c73, key=dil)
        // from I/O pairs alone — no code reading.
        let mut known = ValueCryptor::new(CryptSize::Byte);
        known.add(CryptOp::Neg, 0);
        known.add(CryptOp::Not, 0);
        known.add(CryptOp::Neg, 0);
        known.add(CryptOp::Ror, 1);
        let pairs = pairs_of(&known, &[0x00, 0x3e, 0x42, 0x80, 0xc8, 0xff, 0x11, 0x77]);
        let got = synthesize(&pairs, 4).expect("should synthesize");
        // Simplest equivalent wins: may compress (e.g. Neg->Not == Dec),
        // so assert semantics + bound, not textual identity.
        assert!(got.cmds.len() <= 4);
        // semantic equivalence on fresh inputs (skeleton may differ textually)
        for b in [0x01u8, 0x5a, 0xa5, 0xde] {
            assert_eq!(got.encrypt(b as u64), known.encrypt(b as u64));
        }
    }

    #[test]
    fn prefers_simplest() {
        // identity
        let pairs: Vec<IoPair> = (0u8..=15).map(|b| IoPair { input: b, output: b }).collect();
        let got = synthesize(&pairs, 4).expect("identity");
        assert_eq!(got.cmds.len(), 0);
    }

    #[test]
    fn empty_pairs_none() {
        assert!(synthesize(&[], 4).is_none());
    }

    fn chain_of(ops: &[(CryptOp, u64)]) -> ValueCryptor {
        let mut c = ValueCryptor::new(CryptSize::Byte);
        for (op, v) in ops {
            c.add(*op, *v);
        }
        c
    }

    fn equiv(a: &ValueCryptor, b: &ValueCryptor) -> bool {
        (0..=255u64).all(|x| a.encrypt(x) == b.encrypt(x))
    }

    #[test]
    fn vtil_subset_rules() {
        // Double-inverse cancel.
        for (ops, want_len) in [
            (&[(CryptOp::Neg, 0), (CryptOp::Neg, 0)][..], 0),
            (&[(CryptOp::Not, 0), (CryptOp::Not, 0)][..], 0),
            (&[(CryptOp::Inc, 0), (CryptOp::Dec, 0)][..], 0),
            // Neg/Not identities.
            (&[(CryptOp::Neg, 0), (CryptOp::Not, 0)][..], 1),
            (&[(CryptOp::Not, 0), (CryptOp::Neg, 0)][..], 1),
            // Same-family folds.
            (&[(CryptOp::Xor, 0x12), (CryptOp::Xor, 0x34)][..], 1),
            (&[(CryptOp::Xor, 0x42), (CryptOp::Xor, 0x42)][..], 0),
            (&[(CryptOp::Add, 10), (CryptOp::Add, 20)][..], 1),
            (&[(CryptOp::Add, 10), (CryptOp::Sub, 10)][..], 0),
            (&[(CryptOp::Rol, 3), (CryptOp::Rol, 5)][..], 0), // 3+5=8=0 mod 8
            (&[(CryptOp::Rol, 3), (CryptOp::Ror, 3)][..], 0),
        ] {
            let c = chain_of(ops);
            let s = simplify_chain(&c);
            assert_eq!(s.cmds.len(), want_len, "ops={ops:?} got={:?}", s.cmds);
            assert!(equiv(&c, &s), "semantics changed for {ops:?}");
        }
        // Neg->Not spells Dec; Not->Neg spells Inc.
        let dec = chain_of(&[(CryptOp::Dec, 0)]);
        assert!(equiv(&chain_of(&[(CryptOp::Neg, 0), (CryptOp::Not, 0)]), &dec));
        let inc = chain_of(&[(CryptOp::Inc, 0)]);
        assert!(equiv(&chain_of(&[(CryptOp::Not, 0), (CryptOp::Neg, 0)]), &inc));
        // Full-exhaustive equivalence on a mixed chain.
        let mixed = chain_of(&[
            (CryptOp::Xor, 0x5a),
            (CryptOp::Xor, 0x5a),
            (CryptOp::Neg, 0),
            (CryptOp::Neg, 0),
            (CryptOp::Add, 7),
            (CryptOp::Sub, 7),
            (CryptOp::Rol, 2),
            (CryptOp::Ror, 2),
        ]);
        assert_eq!(simplify_chain(&mixed).cmds.len(), 0);
    }
}
