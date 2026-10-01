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
}
