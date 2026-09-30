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

fn needs_imm(op: CryptOp) -> bool {
    matches!(op, CryptOp::Xor | CryptOp::Add | CryptOp::Sub | CryptOp::Rol | CryptOp::Ror)
}

/// Solve immediates for a fixed skeleton against pairs.
/// v1 cap: at most ONE imm position searched exhaustively (256 tries).
/// Skeletons needing more are skipped (documented limit — mined 3.9
/// chains carry 0-1 immediates plus fixed ops; keys come from registers,
/// and k>=2 needs pair-guided solving, queued).
fn solve_skeleton(skel: &[CryptOp], pairs: &[IoPair]) -> Option<ValueCryptor> {
    let mut chain = ValueCryptor::new(CryptSize::Byte);
    for op in skel {
        chain.add(*op, 0);
    }
    let poss: Vec<usize> = skel
        .iter()
        .enumerate()
        .filter(|(_, op)| needs_imm(**op))
        .map(|(i, _)| i)
        .collect();
    if poss.len() > 1 {
        return None;
    }
    // recursive brute force with fail-fast pair checking
    fn rec(chain: &mut ValueCryptor, poss: &[usize], pairs: &[IoPair]) -> bool {
        if poss.is_empty() {
            return pairs.iter().all(|p| chain.encrypt(p.input as u64) as u8 == p.output);
        }
        let idx = poss[0];
        for v in 0..=255u64 {
            chain.cmds[idx].value = v;
            if rec(chain, &poss[1..], pairs) {
                return true;
            }
        }
        false
    }
    if rec(&mut chain, &poss, pairs) {
        Some(chain)
    } else {
        None
    }
}

/// Synthesize the simplest chain (up to `max_len` ops) matching all pairs.
/// Returns None when nothing matches within budget.
pub fn synthesize(pairs: &[IoPair], max_len: usize) -> Option<ValueCryptor> {
    if pairs.is_empty() {
        return None;
    }
    // breadth-first over lengths: simplest first; skeletons per
    // length enumerated as base-|SKEL_OPS| counter (no wrap bugs).
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
