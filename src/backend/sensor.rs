//! Behavior sensor + adapter selection: version-agnostic fetch discovery.
//!
//! Instead of matching opcode shapes (movzx...), score blocks by *behavior*
//! measured in traces: execution periodicity, advancing data reads, RMW
//! accumulator traffic, and dispatch control flow. The winner selects the
//! miner config (inline / call-hidden / memory-loop cryptor).
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Per-block behavior features.
#[derive(Debug, Clone, Default)]
pub struct BlockFeatures {
    pub va: u64,
    pub exec_count: usize,
    /// Distinct data (non-stack, non-image-code) addresses read.
    pub data_reads: usize,
    /// Max read address - min read address (stream span) for data reads.
    pub read_span: u64,
    /// RMW pairs (same addr read+written).
    pub rmw: usize,
    /// Ends with control flow (from disasm, set by caller).
    pub has_cf: bool,
    pub score: f64,
}

/// Score blocks. `trace` = executed RIPs in order; `reads`/`writes` =
/// (rip, addr) pairs; `is_stack`, `is_code` classify addresses.
/// NOTE: this ranks dispatch/handler centrality (hot + dataful blocks),
/// not rare fetch sites (low counts by nature). Fetch discovery stays
/// miner (disasm shape) + watch (execution confirmation); the auto-adapter
/// chains all three: sense -> mine -> watch-confirm.
pub fn sense(
    trace: &[u64],
    reads: &[(u64, u64)],
    writes: &[(u64, u64)],
    is_stack: &dyn Fn(u64) -> bool,
    is_code: &dyn Fn(u64) -> bool,
) -> Vec<BlockFeatures> {
    // Block split: backward edge or forward gap > 16.
    let mut blocks: Vec<u64> = Vec::new();
    let mut prev = 0u64;
    for a in trace {
        if prev == 0 || *a < prev || *a - prev > 16 {
            blocks.push(*a);
        }
        prev = *a;
    }
    let mut counts: HashMap<u64, usize> = HashMap::new();
    for b in &blocks {
        *counts.entry(*b).or_insert(0) += 1;
    }
    let mut rmap: HashMap<u64, Vec<u64>> = HashMap::new();
    for (rip, addr) in reads {
        rmap.entry(*rip).or_default().push(*addr);
    }
    let mut wset: HashMap<u64, BTreeSet<u64>> = HashMap::new();
    for (rip, addr) in writes {
        wset.entry(*rip).or_default().insert(*addr);
    }
    // Attribute reads/writes to nearest block start (<= rip, within 64B).
    let mut starts: Vec<u64> = counts.keys().cloned().collect();
    starts.sort();
    let at_block = |rip: u64| -> Option<u64> {
        let mut best = None;
        for b in starts.iter() {
            if *b <= rip && rip - *b < 64 {
                best = Some(*b);
            } else if *b > rip {
                break;
            }
        }
        best
    };
    let mut data_reads: HashMap<u64, BTreeSet<u64>> = HashMap::new();
    let mut data_writes: HashMap<u64, BTreeSet<u64>> = HashMap::new();
    for (rip, addr) in reads {
        if is_stack(*addr) || is_code(*addr) {
            continue;
        }
        if let Some(b) = at_block(*rip) {
            data_reads.entry(b).or_default().insert(*addr);
        }
    }
    for (rip, addr) in writes {
        if is_stack(*addr) || is_code(*addr) {
            continue;
        }
        if let Some(b) = at_block(*rip) {
            data_writes.entry(b).or_default().insert(*addr);
        }
    }
    let mut feat = Vec::new();
    for (va, n) in counts {
        let r_addrs: BTreeSet<u64> = data_reads.get(&va).cloned().unwrap_or_default();
        let w_addrs: BTreeSet<u64> = data_writes.get(&va).cloned().unwrap_or_default();
        let span = r_addrs.iter().max().unwrap_or(&0).saturating_sub(*r_addrs.iter().min().unwrap_or(&u64::MAX));
        let rmw = r_addrs.intersection(&w_addrs).count();
        feat.push(BlockFeatures {
            va,
            exec_count: n,
            data_reads: r_addrs.len(),
            read_span: span,
            rmw,
            has_cf: false,
            score: 0.0,
        });
    }
    // Score: periodic + data + span + RMW accumulator.
    let max_n = feat.iter().map(|f| f.exec_count).max().unwrap_or(1) as f64;
    for f in feat.iter_mut() {
        f.score = (f.exec_count as f64 / max_n) * 0.4
            + (f.data_reads.min(8) as f64 / 8.0) * 0.2
            + ((f.read_span.min(0x10000) as f64) / 0x10000 as f64) * 0.1
            + ((f.rmw.min(4) as f64) / 4.0) * 0.3;
    }
    feat.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
    feat
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sense_ranks_periodic_rmw_first() {
        // Two alternating blocks; second does RMW on advancing data. It wins.
        let mut trace = Vec::new();
        for _ in 0..50 {
            trace.extend([0x1000u64, 0x1004, 0x2000, 0x2004]);
        }
        let mut reads = Vec::new();
        let mut writes = Vec::new();
        for i in 0..50u64 {
            reads.push((0x1004, 0x600000 + i));
            reads.push((0x2004, 0x500000 + i * 4));
            writes.push((0x2004, 0x500000 + i * 4));
        }
        let is_stack = |a: u64| (a & 0xFFF00000) == 0x7FF00000;
        let is_code = |a: u64| a >= 0x1000 && a < 0x3000;
        let f = sense(&trace, &reads, &writes, &is_stack, &is_code);
        assert!(f.len() >= 2);
        assert_eq!(f[0].va, 0x2000);
        assert!(f[0].rmw >= 1);
    }
}
