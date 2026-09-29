//! Handler Detector (VMPredator §III step 2, adapted).
//!
//! Version-agnostic handler boundaries from traces, no fetch patterns:
//! a virtual instruction handler must persist its result into the virtual
//! context (rsp-relative stack range), so stack writes are result-stores;
//! back-slicing in the trace from each result-store to the most recently
//! preceding indirect jump yields one handler block. Indirect jumps bound
//! blocks; the dispatcher's own edges are found by `dispatch.rs` from the
//! other direction — the two cross-validate.

use std::collections::{BTreeMap, BTreeSet};

/// One detected handler block: indirect-jump site through result store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerBlock {
    /// VA of the bounding indirect jump (block start).
    pub start: u64,
    /// Number of stack stores observed inside (across executions).
    pub stores: BTreeSet<u64>,
    /// Execution count (jump-to-jump segments opened at `start`).
    pub executions: usize,
}

/// Detect handler blocks (paper §III step 2: jump-to-jump segments).
///
/// `trace` = executed RIPs in order; `writes` = (rip, addr) stack-region
/// data writes; `is_indirect_jmp` classifies a VA (via disasm). Each
/// trace segment opened by an indirect jump is one handler execution;
/// segments sharing `start` merge store sets and execution counts.
pub fn detect_handlers(
    trace: &[u64],
    writes: &[(u64, u64)],
    is_indirect_jmp: &dyn Fn(u64) -> bool,
) -> Vec<HandlerBlock> {
    let mut by_rip: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for (rip, addr) in writes {
        by_rip.entry(*rip).or_default().push(*addr);
    }
    let mut blocks: BTreeMap<u64, HandlerBlock> = BTreeMap::new();
    let mut cur: Option<u64> = None;
    let mut cur_stores: BTreeSet<u64> = BTreeSet::new();
    let mut flush = |start: Option<u64>, stores: &BTreeSet<u64>, blocks: &mut BTreeMap<u64, HandlerBlock>| {
        if let Some(s) = start {
            let e = blocks.entry(s).or_insert(HandlerBlock { start: s, stores: BTreeSet::new(), executions: 0 });
            e.executions += 1;
            e.stores.extend(stores.iter().cloned());
        }
    };
    for a in trace {
        if is_indirect_jmp(*a) {
            flush(cur, &cur_stores, &mut blocks);
            cur = Some(*a);
            cur_stores.clear();
        }
        if cur.is_some() {
            if let Some(addrs) = by_rip.get(a) {
                cur_stores.extend(addrs.iter().cloned());
            }
        }
    }
    flush(cur, &cur_stores, &mut blocks);
    blocks.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn slices_store_to_preceding_indirect_jump() {
        // trace: jmp, a, b(store), c, jmp, d(store2)
        let trace = vec![0x100u64, 0x104, 0x108, 0x10c, 0x100, 0x110];
        let writes = vec![(0x108u64, 0x7ff0u64), (0x110u64, 0x7ff8u64)];
        let is_jmp = |a: u64| a == 0x100;
        let b = detect_handlers(&trace, &writes, &is_jmp);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].start, 0x100);
        assert_eq!(b[0].executions, 2);
        assert!(b[0].stores.contains(&0x7ff0));
        assert!(b[0].stores.contains(&0x7ff8));
    }
    #[test]
    fn store_without_preceding_jump_is_dropped() {
        let trace = vec![0x104u64, 0x108];
        let writes = vec![(0x108u64, 0x7ff0u64)];
        let is_jmp = |_: u64| false;
        assert!(detect_handlers(&trace, &writes, &is_jmp).is_empty());
    }
}
