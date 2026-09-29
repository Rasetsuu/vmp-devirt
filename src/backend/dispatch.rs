//! Indirect-dispatch tables from execution traces.
//!
//! A VM dispatcher is an indirect jump (`jmp reg`) whose successor set is
//! the handler table. This module extracts observed successor sets from a
//! trace; the caller decides which VAs are indirect jumps (via static
//! disasm or live snapshots). Union across traces = complete observed table.

use std::collections::{BTreeMap, BTreeSet};

/// Map every `site` VA to its observed successor set in `trace`.
pub fn dispatch_tables(trace: &[u64], is_site: &dyn Fn(u64) -> bool) -> BTreeMap<u64, BTreeSet<u64>> {
    let mut out: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for w in trace.windows(2) {
        if is_site(w[0]) {
            out.entry(w[0]).or_default().insert(w[1]);
        }
    }
    out
}

/// Union tables across traces.
pub fn union_tables(tables: &[BTreeMap<u64, BTreeSet<u64>>]) -> BTreeMap<u64, BTreeSet<u64>> {
    let mut out: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for t in tables {
        for (k, v) in t {
            out.entry(*k).or_default().extend(v.iter().cloned());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finds_two_way_dispatch() {
        let trace = vec![0x100u64, 0x200, 0x300, 0x200, 0x400, 0x200, 0x300];
        let is_site = |a: u64| a == 0x200;
        let t = dispatch_tables(&trace, &is_site);
        assert_eq!(t[&0x200].len(), 2);
        assert!(t[&0x200].contains(&0x300));
        assert!(t[&0x200].contains(&0x400));
    }
    #[test]
    fn union_merges() {
        let mut a = BTreeMap::new();
        a.insert(1u64, BTreeSet::from([2u64]));
        let mut b = BTreeMap::new();
        b.insert(1u64, BTreeSet::from([3u64]));
        let u = union_tables(&[a, b]);
        assert_eq!(u[&1].len(), 2);
    }
}
