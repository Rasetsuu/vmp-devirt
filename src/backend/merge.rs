//! Multi-trace merge at virtual-branch points (vbraddrs).
//!
//! Given several execution traces over the same code, union their edges and
//! report divergence points: addresses whose successor sets differ between
//! traces. Those are the virtual-branch decisions (cf. hackyboiz vbraddr
//! method); each divergent successor set is one path condition to solve.
use std::collections::{BTreeMap, BTreeSet};

/// Edge multiset with per-trace counts: (from, to) -> counts[trace_idx].
pub fn merge_edges(traces: &[Vec<u64>]) -> BTreeMap<(u64, u64), Vec<usize>> {
    let mut map: BTreeMap<(u64, u64), Vec<usize>> = BTreeMap::new();
    for (ti, trace) in traces.iter().enumerate() {
        let mut prev: Option<u64> = None;
        for a in trace {
            if let Some(p) = prev {
                let e = map.entry((p, *a)).or_insert_with(|| vec![0; traces.len()]);
                e[ti] += 1;
            }
            prev = Some(*a);
        }
    }
    map
}

/// Addresses with >1 distinct successor across the merged traces.
pub fn divergence_points(edges: &BTreeMap<(u64, u64), Vec<usize>>) -> BTreeMap<u64, BTreeSet<u64>> {
    let mut succ: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for ((a, b), _) in edges {
        succ.entry(*a).or_default().insert(*b);
    }
    succ.into_iter().filter(|(_, s)| s.len() > 1).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn merge_finds_divergence() {
        let t1 = vec![0x100u64, 0x104, 0x108, 0x10c];
        let t2 = vec![0x100u64, 0x104, 0x200, 0x204];
        let edges = merge_edges(&[t1, t2]);
        assert_eq!(edges[&(0x100, 0x104)], vec![1, 1]);
        let div = divergence_points(&edges);
        assert_eq!(div.len(), 1);
        assert!(div[&0x104].contains(&0x108));
        assert!(div[&0x104].contains(&0x200));
    }
    #[test]
    fn merge_identical_has_no_divergence() {
        let t = vec![1u64, 2, 3];
        let div = divergence_points(&merge_edges(&[t.clone(), t]));
        assert!(div.is_empty());
    }
}
