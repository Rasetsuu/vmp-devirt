//! Slot-map dataflow: byte-granular memory model over access logs.
//!
//! Custom analysis pass (not LLVM): tracks every written byte, validates
//! every read against the last write. Feeds x86 emission with resolved
//! producer values. Replaces ad-hoc slot tracking in one-off tools.

use std::collections::HashMap;

/// One memory access: (rip, is_write, addr, size_bytes, value).
pub type Access = (u64, bool, u64, u64, u64);

#[derive(Debug, Default)]
pub struct SlotMap {
    bytes: HashMap<u64, u8>,
    pub checked: usize,
    pub mismatches: usize,
}

impl SlotMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one access; returns the previously stored value for reads.
    pub fn feed(&mut self, is_write: bool, addr: u64, size: usize, val: u64) -> Option<u64> {
        let sz = size.min(8);
        if is_write {
            for k in 0..sz {
                self.bytes.insert(addr + k as u64, ((val >> (8 * k)) & 0xFF) as u8);
            }
            None
        } else {
            let mut out = 0u64;
            let mut covered = true;
            for k in 0..sz {
                match self.bytes.get(&(addr + k as u64)) {
                    Some(b) => {
                        out |= (*b as u64) << (8 * k);
                        self.checked += 1;
                        if *b != (((val >> (8 * k)) & 0xFF) as u8) {
                            self.mismatches += 1;
                        }
                    }
                    None => covered = false,
                }
            }
            covered.then_some(out)
        }
    }

    pub fn mismatch_rate(&self) -> f64 {
        100.0 * self.mismatches as f64 / self.checked.max(1) as f64
    }
}

/// Merge-join access RIPs into trace segments (RMW-aware, bounded lookahead,
/// skips addresses never executed in trace). Returns seg id per access
/// (9999 = unattributable).
pub fn attribute_segments(
    trace: &[u64],
    fetch: &dyn Fn(u64) -> bool,
    rips: &[u64],
) -> Vec<usize> {
    let mut out = Vec::with_capacity(rips.len());
    let (mut ti, mut seg, mut prev) = (0usize, 0usize, 0u64);
    for rip in rips {
        if *rip == prev && !out.is_empty() {
            out.push(*out.last().unwrap());
            continue;
        }
        prev = *rip;
        let mut found = false;
        let end = (ti + 50000).min(trace.len());
        let mut t = ti;
        while t < end {
            if fetch(trace[t]) {
                seg += 1;
            }
            if trace[t] == *rip {
                found = true;
                ti = t + 1;
                break;
            }
            t += 1;
        }
        out.push(if found { seg } else { 9999 });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn slot_roundtrip_and_mismatch() {
        let mut m = SlotMap::new();
        m.feed(true, 0x1000, 8, 0x1122334455667788);
        assert_eq!(m.feed(false, 0x1000, 8, 0x1122334455667788), Some(0x1122334455667788));
        assert_eq!(m.checked, 8);
        assert_eq!(m.mismatches, 0);
        m.feed(false, 0x1000, 1, 0x00);
        assert_eq!(m.mismatches, 1);
    }
    #[test]
    fn attribute_rmw_pairs() {
        let trace = vec![0x100u64, 0x104, 0x108];
        let fetch = |a: u64| a == 0x108;
        // RMW pair at 0x104 shares one trace entry.
        let segs = attribute_segments(&trace, &fetch, &[0x100, 0x104, 0x104, 0x108, 0x104]);
        assert_eq!(segs, vec![0, 0, 0, 1, 1]);
    }
}
