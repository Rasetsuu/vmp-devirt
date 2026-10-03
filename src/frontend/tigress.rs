//! Tigress frontend: hub-scored dispatch discovery + `_TIG_` detection.
//!
//! Paper technique donor (no vendored code): An et al., "Static
//! Detection of Core Structures in Tigress Virtualization-Based
//! Obfuscation Using an LLVM Pass" (arXiv 2601.12916v2). Their core
//! structures map to our trace domain as:
//!
//! | Paper (LLVM IR)              | Here (executed trace)                      |
//! |------------------------------|--------------------------------------------|
//! | Dispatch Start = max-successor block | hub VA = max-successor address (`hub_from_successors`) |
//! | Handler Blocks = hub successors     | handler VAs = hub successor set    |
//! | VM Start = Dispatch Start caller    | first trace predecessor of the hub |
//! | VM End = non-returning handler      | hub successor never followed by hub (trace-observed) |
//!
//! Static `detect` keys on Tigress's own `_TIG_`-prefixed symbols
//! (emitted into the ELF symtab, e.g. `_TIG_VZ_..._main_...`).
//! Handler enumeration needs a trace: static-only callers get `[]`
//! (same contract as the VMP fetch frontends).

use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};

use crate::backend::dispatch::dispatch_tables;
use crate::frontend::{FetchHit, VmFrontend};
use crate::pe_loader::{BinFmt, PEBinary};

pub struct Tigress;

/// Dispatch hub: start VA + observed successor (handler) set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TigressHub {
    /// Dispatch Start VA (max observed successors).
    pub start: u64,
    /// Handler VAs (hub successors).
    pub handlers: BTreeSet<u64>,
}

/// Hub discovery over a successor map: the VA with the most observed
/// successors wins (paper §4.2.1). Ties break toward the lower VA
/// (deterministic; logged by callers that care).
pub fn hub_from_successors(succ: &BTreeMap<u64, BTreeSet<u64>>) -> Option<TigressHub> {
    let (start, handlers) = succ.iter().max_by(|(a, sa), (b, sb)| {
        sa.len().cmp(&sb.len()).then_with(|| b.cmp(a))
    })?;
    if handlers.is_empty() {
        return None;
    }
    Some(TigressHub { start: *start, handlers: (*handlers).clone() })
}

/// Successor sets over a raw RIP trace (shared with the dispatch CLI).
pub fn successors_of(trace: &[u64]) -> BTreeMap<u64, BTreeSet<u64>> {
    let mut out: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for w in trace.windows(2) {
        out.entry(w[0]).or_default().insert(w[1]);
    }
    out
}

/// ELF function map: (name, start VA, end VA) for FUNC symbols with
/// nonzero size. Paper §4 works per-function (Dispatch Start lives
/// inside the virtualized function); trace hubs must be scoped the
/// same way or a hot program branch (e.g. `main`'s tail) wins over
/// the real dispatcher.
pub fn elf_functions(binary: &PEBinary) -> Result<Vec<(String, u64, u64)>> {
    if binary.fmt() != BinFmt::Elf {
        return Ok(Vec::new());
    }
    let elf = binary.parse_elf()?;
    let mut out = Vec::new();
    for sym in elf.syms.iter() {
        if !sym.is_function() || sym.st_size == 0 {
            continue;
        }
        let name = elf.strtab[sym.st_name].to_string();
        if name.is_empty() {
            continue;
        }
        out.push((name, sym.st_value, sym.st_value + sym.st_size));
    }
    Ok(out)
}

/// Hub scoped to one function range: max-successor site inside
/// `[start, end)`. Global hubs misfire when a program branch outside
/// the VM runs hotter than the dispatcher (tig_switch: `main`-tail
/// site beats `solo_add`'s dispatch nest).
pub fn hub_in_function(
    succ: &BTreeMap<u64, BTreeSet<u64>>,
    start: u64,
    end: u64,
) -> Option<TigressHub> {
    succ.iter()
        .filter(|(va, _)| **va >= start && **va < end)
        .max_by(|(a, sa), (b, sb)| sa.len().cmp(&sb.len()).then_with(|| b.cmp(a)))
        .and_then(|(va, handlers)| {
            if handlers.is_empty() {
                None
            } else {
                Some(TigressHub { start: *va, handlers: (*handlers).clone() })
            }
        })
}

/// Dispatch region scoped to one function: all multi-target sites in
/// `[start, end)` plus the union handler pool. Switch/ifnest
/// dispatch spreads over a ladder of 2-way branches with disjoint
/// successors (tig_switch: 6 sites, 12 handlers) — no single hub
/// covers it, so the region (not the hub) is the enumeration unit.
/// Direct/indirect/call tables collapse to a one-site region.
pub fn dispatch_region(
    succ: &BTreeMap<u64, BTreeSet<u64>>,
    start: u64,
    end: u64,
) -> (Vec<u64>, BTreeSet<u64>) {
    let mut sites: Vec<u64> = succ
        .iter()
        .filter(|(va, ss)| **va >= start && **va < end && ss.len() > 1)
        .map(|(va, _)| *va)
        .collect();
    sites.sort_unstable();
    let mut pool = BTreeSet::new();
    for va in &sites {
        if let Some(ss) = succ.get(va) {
            pool.extend(ss.iter().copied());
        }
    }
    (sites, pool)
}

/// `_TIG_`-prefixed ELF symbol names (Tigress's own markers).
pub fn tigress_symbols(binary: &PEBinary) -> Result<Vec<String>> {
    if binary.fmt() != BinFmt::Elf {
        return Ok(Vec::new());
    }
    let elf = binary.parse_elf()?;
    let mut out = Vec::new();
    for sym in elf.syms.iter() {
        let name = &elf.strtab[sym.st_name];
        if name.starts_with("_TIG_") {
            out.push(name.to_string());
        }
    }
    Ok(out)
}

impl VmFrontend for Tigress {
    fn name(&self) -> &'static str {
        "tigress-hub"
    }
    fn detect(&self, binary: &PEBinary) -> Result<bool> {
        Ok(!tigress_symbols(binary)?.is_empty())
    }
    fn fetch_stream(&self, _binary: &PEBinary, trace: Option<&[u64]>) -> Result<Vec<FetchHit>> {
        let trace = match trace {
            Some(t) => t,
            None => return Ok(Vec::new()),
        };
        let tables = dispatch_tables(trace, &|_| true);
        let succ: BTreeMap<u64, BTreeSet<u64>> = tables.into_iter().collect();
        let hub = match hub_from_successors(&succ) {
            Some(h) => h,
            None => return Ok(Vec::new()),
        };
        // Dispatch-level hits: handler VAs with undecoded payload
        // (raw/key/opcode come from handler analysis, not the hub).
        Ok(hub
            .handlers
            .into_iter()
            .map(|va| FetchHit { site_va: va, raw: 0, key: 0, opcode: 0 })
            .collect())
    }
    fn handler_addrs(&self, _binary: &PEBinary, hits: &[FetchHit]) -> Result<Vec<u64>> {
        Ok(hits.iter().map(|h| h.site_va).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hub_picks_max_successors() {
        let succ: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::from([
            (0x100u64, BTreeSet::from([0x200])),
            (0x300u64, BTreeSet::from([0x400, 0x500, 0x600])),
        ]);
        let hub = hub_from_successors(&succ).unwrap();
        assert_eq!(hub.start, 0x300);
        assert_eq!(hub.handlers.len(), 3);
    }

    #[test]
    fn hub_empty_map_is_none() {
        assert!(hub_from_successors(&BTreeMap::new()).is_none());
    }

    #[test]
    fn hub_in_function_scopes_to_range() {
        // Hot program branch outside the VM must not beat the dispatcher.
        let succ: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::from([
            (0x100u64, BTreeSet::from([0x1, 0x2, 0x3, 0x4])), // hot, outside
            (0x300u64, BTreeSet::from([0x5, 0x6])),           // dispatcher
        ]);
        // Global hub misfires (documents the failure mode).
        assert_eq!(hub_from_successors(&succ).unwrap().start, 0x100);
        // Scoped hub finds the dispatcher.
        let hub = hub_in_function(&succ, 0x300, 0x400).unwrap();
        assert_eq!(hub.start, 0x300);
        assert_eq!(hub.handlers.len(), 2);
        // Empty range is None.
        assert!(hub_in_function(&succ, 0x900, 0xA00).is_none());
    }

    #[test]
    fn region_collects_ladder() {
        // Switch nest: disjoint 2-way sites form one region.
        let succ: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::from([
            (0x300u64, BTreeSet::from([0x10, 0x11])),
            (0x310u64, BTreeSet::from([0x12, 0x13])),
            (0x320u64, BTreeSet::from([0x14])),
            (0x900u64, BTreeSet::from([0x20, 0x21])),
        ]);
        let (sites, pool) = dispatch_region(&succ, 0x300, 0x400);
        assert_eq!(sites, vec![0x300, 0x310]);
        assert_eq!(pool.len(), 4);
    }

    #[test]
    fn hub_tie_breaks_low_va() {
        let succ: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::from([
            (0x500u64, BTreeSet::from([0x1, 0x2])),
            (0x100u64, BTreeSet::from([0x3, 0x4])),
        ]);
        assert_eq!(hub_from_successors(&succ).unwrap().start, 0x100);
    }

    #[test]
    fn tigress_detect_needs_elf() {
        // TIGRESS_TEST_ELF: local Tigress-built binary; skip in CI.
        let path = match std::env::var("TIGRESS_TEST_ELF") {
            Ok(p) => p,
            Err(_) => return,
        };
        let bin = match PEBinary::load(path) {
            Ok(b) => b,
            Err(_) => return,
        };
        assert!(Tigress.detect(&bin).unwrap());
        let names = tigress_symbols(&bin).unwrap();
        assert!(!names.is_empty());
        assert!(names.iter().all(|n| n.starts_with("_TIG_")));
    }
}
