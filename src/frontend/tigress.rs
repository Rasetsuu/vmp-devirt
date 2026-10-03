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
