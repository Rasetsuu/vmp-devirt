//! Front-ends: per-VMP-version fetch-stream discovery.
//!
//! Every front-end emits the same contract — a decoded fetch stream plus
//! handler addresses — into the shared backend. Static where sufficient,
//! execution-assisted where the VM hides state (3.x FDJ, packed code).

pub mod fetch_finder;
pub mod cryptor_miner;
pub mod site_emulator;
pub mod handler_classifier;
pub mod classifier_legacy;
pub mod v1_gate;
pub mod v2_walker;
pub mod v3_fdj;
pub mod tigress;

use anyhow::Result;
use crate::pe_loader::PEBinary;

/// One decoded VM fetch: where, what byte/key, what opcode.
#[derive(Debug, Clone)]
pub struct FetchHit {
    pub site_va: u64,
    pub raw: u8,
    pub key: u8,
    pub opcode: u8,
}

/// Version front-end contract.
pub trait VmFrontend: Send + Sync {
    /// Human name, e.g. "vmp2-table", "vmp3-fdj".
    fn name(&self) -> &'static str;
    /// True if this front-end applies to the binary.
    fn detect(&self, binary: &PEBinary) -> Result<bool>;
    /// Decode the fetch stream. `trace` optionally carries an executed
    /// address trace (dynamic mode); `None` means static-only.
    fn fetch_stream(&self, binary: &PEBinary, trace: Option<&[u64]>) -> Result<Vec<FetchHit>>;
    /// Handler code addresses referenced by the stream.
    fn handler_addrs(&self, binary: &PEBinary, hits: &[FetchHit]) -> Result<Vec<u64>>;
}
