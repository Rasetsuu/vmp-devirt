//! vmp-devirt: trace-assisted VMProtect devirtualizer (research).
//!
//! Pipeline: version front-end (fetch stream + handler addrs) -> shared
//! backend (Remill lift -> LLVM opt -> semantic cards -> dataflow -> x86).
//! See README.md for scope and limitations.

pub mod pe_loader;
pub mod opcode_map;
pub mod frontend;
pub mod backend;
pub mod harness;

/// Working-data directory (all tool artifacts). Overridable per run.
pub fn data_dir() -> String {
    std::env::var("DATA_DIR").unwrap_or_else(|_| "./data".to_string())
}
