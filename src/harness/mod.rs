//! Harness: instrumented execution snapshots (Unicorn).
//!
//! Maps a binary's sections (+scratch), applies caller-provided register
//! state and hooks (I/O traps, import stubs, fault logging), and records
//! executed addresses + memory traffic for the front-ends to consume.

pub mod snapshot;
