//! Back-end: version-agnostic lifting and analysis.
//!
//! Takes fetch streams + handler addresses from any front-end and produces
//! LLVM IR, semantic cards, dataflow listings, and native objects.

pub mod value_cryptor;
pub mod lifter;
pub mod llvm_pipeline;
pub mod dataflow;
pub mod merge;
pub mod sensor;
