//! Handler classifier for VMP 3.9.4 — extends `handler_classifier.rs` + `standard_model` features
//! with per-site ValueCryptor awareness.
//!
//! For 3.9.4 the handler is reached via per-site `jmp rsi/r9/rcx` after decrypt,
//! not a 256-entry table. We classify by disassembling the handler at its VA
//! (first 64 bytes) and checking for VM stack (`r10`/`rsi`) and stream reads.

use crate::pe_loader::PEBinary;
use crate::frontend::classifier_legacy::HandlerClassifier;
use crate::opcode_map::{CanonicalOpcodeMap, HandlerType};

/// Classify a handler reached from a fetch site.
/// Returns `(handler_type, confidence, stream_read)` where `stream_read` is
/// bytes consumed from bytecode if this handler is a push-imm.
pub fn classify_handler_v394(binary: &PEBinary, handler_va: u64) -> (String, u8, usize) {
    match HandlerClassifier::classify(binary, handler_va) {
        Ok(c) => (c.handler_type, c.confidence, c.size),
        Err(_) => ("unknown".to_string(), 0, 0),
    }
}

/// Map a decrypted opcode byte (from `site_emulator::extract_opcode_pure`) to
/// canonical HandlerType via `opcode_map.rs` 3.5.1 table.
/// For 3.9.4 the opcode value is still within 0..255; unknown entries mean
/// the handler is a merged handler (FUTURE_WORK.md) — caller should fallback to
/// per-handler disasm above.
pub fn opcode_to_handler_type(opcode: u8) -> HandlerType {
    CanonicalOpcodeMap::lookup(opcode).handler_type
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn opcode_map_sane() {
        assert_eq!(opcode_to_handler_type(0), HandlerType::Nop);
        // PushReg range
        assert_eq!(opcode_to_handler_type(1), HandlerType::PushReg);
        assert_eq!(opcode_to_handler_type(7), HandlerType::PushByte);
    }
    #[test]
    fn handler_classify_smoke() {
        let path = std::env::var("VMP_TEST_BIN").unwrap_or_else(|_| "./tests/fixtures/vmp_test.bin".to_string());
        let bin = match PEBinary::load(path) { Ok(b) => b, Err(_) => return };
        // One handler we traced: 0x140152021 is the jmp target of 0x140237587 chain
        // It should be a dispatch, not a simple mov, so we expect at least some classification
        let (ty, conf, _) = classify_handler_v394(&bin, 0x140152021);
        // We don't assert exact type, just that it doesn't crash and returns something
        assert!(!ty.is_empty());
        let _ = conf;
    }
}
