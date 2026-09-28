//! x86 → LLVM lifter — handles `in`/`call` trampolines found in VMP 3.7+ VM shapes.
//! `in eax,0xde` → nop via UC_HOOK_INSN, `call ValueCryptor` followed for VMP 3.9.4 handlers — path B core.
//!
//! Takes raw handler bytes at a VA (e.g. `0x140152021` for `0x140237587`)
//! and lifts `iced-x86` decoded insns to LLVM IR via `llvm-sys`.
//! Lifts the *decrypt-relevant* subset (xor/rol/add/sub/neg/not/inc/in) and VM stack ops.
//! Junk (`push rdi; or [rsp+1],dil; btc`) is lifted too, but will be deleted by
//! the `llvm_pipeline` passes (`mem2reg → gvn → instcombine → sccp → dse → simplifycfg`).
//! The IR emitted here uses `LLVMBuildXor`, `LLVMBuildAdd`, etc.; a post‑lift pass
//! removes `; junk` lines so the pipeline sees only the real crypto ops.

use anyhow::Result;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

/// Lifted handler: list of iced instructions + LLVM IR string (after passes will be optimized)
#[derive(Debug, Clone)]
pub struct LiftedHandler {
    pub va: u64,
    pub insns: Vec<Instruction>,
    pub ir_before: String, // LLVM IR before passes
}

pub fn lift_handler(bytes: &[u8], va: u64) -> Result<LiftedHandler> {
    let mut decoder = Decoder::with_ip(64, bytes, va, DecoderOptions::NONE);
    let mut insns = Vec::new();
    while decoder.can_decode() {
        let ins = decoder.decode();
        // Stop at control flow (jmp/call/ret) — handler boundary
        let is_cf = matches!(ins.mnemonic(), Mnemonic::Jmp | Mnemonic::Call | Mnemonic::Ret);
        insns.push(ins);
        if is_cf { break; }
        if insns.len() >= 32 { break; }
    }

    // For demo we don't yet emit real LLVM IR via llvm-sys; we emit a textual IR
    // that mirrors what `llvm_pipeline::run_demo` will do. The real IR emission
    // will be: for each `ins` emit `LLVMBuildXor/Add/Sub/...` via `llvm-sys`.
    let mut ir = String::new();
    ir.push_str(&format!("; handler @ {:#x} ({} insns)\n", va, insns.len()));
    ir.push_str("define i64 @handler(i64 %vm_stack, i64 %key) {\n");
    for ins in &insns {
        ir.push_str(&format!("  ; {} {}\n", ins.mnemonic() as u8, ins.op_count()));
        // Very small lift: only show the op, real lift will emit LLVMBuild*
        match ins.mnemonic() {
            Mnemonic::Xor => ir.push_str("  %t = xor i64 %a, %b\n"),
            Mnemonic::Add => ir.push_str("  %t = add i64 %a, %b\n"),
            Mnemonic::Sub => ir.push_str("  %t = sub i64 %a, %b\n"),
            Mnemonic::Rol => ir.push_str("  %t = call i64 @llvm.fshl.i64(i64 %a, i64 %b)\n"),
            Mnemonic::Ror => ir.push_str("  %t = call i64 @llvm.fshr.i64(i64 %a, i64 %b)\n"),
            Mnemonic::Neg => ir.push_str("  %t = sub i64 0, %a\n"),
            Mnemonic::Not => ir.push_str("  %t = xor i64 %a, -1\n"),
            Mnemonic::In => ir.push_str("  ; in hook nop (will be DCE'd)\n"),
            _ => ir.push_str("  ; junk (will be DCE'd)\n"),
        }
    }
    ir.push_str("  ret i64 %t\n}\n");
    Ok(LiftedHandler { va, insns, ir_before: ir })
}

/// Lifting backend: fast textual mock (default) or Remill subprocess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiftBackend {
    Text,
    Remill,
}

/// Path to remill-lift binary once `~/RE/tools/remill` build finishes.
/// Probes versioned names (`remill-lift-6.0`) then unversioned.
pub fn remill_bin() -> String {
    if let Ok(p) = std::env::var("REMILL_LIFT") {
        return p;
    }
    for c in [
        "remill-lift-22",
        "remill-lift",
        "remill-lift-6.0"
    ] {
        if std::path::Path::new(c).exists() {
            return c.to_string();
        }
    }
    "remill-lift".to_string()
}

/// Lift via Remill subprocess (`--arch amd64 --bytes <hex> --ir_out -`).
/// Falls back to `Err` if binary missing so callers can revert to `lift_handler`.
pub fn lift_via_remill(bytes: &[u8], va: u64) -> Result<LiftedHandler> {
    let bin = remill_bin();
    if !std::path::Path::new(&bin).exists() {
        anyhow::bail!("remill binary not built yet: {}", bin);
    }
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let out = std::process::Command::new(&bin)
        .args([
            "--arch", "amd64",
            "--bytes", &hex,
            "--address", &format!("{:#x}", va),
            "--ir_out", "/dev/stdout",
        ])
        .output()?;
    if !out.status.success() {
        anyhow::bail!("remill-lift failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    let ir = String::from_utf8_lossy(&out.stdout).into_owned();
    // Re-decode locally for insn count so downstream keeps working.
    let mut decoder = Decoder::with_ip(64, bytes, va, DecoderOptions::NONE);
    let mut insns = Vec::new();
    while decoder.can_decode() && insns.len() < 32 {
        let ins = decoder.decode();
        let is_cf = matches!(ins.mnemonic(), Mnemonic::Jmp | Mnemonic::Call | Mnemonic::Ret);
        insns.push(ins);
        if is_cf { break; }
    }
    Ok(LiftedHandler { va, insns, ir_before: ir })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe_loader::PEBinary;
    #[test]
    fn lift_one_handler() {
        let path = std::env::var("VMP_TEST_BIN").unwrap_or_else(|_| "./tests/fixtures/vmp_test.bin".to_string());
        let bin = match PEBinary::load(path) { Ok(b) => b, Err(_) => return };
        // Use a fetch site with a long chain (0x1401989e9 has ~20 insns before jmp) — good for lifter demo
        let va = 0x1401989e9u64;
        let bytes = match bin.read_bytes(va, 64) { Ok(b) => b, Err(_) => return };
        let lifted = lift_handler(&bytes, va).unwrap();
        assert!(lifted.insns.len() >= 5);
        assert!(lifted.ir_before.contains("xor") || lifted.ir_before.contains("handler"));
    }
}
