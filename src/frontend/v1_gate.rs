//! v1 gate front-end: PUSH imm + CALL dispatch (VMP 1.x, 32/64-bit).
//!
//! VMP 1.x protects via gate stubs that push a value and call into the VM.
//! This front-end scans executable sections for gate-shaped sequences and
//! reports their addresses as fetch points. Full VIP decoding lives behind
//! execution (see harness); statically we return gate locations.
use anyhow::Result;
use crate::frontend::{FetchHit, VmFrontend};
use crate::pe_loader::{vm_candidate_sections, PEBinary};
use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};

pub struct V1Gate;

/// VM address ranges (VA start, VA end) from candidate sections.
fn vm_ranges(binary: &PEBinary) -> Result<Vec<(u64, u64)>> {
    let pe = binary.parse_manual()?;
    Ok(vm_candidate_sections(&pe)
        .iter()
        .map(|&i| {
            let s = &pe.sections[i];
            let start = pe.image_base + s.rva as u64;
            (start, start + s.vsize.max(s.raw_size) as u64)
        })
        .collect())
}

/// Candidate gate: push imm32/64 followed closely by a near call whose
/// target lands in a VM range. The target filter is what separates real
/// 1.x gates (`.text` stubs calling into VM sections) from ordinary
/// push-arg + call sequences (targets in `.text`).
pub fn scan_gates(data: &[u8], image_base: u64) -> Vec<u64> {
    scan_gates_into_vm(data, image_base, &[])
}

/// Target-filtered gate scan. Empty `vm` = no VM ranges known: fall back
/// to the unfiltered shape (legacy behavior) so plain-pattern callers
/// still get candidates.
pub fn scan_gates_into_vm(data: &[u8], image_base: u64, vm: &[(u64, u64)]) -> Vec<u64> {
    scan_gates_into_vm_bits(data, image_base, vm, true)
}

/// Bitness-aware gate scan. 32-bit binaries must decode as 32-bit:
/// 64-bit decode of 32-bit code fabricates push/call shapes (the
/// x32 1.7 build showed 6 phantom gates out of 7).
pub fn scan_gates_into_vm_bits(
    data: &[u8], image_base: u64, vm: &[(u64, u64)], is64: bool,
) -> Vec<u64> {
    let bits = if is64 { 64 } else { 32 };
    let in_vm = |t: u64| vm.iter().any(|(b, e)| *b <= t && t < *e);
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 6 < data.len() {
        let mut d = Decoder::with_ip(bits, &data[off..], image_base + off as u64, DecoderOptions::NONE);
        let ins = d.decode();
        let len = ins.len().max(1);
        // NOTE: `push imm32` (opcode 68) decodes as Immediate32to64 in
        // 64-bit mode; matching only Immediate32/64 misses every gate.
        if ins.mnemonic() == Mnemonic::Push
            && matches!(
                ins.op0_kind(),
                OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate32to64
            )
        {
            let mut d2 = Decoder::with_ip(bits, &data[off + len..], image_base + off as u64 + len as u64, DecoderOptions::NONE);
            for _ in 0..4 {
                if !d2.can_decode() {
                    break;
                }
                let nx = d2.decode();
                if nx.mnemonic() == Mnemonic::Call
                    && matches!(nx.op0_kind(), OpKind::NearBranch32 | OpKind::NearBranch64)
                {
                    let tgt = nx.near_branch_target();
                    if vm.is_empty() || in_vm(tgt) {
                        out.push(image_base + off as u64);
                    }
                    break;
                }
                if nx.ip() > image_base + off as u64 + 24 {
                    break;
                }
            }
        }
        off += len;
    }
    out
}

/// Gate scan over executable sections (gate stubs live in `.text`,
/// not in VM sections).
fn gates_in_exec(binary: &PEBinary, vm: &[(u64, u64)]) -> Result<Vec<u64>> {
    let pe = binary.parse_manual()?;
    let is64 = pe.is64;
    // Gate stubs live in ORIGINAL executable sections (`.text`), not in
    // VM containers: scanning VM sections yields internal push/call
    // noise (x32 1.7: 132 phantom gates inside `.vmp2`). Packed stubs
    // (no file-backed `.text`) honestly report nothing — tracing owns
    // those (32-bit tracing is still a harness gap).
    let vm_idx: std::collections::HashSet<usize> =
        crate::pe_loader::vm_candidate_sections(&pe).into_iter().collect();
    let mut out = Vec::new();
    for (i, s) in pe.sections.iter().enumerate() {
        if vm_idx.contains(&i) {
            continue;
        }
        if s.raw_size == 0 || s.chars & 0x20000000 == 0 {
            continue;
        }
        let off = s.raw_ptr as usize;
        let end = off.saturating_add(s.raw_size as usize).min(binary.data.len());
        if off < end {
            out.extend(scan_gates_into_vm_bits(
                &binary.data[off..end],
                pe.image_base + s.rva as u64,
                vm,
                is64,
            ));
        }
    }
    Ok(out)
}

impl VmFrontend for V1Gate {
    fn name(&self) -> &'static str {
        "vmp1-gate"
    }
    fn detect(&self, binary: &PEBinary) -> Result<bool> {
        let vm = vm_ranges(binary)?;
        if vm.is_empty() {
            return Ok(false);
        }
        Ok(!gates_in_exec(binary, &vm)?.is_empty())
    }
    fn fetch_stream(&self, _binary: &PEBinary, _trace: Option<&[u64]>) -> Result<Vec<FetchHit>> {
        // Gate targets resolve at runtime; static front-end reports no hits.
        Ok(Vec::new())
    }
    fn handler_addrs(&self, binary: &PEBinary, _hits: &[FetchHit]) -> Result<Vec<u64>> {
        let vm = vm_ranges(binary)?;
        gates_in_exec(binary, &vm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real 1.x gate bytes: `push 0x40017dd3; call <vm_target>`.
    fn gate_bytes(base: u64, target: u64) -> Vec<u8> {
        let mut b = vec![0x68, 0xD3, 0x7D, 0x01, 0x40]; // push imm32
        let rel = (target as i64 - (base as i64 + 10)) as i32;
        b.push(0xE8); // call rel32
        b.extend_from_slice(&rel.to_le_bytes());
        b
    }

    #[test]
    fn gate_with_vm_target_found() {
        let base = 0x1400013a0u64;
        let vm = [(0x140017000u64, 0x140018000u64)];
        let data = gate_bytes(base, 0x1400178bf);
        assert_eq!(scan_gates_into_vm(&data, base, &vm), vec![base]);
    }

    #[test]
    fn gate_with_text_target_dropped() {
        let base = 0x1400013a0u64;
        let vm = [(0x140017000u64, 0x140018000u64)];
        let data = gate_bytes(base, 0x140001500); // ordinary .text call
        assert!(scan_gates_into_vm(&data, base, &vm).is_empty());
    }

    #[test]
    fn gate_v154_detect() {
        // 1.54 factory build (local only); skip in CI without the binary.
        let path = match std::env::var("VMP_TEST_BIN_154") {
            Ok(p) => p,
            Err(_) => return,
        };
        let bin = match PEBinary::load(path) {
            Ok(b) => b,
            Err(_) => return,
        };
        assert!(V1Gate.detect(&bin).unwrap(), "v1 gate not detected");
        assert!(!V1Gate.handler_addrs(&bin, &[]).unwrap().is_empty());
    }
}
