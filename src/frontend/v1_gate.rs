//! v1 gate front-end: PUSH imm + CALL dispatch (VMP 1.x, 32/64-bit).
//!
//! VMP 1.x protects via gate stubs that push a value and call into the VM.
//! This front-end scans executable sections for gate-shaped sequences and
//! reports their addresses as fetch points. Full VIP decoding lives behind
//! execution (see harness); statically we return gate locations.
use anyhow::Result;
use crate::frontend::{FetchHit, VmFrontend};
use crate::pe_loader::PEBinary;
use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};

pub struct V1Gate;

/// Candidate gate: push imm32/64 followed closely by a near call.
pub fn scan_gates(data: &[u8], image_base: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 6 < data.len() {
        let mut d = Decoder::with_ip(64, &data[off..], image_base + off as u64, DecoderOptions::NONE);
        let ins = d.decode();
        let len = ins.len().max(1);
        if ins.mnemonic() == Mnemonic::Push
            && (ins.op0_kind() == OpKind::Immediate32 || ins.op0_kind() == OpKind::Immediate64)
        {
            let mut d2 = Decoder::with_ip(64, &data[off + len..], image_base + off as u64 + len as u64, DecoderOptions::NONE);
            for _ in 0..4 {
                if !d2.can_decode() {
                    break;
                }
                let nx = d2.decode();
                if nx.mnemonic() == Mnemonic::Call && nx.op0_kind() == OpKind::NearBranch64 {
                    out.push(image_base + off as u64);
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

impl VmFrontend for V1Gate {
    fn name(&self) -> &'static str {
        "vmp1-gate"
    }
    fn detect(&self, binary: &PEBinary) -> Result<bool> {
        let pe = binary.parse_manual()?;
        for s in &pe.sections {
            if !s.name_lossy.to_lowercase().starts_with(".vmp") {
                continue;
            }
            let sz = s.raw_size as usize;
            if sz == 0 {
                continue;
            }
            let off = s.raw_ptr as usize;
            let end = off.saturating_add(sz).min(binary.data.len());
            if off < end && !scan_gates(&binary.data[off..end], pe.image_base + s.rva as u64).is_empty() {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn fetch_stream(&self, _binary: &PEBinary, _trace: Option<&[u64]>) -> Result<Vec<FetchHit>> {
        // Gate targets resolve at runtime; static front-end reports no hits.
        Ok(Vec::new())
    }
    fn handler_addrs(&self, binary: &PEBinary, _hits: &[FetchHit]) -> Result<Vec<u64>> {
        let pe = binary.parse_manual()?;
        let mut out = Vec::new();
        for s in &pe.sections {
            if !s.name_lossy.to_lowercase().starts_with(".vmp") {
                continue;
            }
            let sz = s.raw_size as usize;
            if sz == 0 {
                continue;
            }
            let off = s.raw_ptr as usize;
            let end = off.saturating_add(sz).min(binary.data.len());
            if off < end {
                out.extend(scan_gates(&binary.data[off..end], pe.image_base + s.rva as u64));
            }
        }
        Ok(out)
    }
}
