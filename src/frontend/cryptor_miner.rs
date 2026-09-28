//! Cryptor miner — stage 1 of real devirt.
//!
//! `site_emulator::cryptor_for_site` hardcodes chains for one binary's VAs.
//! This module derives the same `ValueCryptor` from code: decode forward from
//! the fetch `movzx`, find `xor dst8,key8`, then collect ALU ops on `dst8`
//! until control flow. Works on any VMP 3.x binary.

use anyhow::Result;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use crate::backend::value_cryptor::{ValueCryptor, CryptOp, CryptSize};
use crate::frontend::fetch_finder::FetchSite;

/// Mined per-site decryptor.
#[derive(Debug, Clone)]
pub struct MinedCryptor {
    pub site_va: u64,
    pub cryptor: ValueCryptor,
    /// Key register name (e.g. "bpl"), empty if xor-with-imm chain.
    pub key_reg: String,
    /// Number of chain ops mined (excluding the key-mix xor).
    pub steps: usize,
}

/// Low-8 register for a GPR (ESI -> SIL, R9D -> R9B, AL -> AL).
pub fn low8_of(reg: Register) -> Register {
    match reg {
        Register::RAX | Register::EAX | Register::AX | Register::AL => Register::AL,
        Register::RCX | Register::ECX | Register::CX | Register::CL => Register::CL,
        Register::RDX | Register::EDX | Register::DX | Register::DL => Register::DL,
        Register::RBX | Register::EBX | Register::BX | Register::BL => Register::BL,
        Register::RSI | Register::ESI | Register::SI | Register::SIL => Register::SIL,
        Register::RDI | Register::EDI | Register::DI | Register::DIL => Register::DIL,
        Register::RBP | Register::EBP | Register::BP | Register::BPL => Register::BPL,
        Register::RSP | Register::ESP | Register::SP | Register::SPL => Register::SPL,
        Register::R8 | Register::R8D | Register::R8W | Register::R8L => Register::R8L,
        Register::R9 | Register::R9D | Register::R9W | Register::R9L => Register::R9L,
        Register::R10 | Register::R10D | Register::R10W | Register::R10L => Register::R10L,
        Register::R11 | Register::R11D | Register::R11W | Register::R11L => Register::R11L,
        Register::R12 | Register::R12D | Register::R12W | Register::R12L => Register::R12L,
        Register::R13 | Register::R13D | Register::R13W | Register::R13L => Register::R13L,
        Register::R14 | Register::R14D | Register::R14W | Register::R14L => Register::R14L,
        Register::R15 | Register::R15D | Register::R15W | Register::R15L => Register::R15L,
        r => r,
    }
}

fn reg_name(r: Register) -> String {
    format!("{:?}", r).to_lowercase()
}

/// Mine the cryptor chain starting at the fetch site.
/// Follows conditional-branch targets (worklist) since VMP splits chains
/// across `jcc` (e.g. `0x140237587`: `not sil` lives past a `jle`).
/// Unconditional jmp/call/ret ends a path (terminal dispatch).
pub fn mine_cryptor(site: &FetchSite, binary: &crate::pe_loader::PEBinary) -> Result<MinedCryptor> {
    use std::collections::HashSet;
    let dst8 = low8_of(site.dst);
    let mut cryptor = ValueCryptor::new(CryptSize::Byte);
    let mut key_reg = String::new();
    let mut steps = 0usize;
    let mut found_key_mix = false;
    let mut visited: HashSet<u64> = HashSet::new();
    let mut worklist = vec![site.va];
    let mut total = 0usize;
    while let Some(mut ip) = worklist.pop() {
        if !visited.insert(ip) { continue; }
        let code = match binary.read_bytes(ip, 128) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let mut decoder = Decoder::with_ip(64, &code, ip, DecoderOptions::NONE);
        let dump = std::env::var("MINER_DUMP").is_ok();
        let mut first = ip == site.va;
        let mut first_in_path = true;
        while decoder.can_decode() && total < 400 {
            let ins: Instruction = decoder.decode();
            if dump { eprintln!("  miner {:#x}: {}", ins.ip(), ins); }
            ip = decoder.ip();
            total += 1;
            if first { first = false; continue; } // skip fetch movzx
            if first_in_path { first_in_path = false; } // path-start IP is in visited by construction
            else if !visited.insert(ins.ip()) { break; } // loop guard
            match ins.mnemonic() {
                Mnemonic::Jmp | Mnemonic::Call | Mnemonic::Ret => break, // terminal dispatch
                _ if ins.is_jcc_short_or_near() => {
                    let tgt = ins.near_branch_target();
                    if tgt != 0 && !visited.contains(&tgt) { worklist.push(tgt); }
                    // continue fall-through inline
                }
                Mnemonic::Xor | Mnemonic::Add | Mnemonic::Sub | Mnemonic::Rol | Mnemonic::Ror
                | Mnemonic::Inc | Mnemonic::Dec | Mnemonic::Neg | Mnemonic::Not => {
                    if ins.op_count() < 1 || ins.op0_kind() != OpKind::Register { continue; }
                    if ins.op0_register() != dst8 { continue; }
                    match ins.mnemonic() {
                        Mnemonic::Xor if !found_key_mix && ins.op_count() == 2 && ins.op1_kind() == OpKind::Register => {
                            key_reg = reg_name(ins.op1_register());
                            found_key_mix = true;
                        }
                        Mnemonic::Xor => { cryptor.add(CryptOp::Xor, ins.immediate8() as u64); steps += 1; }
                        Mnemonic::Add => { cryptor.add(CryptOp::Add, ins.immediate8() as u64); steps += 1; }
                        Mnemonic::Sub => { cryptor.add(CryptOp::Sub, ins.immediate8() as u64); steps += 1; }
                        Mnemonic::Rol => { cryptor.add(CryptOp::Rol, ins.immediate8() as u64); steps += 1; }
                        Mnemonic::Ror => { cryptor.add(CryptOp::Ror, ins.immediate8() as u64); steps += 1; }
                        Mnemonic::Inc => { cryptor.add(CryptOp::Inc, 0); steps += 1; }
                        Mnemonic::Dec => { cryptor.add(CryptOp::Dec, 0); steps += 1; }
                        Mnemonic::Neg => { cryptor.add(CryptOp::Neg, 0); steps += 1; }
                        Mnemonic::Not => { cryptor.add(CryptOp::Not, 0); steps += 1; }
                        _ => {}
                    }
                }
                _ => {}
            }
            if steps >= 16 { break; }
        }
        if steps >= 16 { break; }
    }
    if steps == 0 && !found_key_mix {
        anyhow::bail!("no chain mined at {:#x}", site.va);
    }
    // steps==0 with key mix found = identity cryptor (opcode = raw ^ key),
    // e.g. RBX-family `movzx edx,[rbx] ... xor dl,bpl; jmp`.
    Ok(MinedCryptor { site_va: site.va, cryptor, key_reg, steps })
}

impl MinedCryptor {
    /// `opcode = cryptor.encrypt(raw ^ key)` — same contract as pure path.
    pub fn decode(&self, raw: u8, key: u8) -> u8 {
        self.cryptor.encrypt((raw ^ key) as u64) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe_loader::PEBinary;
    use crate::frontend::site_emulator::extract_opcode_pure;

    fn mine_virt_all(site_va: u64) -> Option<MinedCryptor> {
        // Needs a licensed VMP 3.9.4 sample (VMP_TEST_BIN); skipped in CI.
        // Miner logic itself is covered by tests/smoke.rs on a synthetic fixture.
        let path = std::env::var("VMP_TEST_BIN").unwrap_or_else(|_| "./tests/fixtures/vmp_test.bin".to_string());
        let bin = PEBinary::load(path).ok()?;
        let bytes = bin.read_bytes(site_va, 128).ok()?;
        // Reconstruct FetchSite: decode movzx at site for dst reg.
        let mut d = Decoder::with_ip(64, &bytes, site_va, DecoderOptions::NONE);
        let movzx = d.decode();
        if movzx.mnemonic() != Mnemonic::Movzx {
            return None;
        }
        let site = FetchSite { va: site_va, base: movzx.memory_base(), dst: movzx.op0_register(), len: movzx.len() };
        mine_cryptor(&site, &bin).ok()
    }

    #[test]
    fn mines_rbx_family_matching_hardcoded() {
        // Hardcoded oracle vectors from site_emulator tests.
        let Some(m) = mine_virt_all(0x1401989e9) else { return; };
        assert!(m.steps >= 3, "steps={}", m.steps);
        for (raw, key) in [(0x3eu8, 0xf6u8), (0x68, 0xe0), (0x20, 0x94)] {
            let expect = extract_opcode_pure(0x1401989e9, raw, key).unwrap();
            assert_eq!(m.decode(raw, key), expect, "raw {raw:#x} key {key:#x}");
        }
    }

    #[test]
    fn mines_r10_family_matching_hardcoded() {
        let Some(m) = mine_virt_all(0x140237587) else { return; };
        assert!(m.steps >= 3, "steps={}", m.steps);
        for (raw, key) in [(0x39u8, 0xfau8), (0x31, 0xf6)] {
            let expect = extract_opcode_pure(0x140237587, raw, key).unwrap();
            assert_eq!(m.decode(raw, key), expect, "raw {raw:#x} key {key:#x}");
        }
    }
}
