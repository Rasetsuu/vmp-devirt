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
    /// And-mix schedules append '&' plus the co-byte source is recorded
    /// separately (e.g. key "r9b&" with aux_src "rsi+2").
    pub key_reg: String,
    /// Co-byte load source for and-mix schedules ("base+disp"), if found.
    pub aux_src: Option<String>,
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
/// Direct calls are followed one level (call-hidden cryptors, 3.9.4).
/// Unconditional jmp/ret ends a path (terminal dispatch).
/// `read` supplies bytes for any VA — file bytes, or a snapshot
/// overlay for runtime-decrypted regions (protector-grade targets).
pub fn mine_cryptor_with(
    site: &FetchSite,
    read: &dyn Fn(u64, usize) -> Option<Vec<u8>>,
) -> Result<MinedCryptor> {
    use std::collections::HashSet;
    let dst8 = low8_of(site.dst);
    let mut cryptor = ValueCryptor::new(CryptSize::Byte);
    let mut key_reg = String::new();
    let mut steps = 0usize;
    let mut found_key_mix = false;
    let mut visited: HashSet<u64> = HashSet::new();
    // (ip, call_depth): follow direct calls once (call-hidden cryptors).
    // loads: last mem-load source per destination reg name (co-bytes).
    let mut loads: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut aux_src: Option<String> = None;
    let mut worklist = vec![(site.va, 0u8)];
    let mut total = 0usize;
    while let Some((mut ip, depth)) = worklist.pop() {
        if !visited.insert(ip) { continue; }
        let code = match read(ip, 128) {
            Some(b) => b,
            None => continue,
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
            if first {
                first = false;
                // Skip a leading fetch (movzx/movsx) only; chain-start
                // sites (xor dst,key) must be processed, not skipped.
                if ins.mnemonic() == Mnemonic::Movzx || ins.mnemonic() == Mnemonic::Movsx {
                    continue;
                }
            }
            if first_in_path { first_in_path = false; } // path-start IP is in visited by construction
            else if !visited.insert(ins.ip()) { break; } // loop guard
            match ins.mnemonic() {
                Mnemonic::Ret => break, // terminal dispatch
                Mnemonic::Jmp => {
                    // Chain bridge (like jcc splits and call-hidden
                    // cryptors): follow direct jumps once; true terminal
                    // dispatch jumps land in code with no dst8 chain ops
                    // and simply yield nothing further.
                    if depth < 1 && ins.op_count() == 1 && ins.op0_kind() == OpKind::NearBranch64 {
                        let tgt = ins.near_branch_target();
                        if tgt != 0 && !visited.contains(&tgt) {
                            worklist.push((tgt, depth + 1));
                        }
                    }
                    break;
                }
                Mnemonic::Call => {
                    // Call-hidden cryptor (3.9.4): follow one level.
                    if depth < 1 && ins.op_count() == 1 && ins.op0_kind() == OpKind::NearBranch64 {
                        let tgt = ins.near_branch_target();
                        if tgt != 0 && !visited.contains(&tgt) {
                            worklist.push((tgt, depth + 1));
                        }
                    }
                    break;
                }
                // Track byte/word loads per destination reg: co-byte
                // sources for and-mix schedules (e.g. mov r9b,[rsi+2]).
                Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx => {
                    if ins.op_count() == 2 && ins.op0_kind() == OpKind::Register
                        && ins.op1_kind() == OpKind::Memory
                    {
                        let base = ins.memory_base();
                        let disp = ins.memory_displacement64() as i64;
                        let idx = ins.memory_index();
                        if base != Register::None && base != Register::RIP {
                            let src = if idx != Register::None {
                                format!("{:?}+{:?}*{} {:+}",
                                        base, idx, ins.memory_index_scale(),
                                        disp).to_lowercase()
                            } else {
                                format!("{:?} {:+}", base, disp).to_lowercase()
                            };
                            loads.insert(reg_name(ins.op0_register()), src);
                        }
                    }
                }
                _ if ins.is_jcc_short_or_near() => {
                    let tgt = ins.near_branch_target();
                    if tgt != 0 && !visited.contains(&tgt) { worklist.push((tgt, depth)); }
                    // continue fall-through inline
                }
                Mnemonic::Xor | Mnemonic::Add | Mnemonic::Sub | Mnemonic::Rol | Mnemonic::Ror
                | Mnemonic::Inc | Mnemonic::Dec | Mnemonic::Neg | Mnemonic::Not | Mnemonic::And => {
                    if ins.op_count() < 1 || ins.op0_kind() != OpKind::Register { continue; }
                    if ins.op0_register() != dst8 { continue; }
                    match ins.mnemonic() {
                        Mnemonic::Xor if !found_key_mix && ins.op_count() == 2 && ins.op1_kind() == OpKind::Register => {
                            key_reg = reg_name(ins.op1_register());
                            found_key_mix = true;
                        }
                        // And-mix schedules (e.g. NOR `~B0 & ~B1`): second
                        // register is a co-key, not the classic xor key.
                        // Record its load source for co-byte decode.
                        Mnemonic::And if ins.op_count() == 2 && ins.op1_kind() == OpKind::Register => {
                            let co = reg_name(ins.op1_register());
                            if key_reg.is_empty() {
                                key_reg = format!("{}&", co);
                                aux_src = loads.get(&co).cloned();
                            }
                            found_key_mix = true;
                        }
                        Mnemonic::Xor => { cryptor.add(CryptOp::Xor, ins.immediate8() as u64); steps += 1; }
                        Mnemonic::Add => { cryptor.add(CryptOp::Add, ins.immediate8() as u64); steps += 1; }
                        Mnemonic::Sub => { cryptor.add(CryptOp::Sub, ins.immediate8() as u64); steps += 1; }
                        Mnemonic::And => { cryptor.add(CryptOp::And, ins.immediate8() as u64); steps += 1; }
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
    Ok(MinedCryptor { site_va: site.va, cryptor, key_reg, aux_src, steps })
}

/// File-backed mining (static bytes). For runtime-decrypted regions use
/// [`mine_cryptor_with`] with a snapshot overlay reader.
pub fn mine_cryptor(site: &FetchSite, binary: &crate::pe_loader::PEBinary) -> Result<MinedCryptor> {
    mine_cryptor_with(site, &|va, n| binary.read_bytes(va, n).ok())
}

impl MinedCryptor {
    /// `opcode = cryptor.encrypt(raw ^ key)` — byte-xor model only.
    /// Sites with `&`-suffixed key regs (and-mix schedules) report shape;
    /// their decode needs the co-byte and is NOT covered here.
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

    /// Byte overlay reader over a (base, bytes) image for synthetic tests.
    /// Returns whatever bytes are available (short reads OK — decoder
    /// stops at the end, mirroring a mapped-region edge).
    fn overlay_reader(image: &[(u64, Vec<u8>)]) -> impl Fn(u64, usize) -> Option<Vec<u8>> + '_ {
        move |va, n| {
            for (base, data) in image {
                if va >= *base && (va - base) < data.len() as u64 {
                    let o = (va - base) as usize;
                    let end = (o + n).min(data.len());
                    return Some(data[o..end].to_vec());
                }
            }
            None
        }
    }

    #[test]
    fn follows_call_hidden_cryptor_one_level() {
        // movzx eax,[rcx]; call next; [target:] xor al,bl; not al; ret.
        let base = 0x1000u64;
        let code: Vec<u8> = vec![
            0x0F, 0xB6, 0x01, // movzx eax, byte [rcx]
            0xE8, 0x00, 0x00, 0x00, 0x00, // call 0x1008
            0x30, 0xD8, // xor al, bl
            0xF6, 0xD0, // not al
            0xC3, // ret
        ];
        let image = vec![(base, code)];
        let site = FetchSite { va: base, base: Register::RCX, dst: Register::EAX, len: 3 };
        let m = mine_cryptor_with(&site, &overlay_reader(&image)).unwrap();
        assert_eq!(m.key_reg, "bl");
        assert_eq!(m.steps, 1, "steps={}", m.steps);
        // decode(raw,key) = not(raw ^ key)
        assert_eq!(m.decode(0x3e, 0xf6), !(0x3e ^ 0xf6));
    }

    #[test]
    fn mines_chain_start_site_without_fetch() {
        // Site points directly at xor (no leading movzx): must not skip it.
        let base = 0x2000u64;
        let code: Vec<u8> = vec![
            0x30, 0xD8, // xor al, bl
            0xFE, 0xC0, // inc al
            0xC3, // ret
        ];
        let image = vec![(base, code)];
        let site = FetchSite { va: base, base: Register::RCX, dst: Register::EAX, len: 0 };
        let m = mine_cryptor_with(&site, &overlay_reader(&image)).unwrap();
        assert_eq!(m.key_reg, "bl");
        assert_eq!(m.steps, 1);
    }

    #[test]
    fn mines_rbx_family_matching_hardcoded() {        // Hardcoded oracle vectors from site_emulator tests.
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
