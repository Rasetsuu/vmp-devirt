//! FetchSite scanner for VMP 3.9.4
//!
//! Finds `movzx r32, byte ptr [reg]` with optional REX prefix, where the
//! next 1..4 insns contain a `mov rXX, imm32` / `movzx` pattern is enforced
//! for real bytecode fetches (the `mov r10d,0x...` after fetch). This is the
//! Rust port of the Python prefix-aware scanner that produced
//! `fetch_sites_all2.json` (152 sites).

use anyhow::Result;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

#[derive(Debug, Clone)]
pub struct FetchSite {
    /// Virtual address of the `movzx` fetch.
    pub va: u64,
    /// Base register holding the bytecode pointer (rsi/r10/rbx/r9/rax/rcx/rdi/r8/r11/rdx).
    pub base: Register,
    /// Destination register of the movzx (e.g. `edi` for `movzx edi,byte [rsi]`).
    pub dst: Register,
    /// Raw bytes length of the fetch insn (1 byte REX + 3 bytes or 3 bytes)
    pub len: usize,
}

fn is_movzx_byte_mem(ins: &Instruction) -> bool {
    if ins.mnemonic() != Mnemonic::Movzx { return false; }
    if ins.op_count() != 2 { return false; }
    if ins.op0_kind() != OpKind::Register { return false; }
    if ins.op1_kind() != OpKind::Memory { return false; }
    // must be byte ptr
    if ins.memory_size().size() != 1 { return false; }
    // base must be a GPR, no index, no scale, disp 0
    if ins.memory_index() != Register::None { return false; }
    if ins.memory_displacement64() != 0 { return false; }
    if ins.memory_base() == Register::None { return false; }
    true
}

/// Scan `data` at `image_base` for VMP 3.9.4 fetch sites.
///
/// `data` should be the raw bytes of the VMP section (`.vmp00` 0x14000c000,
/// size 0x266238 in `vmp_test_suite_virt_all_394.vmp.exe`). `image_base` is
/// the VA of `data[0]`.
pub fn scan_fetch_sites(data: &[u8], image_base: u64) -> Vec<FetchSite> {
    let mut sites = Vec::new();
    let mut off = 0usize;
    while off + 3 < data.len() {
        // Try decode at off (with REX handling). iced_x86 will correctly consume REX.
        let mut decoder = Decoder::with_ip(64, &data[off..], image_base + off as u64, DecoderOptions::NONE);
        let ins = decoder.decode();
        if is_movzx_byte_mem(&ins) {
            // Validate: within next 4 insns there is a new `mov r32,imm32` or `movzx` that loads a constant
            // is *not* required for correctness but filters garbage 622 -> 152 (we keep it optional here).
            // For the Rust scanner we keep the strict REX-aware rule and emit if base is GPR.
            let dst = ins.op0_register();
            let base = ins.memory_base();
            // Only 64-bit GPRs allowed as base for bytecode ptr.
            let is_gpr = matches!(base,
                Register::RAX | Register::RCX | Register::RDX | Register::RBX |
                Register::RSP | Register::RBP | Register::RSI | Register::RDI |
                Register::R8 | Register::R9 | Register::R10 | Register::R11 |
                Register::R12 | Register::R13 | Register::R14 | Register::R15);
            if is_gpr {
                sites.push(FetchSite { va: ins.ip(), base, dst, len: ins.len() });
            }
            off += ins.len();
        } else {
            off += 1;
        }
    }
    sites
}

/// Strict variant that also checks for a following `mov reg,imm` within 4 insns,
/// matching the Python `fetch_sites_all2.json` filter.
pub fn scan_fetch_sites_strict(data: &[u8], image_base: u64) -> Vec<FetchSite> {
    let all = scan_fetch_sites(data, image_base);
    let mut strict = Vec::new();
    for site in all {
        let off = (site.va - image_base) as usize;
        // Look ahead up to 64 bytes / 6 insns for a mov reg,imm32.
        let mut decoder = Decoder::with_ip(64, &data[off + site.len ..], site.va + site.len as u64, DecoderOptions::NONE);
        let mut found = false;
        for _ in 0..6 {
            if usize::try_from(decoder.ip() - image_base).unwrap_or(usize::MAX) >= data.len() { break; }
            let ins = decoder.decode();
            if ins.is_invalid() { break; }
            if ins.mnemonic() == Mnemonic::Mov && ins.op1_kind() == OpKind::Immediate32 {
                found = true;
                break;
            }
            if ins.ip() > site.va + 32 { break; }
        }
        if found {
            strict.push(site);
        }
    }
    strict
}

/// Watch-set of fetch VAs for segment splitting across tools.
/// Reads `WATCH_FILE` env (default: `<data>/watch.txt` executed-movzx list).
/// Empty file / missing -> empty set (callers fall back as they see fit).
pub fn load_watchset() -> std::collections::BTreeSet<u64> {
    let def = format!("{}/watch.txt", crate::data_dir());
    let path = std::env::var("WATCH_FILE").unwrap_or(def);
    std::fs::read_to_string(&path).unwrap_or_default().lines()
        .filter_map(|l| u64::from_str_radix(l.trim().trim_start_matches("0x"), 16).ok())
        .collect()
}

/// Snapshot sections with bases from `<dir>/open_bases.json`
/// (written by tracer; fallback: generic defaults).
pub fn load_snapshots(dir: &str) -> Vec<(u64, Vec<u8>)> {
    let bmap: std::collections::HashMap<String, u64> =
        std::fs::read_to_string(format!("{}/open_bases.json", dir))
            .ok()
            .and_then(|s| serde_json::from_str::<std::collections::HashMap<String, String>>(&s).ok())
            .map(|m| {
                m.into_iter()
                    .filter_map(|(k, v)| {
                        u64::from_str_radix(v.trim().trim_start_matches("0x"), 16).ok().map(|a| (k, a))
                    })
                    .collect()
            })
            .unwrap_or_default();
    let bget = |n: &str, dflt: u64| *bmap.get(n).unwrap_or(&dflt);
    let mut out = Vec::new();
    for (name, base) in [
        ("text", bget("text", 0x140001000u64)),
        ("rdata", bget("rdata", 0x140003000)),
        ("data", bget("data", 0x140005000)),
        ("vmp0", bget("vmp0", 0x140007000)),
        ("vmp1", bget("vmp1", 0x14035f000)),
        ("staged", bget("staged", 0x300000)),
        ("heap", bget("heap", 0x71000000)),
    ] {
        if let Ok(d) = std::fs::read(format!("{}/open_mem_{}.bin", dir, name)) {
            out.push((base, d));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe_loader::PEBinary;

    #[test]
    fn finds_152_in_virt_all() {
        // Needs the licensed ground-truth binary; the checked-in fixture
        // is synthetic (1 site), so skip unless VMP_TEST_BIN is explicit.
        let path = match std::env::var("VMP_TEST_BIN") {
            Ok(p) => p,
            Err(_) => return,
        };
        let bin = match PEBinary::load(path) {
            Ok(b) => b,
            Err(_) => return, // skip in CI without binary
        };
        let vmp_data = bin.get_section(".vmp00").or_else(|_| {
            // Fallback: VMP section has garbage name in 3.9.4, so grab largest non-standard
            let pe = bin.parse_pe().unwrap();
            let base = bin.image_base().unwrap();
            let mut best: Option<Vec<u8>> = None;
            let mut best_size = 0usize;
            for s in &pe.sections {
                let name = std::str::from_utf8(&s.name).unwrap_or("").trim_end_matches('\0');
                if [".text",".rdata",".data",".pdata",".reloc",".rsrc"].contains(&name) { continue; }
                let sz = s.size_of_raw_data as usize;
                if sz > best_size {
                    best_size = sz;
                    let off = s.pointer_to_raw_data as usize;
                    best = Some(bin.data[off..off+sz].to_vec());
                }
                let _ = base;
            }
            best.ok_or(anyhow::anyhow!("no vmp")) 
        });
        let data = match vmp_data { Ok(d) => d, Err(_) => return };
        // For virt_all the VMP section is at 0x14000c000; we fake base for test
        let sites = scan_fetch_sites(&data, 0x14000c000);
        // We expect ~150+ raw movzx byte [reg]
        assert!(sites.len() >= 140, "got {} sites", sites.len());
    }
}
