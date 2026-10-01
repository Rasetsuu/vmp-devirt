//! Recompilability proof: Remill-lift N consecutive segment blocks -> opt -> llc -> .o
use vmp_devirt::backend::lifter::lift_via_remill;
use vmp_devirt::backend::llvm_pipeline::optimize_lifted;

fn read_mem(snaps: &[(u64, Vec<u8>)], va: u64, len: usize) -> Option<Vec<u8>> {
    for (base, data) in snaps {
        if va >= *base && (va - base) as usize + len <= data.len() {
            let o = (va - base) as usize;
            return Some(data[o..o + len].to_vec());
        }
    }
    None
}

/// Instruction-exact byte span from VA: decode forward (iced), stop after
/// the first control-flow insn inclusive, cap 32 insns. Fixed windows
/// (e.g. 48B) cut mid-instruction and remill appends __remill_error.
fn block_bytes(snaps: &[(u64, Vec<u8>)], va: u64) -> Option<Vec<u8>> {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic};
    let raw = read_mem(snaps, va, 256)?;
    let mut decoder = Decoder::with_ip(64, &raw, va, DecoderOptions::NONE);
    let mut end = 0usize;
    let mut n = 0usize;
    while decoder.can_decode() && n < 32 {
        let ins = decoder.decode();
        end = (decoder.ip() - va) as usize;
        n += 1;
        if matches!(ins.mnemonic(), Mnemonic::Jmp | Mnemonic::Call | Mnemonic::Ret) {
            break;
        }
    }
    if end == 0 || end > raw.len() { return None; }
    Some(raw[..end].to_vec())
}

fn main() -> anyhow::Result<()> {
    let dir = std::env::var("DATA_DIR").unwrap_or_else(|_| "./data".to_string());
    let tb = std::fs::read(format!("{}/open_trace.bin", dir))?;
    let trace: Vec<u64> = tb.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
    use vmp_devirt::frontend::fetch_finder::load_snapshots;
    let snaps = load_snapshots(&dir);
    // Env-driven (was Open.exe-hardcoded): fetch site + segment index.
    let fetch_va: u64 = std::env::var("FETCH_VA").map(|v| u64::from_str_radix(v.trim().trim_start_matches("0x"), 16).unwrap()).unwrap_or(0x14087daa3u64);
    let bounds: Vec<usize> = trace.iter().enumerate().filter(|(_, a)| **a == fetch_va).map(|(i, _)| i).collect();
    if bounds.len() < 2 { anyhow::bail!("fetch {:#x} visited {}x (<2)", fetch_va, bounds.len()); }
    // All blocks of segment 1 in trace order.
    let segno = 1usize;
    let mut blocks = Vec::new();
    let mut prev = 0u64;
    for a in trace[bounds[segno]..bounds[segno + 1]].iter() {
        if *a < 0x900000 { prev = *a; continue; }
        if prev == 0 || *a < prev || *a - prev > 16 { blocks.push(*a); }
        prev = *a;
    }
    println!("seg{}: {} blocks", segno, blocks.len());
    // Dedup by VA (loops revisit): lift once, link unique set.
    let mut seen = std::collections::BTreeSet::new();
    let uniq: Vec<u64> = blocks.clone().into_iter().filter(|v| seen.insert(*v)).collect();
    println!("seg{}: {} unique", segno, uniq.len());
    let outdir = format!("{}/recomp", dir);
    std::fs::create_dir_all(&outdir).ok();
    let mut objs = Vec::new();
    for (i, va) in uniq.iter().enumerate() {
        let code = match block_bytes(&snaps, *va) {
            Some(c) => c,
            None => { eprintln!("  skip {:#x}: no mem", va); continue; }
        };
        let lifted = match lift_via_remill(&code, *va) {
            Ok(l) => l,
            Err(e) => { eprintln!("  skip {:#x}: {}", va, e); continue; }
        };
        let opt = optimize_lifted(&lifted);
        let ll = format!("{}/s1_{:03}_{:#x}.ll", outdir, i, va);
        std::fs::write(&ll, &opt)?;
        let bc = format!("{}/s1_{:03}.bc", outdir, i);
        let o1 = std::process::Command::new("opt").args(["-O3", "-S", &ll, "-o", &bc]).output()?;
        if !o1.status.success() { eprintln!("  opt failed {:#x}", va); continue; }
        let obj = format!("{}/s1_{:03}.o", outdir, i);
        let o2 = std::process::Command::new("llc").args(["-filetype=obj", "-relocation-model=pic", &bc, "-o", &obj]).output()?;
        if !o2.status.success() { eprintln!("  llc failed {:#x}", va); continue; }
        objs.push(obj);
    }
    println!("seg{}: {}/{} blocks -> objects", segno, objs.len(), blocks.len());
    // Partial link into one segment object (proves composability).
    let segobj = format!("{}/seg1.o", outdir);
    let ld = std::process::Command::new("ld").args([vec!["-r".to_string(), "-o".to_string(), segobj.clone()], objs.clone()].concat()).output()?;
    if !ld.status.success() { anyhow::bail!("ld -r failed: {}", String::from_utf8_lossy(&ld.stderr)); }
    println!("OK: seg1.o linked ({} bytes)", std::fs::metadata(&segobj)?.len());
    Ok(())
}
