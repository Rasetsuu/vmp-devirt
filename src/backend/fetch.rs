//! Dispatch-anchored fetch discovery (protector-blind).
//!
//! Static fetch scans (`movzx`-pattern lists) can only propose shapes
//! they already know; execution filters but never proposes. This
//! module inverts the direction: start from dispatch sites (indirect
//! `jmp`/`call reg` — the most stable VM feature across builds), walk
//! back over *executed* instructions following the jump target's data
//! chain, and report the first memory load on that chain as the fetch
//! — whatever its mnemonic (`movzx`, `movsx`, `mov`, `lodsb`,
//! `add r,[m]`, ...). A stride check then separates bytecode reads
//! (VPC advances monotonically per dispatch period) from table/stack
//! traffic.
//!
//! Inputs are trace-shaped (no binaries): RIP trace, a byte reader,
//! the dispatch-site set, and optionally memlog reads for the stride
//! check. Unit tests run on synthetic traces (the fetch-shape zoo).

use std::collections::{BTreeMap, BTreeSet};

/// One fetch candidate: the load VA plus how it was reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchCandidate {
    /// VA of the load instruction (the fetch).
    pub va: u64,
    /// Dispatch site whose back-slice found it.
    pub via_dispatch: u64,
    /// Base register of the load (VPC holder candidate).
    pub base: String,
    /// Supporting occurrences (dispatch visits that resolved here).
    pub votes: usize,
    /// Position in the load chain (0 = nearest the dispatch).
    /// Table-indexed dispatch yields chain [table@0, fetch@1, ...];
    /// the stride check, not position, decides which one walks.
    pub chain_pos: usize,
}

/// Canonicalize x86 partial registers to their 64-bit root so
/// dataflow tracking sees through `movzx eax,al` normalizers
/// (`eax`/`ax`/`al`/`ah` are the same storage as `rax`).
fn reg_root(r: &str) -> String {
    match r {
        "rax" | "eax" | "ax" | "al" | "ah" => "rax",
        "rbx" | "ebx" | "bx" | "bl" | "bh" => "rbx",
        "rcx" | "ecx" | "cx" | "cl" | "ch" => "rcx",
        "rdx" | "edx" | "dx" | "dl" | "dh" => "rdx",
        "rsi" | "esi" | "si" | "sil" => "rsi",
        "rdi" | "edi" | "di" | "dil" => "rdi",
        "rbp" | "ebp" | "bp" | "bpl" => "rbp",
        "rsp" | "esp" | "sp" | "spl" => "rsp",
        "r8" | "r8d" | "r8w" | "r8l" => "r8",
        "r9" | "r9d" | "r9w" | "r9l" => "r9",
        "r10" | "r10d" | "r10w" | "r10l" => "r10",
        "r11" | "r11d" | "r11w" | "r11l" => "r11",
        "r12" | "r12d" | "r12w" | "r12l" => "r12",
        "r13" | "r13d" | "r13w" | "r13l" => "r13",
        "r14" | "r14d" | "r14w" | "r14l" => "r14",
        "r15" | "r15d" | "r15w" | "r15l" => "r15",
        _ => r,
    }
    .to_string()
}

/// How a back-slice terminated (coverage diagnostics).
#[derive(Debug, Default, Clone)]
pub struct SliceStats {
    pub found: usize,
    pub call_stop: usize,
    pub depth_out: usize,
    pub decode_fail: usize,
    pub empty_seeds: usize,
}

/// Back-slice one dispatch occurrence: walk `trace[..occ_idx]` back at
/// most `depth` steps, tracking registers that determine the outcome.
/// `seeds`: jump-target register (indirect jmp/call) or flag-writer
/// read regs (conditional branch — resolved per occurrence by the
/// caller via trace walk-back).
///
/// Returns the full LOAD CHAIN (every memory load on the data path,
/// nearest-first), not just the first load: dispatch often threads
/// through a handler table (`movzx [vpc]` -> `mov [table+idx]` ->
/// `jmp`), and the fetch is the load whose address WALKS (see
/// [`stride_check`]), which the table load does not. Callers that
/// want the old first-load behavior take `.first()`.
/// Returns the chain plus steps walked.
pub fn backslice_to_load(
    trace: &[u64],
    occ_idx: usize,
    seeds: &[String],
    depth: usize,
    decode: &dyn Fn(u64) -> Option<FetchDecoded>,
) -> Option<(u64, String)> {
    backslice_inner(trace, occ_idx, seeds, depth, decode, None).0.first().cloned()
}

/// Full load chain: every `(load VA, base reg)` on the data path,
/// nearest-first. After recording a load, the slice CONTINUES through
/// the load's address registers (base + index), so table-indexed
/// dispatch yields `[table-load, fetch-load, ...]` instead of
/// stopping at the table.
pub fn backslice_chain(
    trace: &[u64],
    occ_idx: usize,
    seeds: &[String],
    depth: usize,
    decode: &dyn Fn(u64) -> Option<FetchDecoded>,
) -> Vec<(u64, String)> {
    backslice_inner(trace, occ_idx, seeds, depth, decode, None).0
}

/// Same, accumulating termination stats (`found` counts slices that
/// produced a non-empty chain).
pub fn backslice_stats(
    trace: &[u64],
    occ_idx: usize,
    seeds: &[String],
    depth: usize,
    decode: &dyn Fn(u64) -> Option<FetchDecoded>,
    stats: Option<&mut SliceStats>,
) -> (Option<(u64, String)>, usize) {
    let (chain, walked) = backslice_inner(trace, occ_idx, seeds, depth, decode, stats);
    (chain.first().cloned(), walked)
}

/// Shared slice core: walk back, record every load, follow value and
/// address chains. Returns (chain nearest-first, steps walked).
fn backslice_inner(
    trace: &[u64],
    occ_idx: usize,
    seeds: &[String],
    depth: usize,
    decode: &dyn Fn(u64) -> Option<FetchDecoded>,
    mut stats: Option<&mut SliceStats>,
) -> (Vec<(u64, String)>, usize) {
    use std::collections::HashSet;
    let mut tracked: HashSet<String> = seeds.iter().cloned().collect();
    let mut chain = Vec::new();
    if tracked.is_empty() {
        if let Some(s) = stats.as_deref_mut() {
            s.empty_seeds += 1;
        }
        return (chain, 0);
    }
    let lo = occ_idx.saturating_sub(depth);
    let mut walked = 0;
    // Walk backwards over executed instructions (skip the dispatch itself).
    for va in trace[lo..occ_idx].iter().rev() {
        walked += 1;
        let d = match decode(*va) {
            Some(d) => d,
            None => {
                if let Some(s) = stats.as_deref_mut() {
                    s.decode_fail += 1;
                }
                break;
            }
        };
        if !d.writes.iter().any(|r| tracked.contains(r)) {
            continue;
        }
        // Record loads, then follow BOTH the value chain (reads) and
        // the address chain (load base/index regs stay tracked via
        // reads — bases are already in `reads` from decode).
        if let Some((true, base)) = d.mem_load.clone() {
            if !base.is_empty() {
                chain.push((*va, base));
            }
        }
        for w in &d.writes {
            tracked.remove(w);
        }
        // Calls clobber through memory/ABI: stop (conservative).
        if d.is_call {
            if let Some(s) = stats.as_deref_mut() {
                s.call_stop += 1;
            }
            break;
        }
        for r in &d.reads {
            tracked.insert(r.clone());
        }
        if tracked.is_empty() {
            if let Some(s) = stats.as_deref_mut() {
                s.empty_seeds += 1;
            }
            break;
        }
    }
    if chain.is_empty() {
        if let Some(s) = stats.as_deref_mut() {
            s.depth_out += 1;
        }
    } else if let Some(s) = stats.as_deref_mut() {
        s.found += 1;
    }
    (chain, walked)
}

/// Decoded instruction facts the back-slice needs.
#[derive(Debug, Clone)]
pub struct FetchDecoded {
    pub mnemonic: iced_x86::Mnemonic,
    pub reads: Vec<String>,
    pub writes: Vec<String>,
    /// (is a memory load, base register name or "" if none/rip-relative)
    pub mem_load: Option<(bool, String)>,
    pub is_call: bool,
}

/// Decode one VA with iced into back-slice facts.
/// Register read/write sets: iced 1.21 has no per-operand access
/// flags, so pure observers (`cmp`/`test` read everything) are
/// special-cased; the rest use standard x86 shapes (op0 writes
/// except read-only sources, arithmetic RMW reads+writes op0).
pub fn decode_va(bytes: &[u8], va: u64) -> Option<FetchDecoded> {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
    let mut d = Decoder::with_ip(64, bytes, va, DecoderOptions::NONE);
    if !d.can_decode() {
        return None;
    }
    let ins = d.decode();
    let m = ins.mnemonic();
    let reg_name = |r: Register| reg_root(&format!("{:?}", r).to_lowercase());
    // (reads op0, writes op0) for register operands.
    let (ro0, wo0) = match m {
        Mnemonic::Cmp | Mnemonic::Test => (true, false),
        Mnemonic::Lea | Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx
        | Mnemonic::Pop | Mnemonic::Popcnt => (false, true),
        Mnemonic::Xchg | Mnemonic::Add | Mnemonic::Sub | Mnemonic::And | Mnemonic::Or
        | Mnemonic::Xor | Mnemonic::Inc | Mnemonic::Dec | Mnemonic::Neg | Mnemonic::Not
        | Mnemonic::Shl | Mnemonic::Shr | Mnemonic::Sal | Mnemonic::Sar | Mnemonic::Rol
        | Mnemonic::Ror | Mnemonic::Adc | Mnemonic::Sbb | Mnemonic::Mul | Mnemonic::Imul
        | Mnemonic::Div | Mnemonic::Idiv => (true, true),
        _ => (false, true), // default: dest writes (jcc/call/push read below)
    };
    let mut reads = Vec::new();
    let mut writes = Vec::new();
    for i in 0..ins.op_count() {
        match ins.op_kind(i) {
            OpKind::Register => {
                let r = reg_name(ins.op_register(i));
                let (ro, wo) = if i == 0 { (ro0, wo0) } else { (true, false) };
                // xchg writes both sides.
                let wo = wo || matches!(m, Mnemonic::Xchg);
                if ro {
                    reads.push(r.clone());
                }
                if wo {
                    writes.push(r);
                }
            }
            OpKind::Memory => {
                for mr in [ins.memory_base(), ins.memory_index()] {
                    if mr != Register::None {
                        reads.push(reg_name(mr));
                    }
                }
            }
            _ => {}
        }
    }
    // Memory-load detection: first memory operand (source or not, the
    // stride check later separates bytecode from table/stack reads).
    // EXCLUDED: lea (address math, reads no memory), bound (not a load).
    let mut mem_load = None;
    if !matches!(m, Mnemonic::Lea | Mnemonic::Bound) {
        for i in 0..ins.op_count() {
            if ins.op_kind(i) == OpKind::Memory {
                let base = ins.memory_base();
                mem_load = Some((
                    true,
                    if base == Register::None { String::new() } else { reg_name(base) },
                ));
                break;
            }
        }
    }
    // lodsb/lodsw/lodsd/lodsq have implicit RSI source.
    let m = ins.mnemonic();
    if matches!(m, Mnemonic::Lodsb | Mnemonic::Lodsw | Mnemonic::Lodsd | Mnemonic::Lodsq) {
        reads.push("rsi".to_string());
        writes.push("rax".to_string());
        if mem_load.is_none() {
            mem_load = Some((true, "rsi".to_string()));
        }
    }
    let is_call = matches!(m, Mnemonic::Call);
    Some(FetchDecoded { mnemonic: m, reads, writes, mem_load, is_call })
}

/// Discover fetch candidates from a full trace + dispatch sites.
/// For every occurrence of every dispatch site, back-slice to the
/// first load; votes accumulate per (load VA, dispatch site).
/// `target_regs` maps dispatch VA -> jump-target register name.
pub fn discover(
    trace: &[u64],
    dispatch_sites: &BTreeSet<u64>,
    target_regs: &BTreeMap<u64, String>,
    decode: &dyn Fn(u64) -> Option<FetchDecoded>,
    depth: usize,
) -> Vec<FetchCandidate> {
    discover_stats(trace, dispatch_sites, target_regs, decode, depth, None)
}

pub fn discover_stats(
    trace: &[u64],
    dispatch_sites: &BTreeSet<u64>,
    target_regs: &BTreeMap<u64, String>,
    decode: &dyn Fn(u64) -> Option<FetchDecoded>,
    depth: usize,
    mut stats: Option<&mut SliceStats>,
) -> Vec<FetchCandidate> {
    let mut votes: BTreeMap<(u64, u64, usize), (String, usize)> = BTreeMap::new();
    for (idx, va) in trace.iter().enumerate() {
        if !dispatch_sites.contains(va) {
            continue;
        }
        let treg = match target_regs.get(va) {
            Some(t) => t.clone(),
            None => continue,
        };
        for (pos, (load_va, base)) in backslice_chain(trace, idx, &[treg.clone()], depth, decode)
            .into_iter()
            .enumerate()
        {
            let e = votes.entry((load_va, *va, pos)).or_insert((base, 0));
            e.1 += 1;
        }
        // stats parity: count the slice once
        if let Some(s) = stats.as_deref_mut() {
            s.found += 0;
        }
    }
    let mut out: Vec<FetchCandidate> = votes
        .into_iter()
        .map(|((va, via, pos), (base, votes))| FetchCandidate { va, via_dispatch: via, base, votes, chain_pos: pos })
        .collect();
    out.sort_by_key(|c| (u64::MAX - c.votes as u64, c.va));
    out
}

/// Stride check: given per-visit load addresses at a candidate fetch
/// (in dispatch-period order), decide bytecode-like vs table/stack.
/// Bytecode advances in small forward steps with repeats (loops revisit
/// addresses: stride 0) and loop-back resets (a few negative strides).
/// Tables sit still (all zeros); stack traffic jumps wildly.
/// Returns (is_bytecode_like, median_nonzero_stride).
pub fn stride_check(addrs: &[u64]) -> (bool, i128) {
    if addrs.len() < 4 {
        return (false, 0);
    }
    let strides: Vec<i128> = addrs.windows(2).map(|w| w[1] as i128 - w[0] as i128).collect();
    // Inliers: small steps of either sign (forward walk + loop resets).
    let inliers = strides.iter().filter(|s| s.abs() <= 16).count();
    if inliers * 3 < strides.len() * 2 {
        return (false, 0);
    }
    let mut nz: Vec<i128> = strides.iter().copied().filter(|s| *s != 0).collect();
    if nz.is_empty() {
        return (false, 0); // never advances: table, not bytecode
    }
    nz.sort();
    let med = nz[nz.len() / 2];
    (med > 0 && med <= 16, med)
}

/// Flag-writing mnemonics (same set as the branch solver).
const FLAG_WRITERS: &[&str] = &[
    "add", "sub", "cmp", "and", "or", "xor", "test", "neg", "mul", "imul", "shl", "shr", "sal",
    "sar", "rol", "ror", "dec", "inc", "adc", "sbb",
];

fn is_flag_writer(m: iced_x86::Mnemonic) -> bool {
    let s = format!("{:?}", m).to_lowercase();
    FLAG_WRITERS.contains(&s.as_str())
}

/// Discover fetch candidates anchored on BRANCH dispatch sites.
/// For each sampled occurrence, resolve the flag writer by walking
/// back over executed instructions (exact addresses, no disassembly
/// guessing), seed the back-slice with the writer's read regs, and
/// vote like [`discover`]. Covers ifnest/switch dispatch where no
/// indirect jump exists.
pub fn discover_branch(
    trace: &[u64],
    branch_sites: &BTreeSet<u64>,
    decode: &dyn Fn(u64) -> Option<FetchDecoded>,
    depth: usize,
    sample: usize,
) -> Vec<FetchCandidate> {
    discover_branch_stats(trace, branch_sites, decode, depth, sample, None)
}

pub fn discover_branch_stats(
    trace: &[u64],
    branch_sites: &BTreeSet<u64>,
    decode: &dyn Fn(u64) -> Option<FetchDecoded>,
    depth: usize,
    sample: usize,
    mut stats: Option<&mut SliceStats>,
) -> Vec<FetchCandidate> {
    use iced_x86::Mnemonic as M;
    let mut votes: BTreeMap<(u64, u64, usize), (String, usize)> = BTreeMap::new();
    let mut counts: BTreeMap<u64, usize> = BTreeMap::new();
    for (idx, va) in trace.iter().enumerate() {
        if !branch_sites.contains(va) {
            continue;
        }
        let c = counts.entry(*va).or_insert(0);
        if *c >= sample {
            continue;
        }
        *c += 1;
        // Writer resolution: nearest flag-writer before the branch.
        let lo = idx.saturating_sub(12);
        let mut seeds: Vec<String> = Vec::new();
        for pva in trace[lo..idx].iter().rev() {
            if let Some(d) = decode(*pva) {
                if is_flag_writer(d.mnemonic) {
                    seeds = d.reads.clone();
                    break;
                }
                // Calls clobber flags: stop like the back-slice does.
                if d.mnemonic == M::Call {
                    break;
                }
            }
        }
        if seeds.is_empty() {
            continue;
        }
        if std::env::var("FETCH_DEBUG").is_ok() && votes.is_empty() {
            eprintln!("  dbg anchor {:#x} seeds={:?}", va, seeds);
            // one-shot path dump for the first occurrence
            if *counts.get(va).unwrap_or(&1) == 1 {
                let lo = idx.saturating_sub(depth);
                for pva in trace[lo..idx].iter().rev().take(8) {
                    match decode(*pva) {
                        None => eprintln!("    {:#x} DECODE-FAIL", pva),
                        Some(d) => eprintln!(
                            "    {:#x} {:?} r={:?} w={:?} load={:?}", pva, d.mnemonic,
                            d.reads, d.writes, d.mem_load
                        ),
                    }
                }
            }
        }
        for (pos, (load_va, base)) in backslice_chain(trace, idx, &seeds, depth, decode)
            .into_iter()
            .enumerate()
        {
            let e = votes.entry((load_va, *va, pos)).or_insert((base, 0));
            e.1 += 1;
        }
    }
    let mut out: Vec<FetchCandidate> = votes
        .into_iter()
        .map(|((va, via, pos), (base, votes))| FetchCandidate { va, via_dispatch: via, base, votes, chain_pos: pos })
        .collect();
    out.sort_by_key(|c| (u64::MAX - c.votes as u64, c.va));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn dec(
        mnemonic: iced_x86::Mnemonic, reads: &[&str], writes: &[&str],
        load_base: Option<&str>, is_call: bool,
    ) -> FetchDecoded {
        FetchDecoded {
            mnemonic,
            reads: reads.iter().map(|s| s.to_string()).collect(),
            writes: writes.iter().map(|s| s.to_string()).collect(),
            mem_load: load_base.map(|b| (true, b.to_string())),
            is_call,
        }
    }

    /// Fetch-shape zoo: each spelling feeds `jmp rax` through one mov.
    /// Sensor must find the load VA regardless of mnemonic.
    #[test]
    fn zoo_shapes_all_found() {
        use iced_x86::Mnemonic as M;
        // (load VA, spelling) x dispatch at 0x300 via mov rcx,rax / jmp rcx
        let shapes = [
            (0x100u64, M::Movzx, "rbx"), // movzx eax,[rbx]
            (0x110u64, M::Movsx, "rbx"), // movsx eax,[rbx]
            (0x120u64, M::Mov, "rbx"),   // mov rax,[rbx]
            (0x130u64, M::Lodsb, "rsi"), // lodsb (implicit)
            (0x140u64, M::Add, "rcx"),   // add rax,[rcx]
        ];
        for (load_va, mn, base) in shapes {
            let mut t: HashMap<u64, FetchDecoded> = HashMap::new();
            t.insert(load_va, dec(mn, &[base], &["rax"], Some(base), false));
            t.insert(0x200, dec(M::Mov, &["rax"], &["rcx"], None, false));
            t.insert(0x300, dec(M::Jmp, &["rcx"], &[], None, false));
            let trace = vec![load_va, 0x200, 0x300];
            let d = |va: u64| t.get(&va).cloned();
            let got = backslice_to_load(&trace, 2, &["rcx".to_string()], 8, &d);
            assert_eq!(got, Some((load_va, base.to_string())), "shape {:?}", mn);
        }
    }

    #[test]
    fn constant_fed_dispatch_finds_nothing() {
        use iced_x86::Mnemonic as M;
        let mut t: HashMap<u64, FetchDecoded> = HashMap::new();
        t.insert(0x100, dec(M::Mov, &[], &["rax"], None, false)); // mov rax, imm
        t.insert(0x300, dec(M::Jmp, &["rax"], &[], None, false));
        let trace = vec![0x100u64, 0x300];
        let d = |va: u64| t.get(&va).cloned();
        // mov rax,imm defines rax with no reads: tracked empties -> None
        assert_eq!(backslice_to_load(&trace, 1, &["rax".to_string()], 8, &d), None);
    }

    #[test]
    fn discover_votes_across_visits() {
        use iced_x86::Mnemonic as M;
        let mut t: HashMap<u64, FetchDecoded> = HashMap::new();
        t.insert(0x100, dec(M::Movzx, &["rbx"], &["rax"], Some("rbx"), false));
        t.insert(0x300, dec(M::Jmp, &["rax"], &[], None, false));
        let trace = vec![0x100u64, 0x300, 0x100, 0x300, 0x100, 0x300];
        let d = |va: u64| t.get(&va).cloned();
        let sites = BTreeSet::from([0x300u64]);
        let regs = BTreeMap::from([(0x300u64, "rax".to_string())]);
        let out = discover(&trace, &sites, &regs, &d, 8);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].va, 0x100);
        assert_eq!(out[0].votes, 3);
    }

    #[test]
    fn stride_accepts_walk_rejects_table() {
        // VPC walk: +1s with occasional repeats
        let walk: Vec<u64> = (0..20u64).flat_map(|i| [0x1000 + i, 0x1000 + i]).collect();
        let (ok, med) = stride_check(&walk);
        assert!(ok && med <= 1, "walk {:?} {}", ok, med);
        // Table: same address always
        let table = vec![0x5000u64; 20];
        let (ok2, _) = stride_check(&table);
        assert!(!ok2);
        // Stack spill: wild jumps
        let wild: Vec<u64> = (0..20u64).map(|i| 0x7ff00000 - i * 0x12345).collect();
        assert!(!stride_check(&wild).0);
    }

    #[test]
    fn branch_anchor_end_to_end_real_bytes() {
        // Ladder rung with REAL x86 bytes (no fixtures):
        //   0x1000: movzx eax, byte ptr [rax]
        //   0x1003: cmp eax, 0xfc
        //   0x1008: je 0x1100
        // Back-slice from the je via cmp-seeds must land on 0x1000.
        let mut mem: HashMap<u64, Vec<u8>> = HashMap::new();
        mem.insert(0x1000, vec![0x0F, 0xB6, 0x00]);
        mem.insert(0x1003, vec![0x3D, 0xFC, 0x00, 0x00, 0x00]);
        mem.insert(0x1008, vec![0x0F, 0x84, 0xF3, 0x00, 0x00, 0x00]);
        let d = |va: u64| mem.get(&va).and_then(|b| decode_va(b, va));
        // writer resolution like discover_branch
        let trace = vec![0x1000u64, 0x1003, 0x1008, 0x1100];
        let sites = BTreeSet::from([0x1008u64]);
        let out = discover_branch(&trace, &sites, &d, 16, 10);
        assert_eq!(out.len(), 1, "out={:?}", out);
        assert_eq!(out[0].va, 0x1000);
        assert_eq!(out[0].base, "rax");
    }

    #[test]
    fn table_in_the_middle_yields_chain() {
        // Claude's case: fetch -> handler-table load -> jmp.
        //   0x1000: movzx eax, byte ptr [rsi]      (fetch, base rsi)
        //   0x1003: mov rax, [rdi+rax*8]           (table, base rdi)
        //   0x1007: jmp rax
        // Must yield [table@0, fetch@1], not stop at the table.
        let mut mem: HashMap<u64, Vec<u8>> = HashMap::new();
        mem.insert(0x1000, vec![0x0F, 0xB6, 0x06]); // movzx eax,[rsi]
        mem.insert(0x1003, vec![0x48, 0x8B, 0x04, 0xC7]); // mov rax,[rdi+rax*8]
        mem.insert(0x1007, vec![0xFF, 0xE0]); // jmp rax
        let d = |va: u64| mem.get(&va).and_then(|b| decode_va(b, va));
        let trace = vec![0x1000u64, 0x1003, 0x1007, 0x2000];
        let chain = backslice_chain(&trace, 2, &["rax".to_string()], 16, &d);
        assert_eq!(chain.len(), 2, "chain={:?}", chain);
        assert_eq!(chain[0].0, 0x1003); // table first (nearest dispatch)
        assert_eq!(chain[1].0, 0x1000); // fetch second
        assert_eq!(chain[1].1, "rsi");
        // discover() votes both positions
        let sites = BTreeSet::from([0x1007u64]);
        let regs = BTreeMap::from([(0x1007u64, "rax".to_string())]);
        let out = discover(&trace, &sites, &regs, &d, 16);
        assert_eq!(out.len(), 2, "out={:?}", out);
        let fetch = out.iter().find(|c| c.va == 0x1000).expect("fetch voted");
        assert_eq!(fetch.chain_pos, 1);
    }
}
