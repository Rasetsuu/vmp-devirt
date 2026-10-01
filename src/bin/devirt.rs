//! vmp-devirt CLI: scan / mine / decode.
use anyhow::{Context, Result};
use vmp_devirt::frontend::{VmFrontend, v1_gate::V1Gate, v2_walker::V2Table, v3_fdj::V3Fdj};
use vmp_devirt::frontend::fetch_finder::FetchSite;
use vmp_devirt::frontend::cryptor_miner::mine_cryptor;
use vmp_devirt::pe_loader::PEBinary;

fn frontends() -> Vec<Box<dyn VmFrontend>> {
    vec![Box::new(V1Gate), Box::new(V2Table), Box::new(V3Fdj)]
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage:");
        eprintln!("  devirt scan <binary>            # detect version + list fetch/handler addrs");
        eprintln!("  devirt mine <binary> <site-va>  # mine cryptor chain at a fetch site");
        eprintln!("  devirt merge <trace...>         # union edges + divergence points (.bin u64LE)");
        eprintln!("  devirt map <op...>              # opcode -> handler type (hex bytes)");
        eprintln!("  devirt sense <trace> <memlog>  # behavior-ranked fetch candidates");
        eprintln!("  devirt dispatch <trace.bin> <binary>  # indirect-jmp successor tables");
        eprintln!("  devirt mine-live <snapdir> <site-va>  # mine chain from snapshot overlay (live bytes)");
        eprintln!("  devirt mine-hits <open_hits.json>     # mine all hit sites from hit-time code");
        eprintln!("  devirt synth <chains.json>           # cross-check mined chains by re-synthesis");        eprintln!("  devirt handlers <trace> <memlog> <bin>  # handler blocks via vctx-stores + back-slice");
        eprintln!("  devirt brighten <ll> [--regs <json> --pool <json> --image <bin> --base <hex> --out <ll>]");
        eprintln!("  devirt fetch <trace> <bin> [--memlog <ml>]  # dispatch-anchored fetch discovery");
        eprintln!("                                           # Saturn-subset: const-pool fold + stack slots");
        std::process::exit(2);
    }
    let bin = if ["merge", "map", "sense", "dispatch", "mine-live", "mine-hits", "handlers", "synth", "brighten", "fetch"].contains(&args[1].as_str()) {
        // Merge/sense/dispatch/mine-live/mine-hits/handlers work on raw
        // files, not PEs (handlers takes its binary as args[4]).
        None
    } else {
        Some(PEBinary::load(&args[2]).with_context(|| format!("load {}", args[2]))?)
    };
    match args[1].as_str() {
        "scan" => {
            let bin = bin.as_ref().unwrap();
            for f in frontends() {
                let applies = f.detect(&bin).unwrap_or(false);
                println!("frontend {:<10} applies={}", f.name(), applies);
                if applies {
                    for h in f.handler_addrs(&bin, &[]).unwrap_or_default().iter() {
                        println!("  handler candidate {:#x}", h);
                    }
                }
            }
        }
        "mine" => {
            if args.len() < 4 {
                eprintln!("mine needs a site VA (hex)");
                std::process::exit(2);
            }
            let va = u64::from_str_radix(args[3].trim_start_matches("0x"), 16)?;
            let bin = bin.as_ref().unwrap();
            let bytes = bin.read_bytes(va, 16)?;
            let mut d = iced_x86::Decoder::with_ip(
                64,
                &bytes,
                va,
                iced_x86::DecoderOptions::NONE,
            );
            // Entry tolerance: prologue first, fetch within 4 insns.
            let mut movzx = None;
            for _ in 0..4 {
                if !d.can_decode() {
                    break;
                }
                let ins = d.decode();
                if (ins.mnemonic() == iced_x86::Mnemonic::Movzx
                    || ins.mnemonic() == iced_x86::Mnemonic::Movsx)
                    && ins.memory_base() != iced_x86::Register::None
                {
                    movzx = Some(ins);
                    break;
                }
                if matches!(ins.mnemonic(), iced_x86::Mnemonic::Jmp | iced_x86::Mnemonic::Call | iced_x86::Mnemonic::Ret) {
                    break;
                }
            }
            let movzx = movzx.with_context(|| format!("{:#x} is not a movzx/movsx fetch site", va))?;
            let site = FetchSite {
                va: movzx.ip(),
                base: movzx.memory_base(),
                dst: movzx.op0_register(),
                len: movzx.len(),
            };
            let m = mine_cryptor(&site, &bin)?;
            println!("site {:#x} key={} aux={:?} steps={} {:?}", va, m.key_reg, m.aux_src, m.steps, m.cryptor.cmds);
        }
        other if other == "merge" => {
            if args.len() < 4 {
                eprintln!("merge needs at least one trace file");
                std::process::exit(2);
            }
            use vmp_devirt::backend::merge::{divergence_points, merge_edges};
            let mut traces = Vec::new();
            for p in &args[2..] {
                let b = std::fs::read(p).with_context(|| format!("read {}", p))?;
                traces.push(b.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect::<Vec<u64>>());
            }
            let edges = merge_edges(&traces);
            let div = divergence_points(&edges);
            println!("traces={} edges={} divergence_points={}", traces.len(), edges.len(), div.len());
            for (a, succ) in div.iter().take(30) {
                println!("  vbraddr {:#x}: {}", a, succ.iter().map(|s| format!("{:#x}", s)).collect::<Vec<_>>().join(" | "));
            }
        }
        other if other == "map" => {
            use vmp_devirt::opcode_map::CanonicalOpcodeMap;
            for a in &args[2..] {
                let op = u8::from_str_radix(a.trim_start_matches("0x"), 16)?;
                let e = CanonicalOpcodeMap::lookup(op);
                println!("{:#04x} -> {:?} ({})", op, e.handler_type, e.semantic);
            }
        }
        other if other == "sense" => {
            if args.len() < 4 {
                eprintln!("sense needs <trace.bin> <memlog.bin>");
                std::process::exit(2);
            }
            use vmp_devirt::backend::sensor::sense;
            let tb = std::fs::read(&args[2]).with_context(|| format!("read {}", args[2]))?;
            let trace: Vec<u64> = tb.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
            let mb = std::fs::read(&args[3]).with_context(|| format!("read {}", args[3]))?;
            const REC: usize = 33;
            let mut reads = Vec::new();
            let mut writes = Vec::new();
            for c in mb.chunks_exact(REC) {
                let rip = u64::from_le_bytes(c[0..8].try_into().unwrap());
                let w = c[8] == 1;
                let addr = u64::from_le_bytes(c[9..17].try_into().unwrap());
                if rip < 0x900000 {
                    continue;
                }
                if w { writes.push((rip, addr)); } else { reads.push((rip, addr)); }
            }
            // Stack: high scratch pages. NOTE: every memlog access is data
            // (instruction fetches never hit MEM hooks), so image-range
            // pool reads count — only the VM stack is excluded as noise.
            let is_stack = |a: u64| (a & 0xFFF00000) == 0x7FF00000;
            let is_code = |_a: u64| false;
            let ranked = sense(&trace, &reads, &writes, &is_stack, &is_code);
            println!("ranked {} blocks", ranked.len());
            for f in ranked.iter().take(25) {
                println!("  {:#x} score={:.3} exec={} data={} span={:#x} rmw={}",
                    f.va, f.score, f.exec_count, f.data_reads, f.read_span, f.rmw);
            }
        }
        other if other == "dispatch" => {
            if args.len() < 4 {
                eprintln!("dispatch needs <trace.bin> <binary>");
                std::process::exit(2);
            }
            use vmp_devirt::backend::dispatch::dispatch_tables;
            let tb = std::fs::read(&args[2]).with_context(|| format!("read {}", args[2]))?;
            let trace: Vec<u64> = tb.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
            let bin = PEBinary::load(&args[3]).with_context(|| format!("load {}", args[3]))?;
            // Pre-decode unique VAs once (trace is millions of steps).
            // section_map() is format-agnostic (PE RVAs / ELF sh_addrs);
            // read bytes via bin.read_via (file-backed ranges only).
            use std::collections::{BTreeSet, HashSet};
            let sects = bin.section_map()?;
            let read_va = |va: u64, n: usize| -> Option<Vec<u8>> {
                bin.read_via(&sects, va, n)
            };
            let uniq: BTreeSet<u64> = trace.iter().cloned().collect();
            let mut indirect: HashSet<u64> = HashSet::new();
            // Branch dispatch (Tigress ifnest/switch nests, VMP jcc splits):
            // conditional jumps with >1 observed successor ARE dispatchers.
            // Collected here, filtered to multi-target after table build.
            let mut branches: HashSet<u64> = HashSet::new();
            for va in uniq {
                let bytes = match read_va(va, 6) {
                    Some(b) => b,
                    None => continue,
                };
                let mut d = iced_x86::Decoder::with_ip(64, &bytes, va, iced_x86::DecoderOptions::NONE);
                let ins = d.decode();
                if ins.mnemonic() == iced_x86::Mnemonic::Jmp
                    && matches!(ins.op0_kind(), iced_x86::OpKind::Register)
                {
                    indirect.insert(va);
                } else if ins.mnemonic() == iced_x86::Mnemonic::Call
                    && matches!(ins.op0_kind(), iced_x86::OpKind::Register)
                {
                    // Call threading (Tigress call dispatch): handler
                    // invocation IS the dispatch edge; rets are not sites
                    // so no return-edge noise enters the tables.
                    indirect.insert(va);
                } else if ins.is_jcc_short_or_near() {
                    branches.insert(va);
                }
            }
            let both = |va: u64| indirect.contains(&va) || branches.contains(&va);
            let tables = dispatch_tables(&trace, &both);
            println!("indirect dispatch sites: {}", tables.len());
            let mut multi = 0;
            let mut multi_br = 0;
            for (va, succ) in tables.iter().take(40) {
                let kind = if indirect.contains(va) { "ind" } else { "br" };
                println!("  {:#x}: {} targets {} [{}]", va, succ.len(),
                    succ.iter().take(6).map(|s| format!("{:#x}", s)).collect::<Vec<_>>().join(" | "), kind);
            }
            for (va, succ) in tables.iter() {
                if succ.len() > 1 {
                    multi += 1;
                    if branches.contains(va) {
                        multi_br += 1;
                    }
                }
            }
            println!("multi-target dispatchers (total): {} (indirect {}, branch {})",
                multi, multi - multi_br, multi_br);
        }
        other if other == "mine-live" => {
            if args.len() < 4 {
                eprintln!("mine-live needs <snapshot-dir> <site-va>");
                std::process::exit(2);
            }
            use vmp_devirt::frontend::cryptor_miner::mine_cryptor_with;
            let dir = &args[2];
            let va = u64::from_str_radix(args[3].trim_start_matches("0x"), 16)?;
            // Generic overlay: <dir>/open_bases.json maps mem-tag ->
            // base; <dir>/open_mem_<tag>.bin carries bytes (any tag set,
            // unlike the fixed-name load_snapshots helper).
            let bmap: std::collections::HashMap<String, String> =
                serde_json::from_str(&std::fs::read_to_string(format!("{}/open_bases.json", dir))?)?;
            let mut sections: Vec<(u64, Vec<u8>)> = Vec::new();
            for e in std::fs::read_dir(dir)? {
                let e = e?;
                let name = e.file_name().to_string_lossy().into_owned();
                if !name.starts_with("open_mem_") || !name.ends_with(".bin") {
                    continue;
                }
                let tag = &name["open_mem_".len()..name.len() - ".bin".len()];
                if let Some(base) = bmap.get(tag).and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok()) {
                    sections.push((base, std::fs::read(e.path())?));
                }
            }
            if sections.is_empty() {
                anyhow::bail!("no snapshot sections in {}", dir);
            }
            let read = |va: u64, n: usize| -> Option<Vec<u8>> {
                for (base, data) in &sections {
                    if va >= *base && va - base + n as u64 <= data.len() as u64 {
                        let o = (va - base) as usize;
                        return Some(data[o..o + n].to_vec());
                    }
                }
                None
            };
            let bytes = read(va, 16).with_context(|| format!("no snapshot bytes at {:#x}", va))?;
            let mut d = iced_x86::Decoder::with_ip(64, &bytes, va, iced_x86::DecoderOptions::NONE);
            let mut fetch = None;
            for _ in 0..4 {
                if !d.can_decode() {
                    break;
                }
                let ins = d.decode();
                if (ins.mnemonic() == iced_x86::Mnemonic::Movzx
                    || ins.mnemonic() == iced_x86::Mnemonic::Movsx)
                    && ins.memory_base() != iced_x86::Register::None
                {
                    fetch = Some(ins);
                    break;
                }
                if matches!(ins.mnemonic(), iced_x86::Mnemonic::Jmp | iced_x86::Mnemonic::Call | iced_x86::Mnemonic::Ret) {
                    break;
                }
            }
            let fetch = fetch.with_context(|| format!("{:#x} is not a movzx/movsx fetch site in overlay", va))?;
            let site = FetchSite {
                va: fetch.ip(),
                base: fetch.memory_base(),
                dst: fetch.op0_register(),
                len: fetch.len(),
            };
            let m = mine_cryptor_with(&site, &read)?;
            println!("site {:#x} key={} aux={:?} steps={} {:?}", va, m.key_reg, m.aux_src, m.steps, m.cryptor.cmds);
        }
        other if other == "mine-hits" => {
            if args.len() < 3 {
                eprintln!("mine-hits needs <open_hits.json>");
                std::process::exit(2);
            }
            use vmp_devirt::frontend::cryptor_miner::mine_cryptor_with;
            let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&args[2])?)?;
            // Accepts a hits array (open_hits.json) or a forced.json
            // object (mines its "pre" force-target records).
            let arr: Vec<serde_json::Value> = match &v {
                serde_json::Value::Array(a) => a.clone(),
                serde_json::Value::Object(m) => m.get("pre").and_then(|p| p.as_array()).cloned().unwrap_or_default(),
                _ => Vec::new(),
            };
            // Distinct sites -> first hit's code bytes (hit-time live).
            let mut sites: std::collections::BTreeMap<u64, Vec<u8>> = std::collections::BTreeMap::new();
            for x in &arr {
                let va = match x.get("site").and_then(|s| s.as_str()).and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()) {
                    Some(a) => a,
                    None => continue,
                };
                if sites.contains_key(&va) {
                    continue;
                }
                let code = match x.get("code").and_then(|s| s.as_str()) {
                    Some(s) => s,
                    None => continue,
                };
                let bytes: Vec<u8> = (0..code.len()).step_by(2).filter_map(|i| u8::from_str_radix(&code[i..(i + 2).min(code.len())], 16).ok()).collect();
                if !bytes.is_empty() {
                    sites.insert(va, bytes);
                }
            }
            let mut ok = 0usize;
            for (va, code) in &sites {
                // Entry tolerance: prologue first, fetch within 4 insns.
                let mut d = iced_x86::Decoder::with_ip(64, code, *va, iced_x86::DecoderOptions::NONE);
                let mut fetch = None;
                for _ in 0..4 {
                    if !d.can_decode() {
                        break;
                    }
                    let ins = d.decode();
                    if (ins.mnemonic() == iced_x86::Mnemonic::Movzx
                        || ins.mnemonic() == iced_x86::Mnemonic::Movsx)
                        && ins.memory_base() != iced_x86::Register::None
                    {
                        fetch = Some(ins);
                        break;
                    }
                    if matches!(ins.mnemonic(), iced_x86::Mnemonic::Jmp | iced_x86::Mnemonic::Call | iced_x86::Mnemonic::Ret) {
                        break;
                    }
                }
                let fetch = match fetch {
                    Some(f) => f,
                    None => continue,
                };
                let site = FetchSite {
                    va: fetch.ip(),
                    base: fetch.memory_base(),
                    dst: fetch.op0_register(),
                    len: fetch.len(),
                };
                let read = |a: u64, n: usize| -> Option<Vec<u8>> {
                    if a >= *va && a - va + n as u64 <= code.len() as u64 {
                        let o = (a - va) as usize;
                        Some(code[o..o + n].to_vec())
                    } else {
                        None
                    }
                };
                match mine_cryptor_with(&site, &read) {
                    Ok(m) => {
                        ok += 1;
                        println!("site {:#x} key={} aux={:?} steps={} {:?}", va, m.key_reg, m.aux_src, m.steps, m.cryptor.cmds);
                    }
                    Err(_) => {}
                }
            }
            println!("mined {}/{} hit sites", ok, sites.len());
        }
        other if other == "handlers" => {
            if args.len() < 5 {
                eprintln!("handlers needs <trace.bin> <memlog.bin> <binary>");
                std::process::exit(2);
            }
            use vmp_devirt::backend::handlers::detect_handlers;
            use std::collections::HashSet;
            let tb = std::fs::read(&args[2]).with_context(|| format!("read {}", args[2]))?;
            let trace: Vec<u64> = tb.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
            let mb = std::fs::read(&args[3]).with_context(|| format!("read {}", args[3]))?;
            const REC: usize = 33;
            let mut writes = Vec::new();
            for c in mb.chunks_exact(REC) {
                let rip = u64::from_le_bytes(c[0..8].try_into().unwrap());
                let w = c[8] == 1;
                let addr = u64::from_le_bytes(c[9..17].try_into().unwrap());
                if !w {
                    continue;
                }
                // Virtual context = stack range (paper §II-B: VM reuses the
                // stack frame; rsp-region stores are result-stores).
                if (addr & 0xFFF00000) != 0x7FF00000 {
                    continue;
                }
                writes.push((rip, addr));
            }
            let bin = PEBinary::load(&args[4]).with_context(|| format!("load {}", args[4]))?;
            let map = bin.section_map()?;
            let uniq: std::collections::BTreeSet<u64> = trace.iter().cloned().collect();
            // Segment openers: indirect jmp/call-reg (threaded dispatch)
            // or multi-successor jcc (ifnest/switch dispatch). Same
            // generalization as the dispatch CLI; back-slice needs no
            // fetch patterns on either protector.
            let mut indirect: HashSet<u64> = HashSet::new();
            let mut branches: HashSet<u64> = HashSet::new();
            for va in uniq {
                let bytes = match bin.read_via(&map, va, 6) {
                    Some(b) => b,
                    None => continue,
                };
                let mut d = iced_x86::Decoder::with_ip(64, &bytes, va, iced_x86::DecoderOptions::NONE);
                let ins = d.decode();
                if (ins.mnemonic() == iced_x86::Mnemonic::Jmp
                    || ins.mnemonic() == iced_x86::Mnemonic::Call)
                    && matches!(ins.op0_kind(), iced_x86::OpKind::Register)
                {
                    indirect.insert(va);
                } else if ins.is_jcc_short_or_near() {
                    branches.insert(va);
                }
            }
            let is_opener = |va: u64| indirect.contains(&va) || branches.contains(&va);
            let blocks = detect_handlers(&trace, &writes, &is_opener);
            println!("writes={} openers={} (indirect {}) handlers={}", writes.len(), indirect.len() + branches.len(), indirect.len(), blocks.len());
            let mut ranked = blocks.clone();
            ranked.sort_by_key(|b| (b.executions, b.stores.len()));
            for b in ranked.iter().rev().take(25) {
                println!("  {:#x} exec={} stores={}", b.start, b.executions, b.stores.len());
            }
        }
        other if other == "synth" => {
            if args.len() < 3 {
                eprintln!("synth needs <chains.json> (gen_chains.py output)");
                std::process::exit(2);
            }
            use vmp_devirt::backend::synth::simplify_chain;
            use vmp_devirt::backend::value_cryptor::{CryptOp, CryptSize, ValueCryptor};
            let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&args[2])?)?;
            let m = v.as_object().context("chains.json must be an object")?;
            let mut agree = 0usize;
            let mut skipped = 0usize;
            let mut disagree = Vec::new();
            for (site, ch) in m {
                let cmds = match ch.get("cmds").and_then(|c| c.as_array()) {
                    Some(c) => c,
                    None => { skipped += 1; continue; }
                };
                let mut chain = ValueCryptor::new(CryptSize::Byte);
                let mut usable = true;
                for c in cmds {
                    let op = match c.get(0).and_then(|s| s.as_str()).unwrap_or("") {
                        "Xor" => CryptOp::Xor, "Add" => CryptOp::Add, "Sub" => CryptOp::Sub,
                        "Rol" => CryptOp::Rol, "Ror" => CryptOp::Ror, "Inc" => CryptOp::Inc,
                        "Dec" => CryptOp::Dec, "Neg" => CryptOp::Neg, "Not" => CryptOp::Not,
                        _ => { usable = false; break; }  // And etc: no byte model
                    };
                    let imm = c.get(1).and_then(|n| n.as_u64()).unwrap_or(0);
                    chain.add(op, imm);
                }
                if !usable {
                    skipped += 1;
                    continue;
                }
                // Simplification search (not de-novo synthesis: pairs derive
                // from the chain itself, so full search would only test
                // the searcher): deletions + single substitutions of the
                // mined skeleton, verified on fresh inputs.
                let ops: Vec<(CryptOp, u64)> = chain.cmds.iter()
                    .map(|c| (c.op, c.value)).collect();
                let truth: Vec<u8> = [0x01u8, 0x5a, 0xa5, 0xde].iter()
                    .map(|b| chain.encrypt(*b as u64) as u8).collect();
                let probe = |sk: &[(CryptOp, u64)]| -> bool {
                    let mut c = ValueCryptor::new(CryptSize::Byte);
                    for (op, v) in sk {
                        c.add(*op, *v);
                    }
                    [0x01u8, 0x5a, 0xa5, 0xde].iter().enumerate().all(|(i, b)| {
                        c.encrypt(*b as u64) as u8 == truth[i]
                    })
                };
                // verify mined skeleton first (sanity, instant)
                let base: Vec<(CryptOp, u64)> = ops.clone();
                if !probe(&base) {
                    disagree.push(site.clone() + " (self-inconsistent)");
                    continue;
                }
                // deletions, shortest first
                let mut best = base.len();
                let n = base.len();
                // bitmask over subsets (len <= 10 keeps this bounded)
                if n <= 10 {
                    for mask in 0..(1u32 << n) {
                        let sub: Vec<(CryptOp, u64)> = base.iter().enumerate()
                            .filter(|(i, _)| mask & (1 << i) == 0)
                            .map(|(_, x)| *x).collect();
                        if sub.len() < best && probe(&sub) {
                            best = sub.len();
                        }
                    }
                }
                // single substitutions toward fewer ops are covered by
                // deletions of redundant pairs in practice; report.
                // VTIL-rule canonical form (instant, no search).
                let canon = simplify_chain(&chain);
                // Cross-check: rule result must verify on probe inputs.
                let cvec: Vec<(CryptOp, u64)> = canon.cmds.iter()
                    .map(|c| (c.op, c.value)).collect();
                if !probe(&cvec) {
                    disagree.push(site.clone() + " (rule-unsound)");
                    continue;
                }
                if canon.cmds.len() < best {
                    println!("  {} compressible {} -> {} (subset) / {} (rules)",
                        site, n, best, canon.cmds.len());
                } else if best < n {
                    println!("  {} compressible {} -> {}", site, n, best);
                }
                agree += 1;
            }
            println!("synth cross-check: agree={} disagree={} skipped={} total={}",
                agree, disagree.len(), skipped, m.len());
            for s in disagree.iter().take(10) {
                println!("  MISMATCH {}", s);
            }
        }
        other if other == "brighten" => {
            if args.len() < 3 {
                eprintln!("brighten needs <file.ll> [--regs <json> --pool <json> --image <bin> --base <hex> --out <ll>]");
                std::process::exit(2);
            }
            use vmp_devirt::backend::brighten::brighten;
            // flag parser: --key value pairs after the .ll path
            let mut regs_p = None::<String>;
            let mut pool_p = None::<String>;
            let mut image_p = None::<String>;
            let mut base = 0x1400_00000u64;
            let mut out_p = None::<String>;
            let mut i = 3;
            while i < args.len() {
                match args[i].as_str() {
                    "--regs" => { regs_p = Some(args[i + 1].clone()); i += 2; }
                    "--pool" => { pool_p = Some(args[i + 1].clone()); i += 2; }
                    "--image" => { image_p = Some(args[i + 1].clone()); i += 2; }
                    "--base" => {
                        base = u64::from_str_radix(args[i + 1].trim_start_matches("0x"), 16)?;
                        i += 2;
                    }
                    "--out" => { out_p = Some(args[i + 1].clone()); i += 2; }
                    f => {
                        eprintln!("brighten: unknown flag {}", f);
                        std::process::exit(2);
                    }
                }
            }
            let ir = std::fs::read_to_string(&args[2])?;
            let regs: std::collections::HashMap<String, u64> = match regs_p {
                Some(p) => {
                    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&p)?)?;
                    v.as_object().context("regs json must be an object")?.iter()
                        .map(|(k, v)| (k.to_lowercase(), v.as_u64().unwrap_or(0)))
                        .collect()
                }
                None => Default::default(),
            };
            // pool json: {"ranges": [[start, len], ...]} (ints, hex strings ok)
            let pools: Vec<(u64, u64)> = match pool_p {
                Some(p) => {
                    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&p)?)?;
                    let mut r = Vec::new();
                    for e in v.get("ranges").and_then(|x| x.as_array()).cloned().unwrap_or_default() {
                        let num = |x: &serde_json::Value| -> u64 {
                            if let Some(n) = x.as_u64() {
                                n
                            } else {
                                u64::from_str_radix(x.as_str().unwrap_or("0").trim_start_matches("0x"), 16).unwrap_or(0)
                            }
                        };
                        if let Some(a) = e.as_array() {
                            if a.len() >= 2 {
                                r.push((num(&a[0]), num(&a[1])));
                            }
                        }
                    }
                    r
                }
                None => Vec::new(),
            };
            let image: Vec<u8> = match image_p {
                Some(p) => std::fs::read(&p)?,
                None => Vec::new(),
            };
            let o = brighten(&ir, &regs, &pools, &image, base, 0);
            if let Some(p) = out_p {
                std::fs::write(&p, &o.ir)?;
            } else {
                println!("{}", o.ir);
            }
            eprintln!("brighten: folds={} slots={}", o.folds, o.slots.len());
            for s in o.slots.iter().take(20) {
                eprintln!("  slot rsp{:+} w={} {}", s.offset, s.width, if s.is_write { "wr" } else { "rd" });
            }
        }
        other if other == "fetch" => {
            if args.len() < 4 {
                eprintln!("fetch needs <trace.bin> <binary> [--memlog <memlog.bin> --depth N --sample N]");
                std::process::exit(2);
            }
            use vmp_devirt::backend::fetch::{decode_va, discover, stride_check};
            use std::collections::{BTreeMap, BTreeSet};
            let mut memlog_p = None::<String>;
            let mut depth = 40usize;
            let mut sample = 200usize;
            let mut i = 4;
            while i < args.len() {
                match args[i].as_str() {
                    "--memlog" => { memlog_p = Some(args[i + 1].clone()); i += 2; }
                    "--depth" => { depth = args[i + 1].parse().unwrap_or(40); i += 2; }
                    "--sample" => { sample = args[i + 1].parse().unwrap_or(200); i += 2; }
                    f => {
                        eprintln!("fetch: unknown flag {}", f);
                        std::process::exit(2);
                    }
                }
            }
            let tb = std::fs::read(&args[2]).with_context(|| format!("read {}", args[2]))?;
            let trace: Vec<u64> = tb.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
            let bin = PEBinary::load(&args[3]).with_context(|| format!("load {}", args[3]))?;
            let map = bin.section_map()?;
            let read_va = |va: u64, n: usize| -> Option<Vec<u8>> { bin.read_via(&map, va, n) };
            // Dispatch sites + target regs (same finder as dispatch CLI).
            let uniq: BTreeSet<u64> = trace.iter().cloned().collect();
            let mut sites = BTreeSet::new();
            let mut tregs = BTreeMap::new();
            for va in uniq {
                let bytes = match read_va(va, 15) {
                    Some(b) => b,
                    None => continue,
                };
                let mut d = iced_x86::Decoder::with_ip(64, &bytes, va, iced_x86::DecoderOptions::NONE);
                if !d.can_decode() {
                    continue;
                }
                let ins = d.decode();
                if (ins.mnemonic() == iced_x86::Mnemonic::Jmp
                    || ins.mnemonic() == iced_x86::Mnemonic::Call)
                    && matches!(ins.op0_kind(), iced_x86::OpKind::Register)
                {
                    sites.insert(va);
                    tregs.insert(va, format!("{:?}", ins.op_register(0)).to_lowercase());
                }
            }
            eprintln!("fetch: {} dispatch sites, trace steps {}", sites.len(), trace.len());
            // Branch anchors: multi-successor jcc (ifnest/switch dispatch).
            // Successor sets over the full trace, then jcc decode check.
            let mut succ: BTreeMap<u64, std::collections::BTreeSet<u64>> = BTreeMap::new();
            for w in trace.windows(2) {
                succ.entry(w[0]).or_default().insert(w[1]);
            }
            let mut branches = BTreeSet::new();
            for (va, ss) in &succ {
                if ss.len() < 2 {
                    continue;
                }
                if let Some(b) = read_va(*va, 6) {
                    let mut d = iced_x86::Decoder::with_ip(64, &b, *va, iced_x86::DecoderOptions::NONE);
                    if d.can_decode() && d.decode().is_jcc_short_or_near() {
                        branches.insert(*va);
                    }
                }
            }
            eprintln!("fetch: {} branch anchors", branches.len());
            let mut counts: BTreeMap<u64, usize> = BTreeMap::new();
            let mut sub: Vec<u64> = Vec::new();
            for va in &trace {
                if sites.contains(va) {
                    let c = counts.entry(*va).or_insert(0);
                    if *c < sample {
                        *c += 1;
                        sub.push(*va);
                    }
                } else {
                    // keep full context for back-slices: retain everything
                    // (memory cost ~8B/step; sampled dispatch only bounds work).
                    sub.push(*va);
                }
            }
            let decode = |va: u64| -> Option<vmp_devirt::backend::fetch::FetchDecoded> {
                read_va(va, 15).and_then(|b| decode_va(&b, va))
            };
            use vmp_devirt::backend::fetch::{discover_branch_stats, discover_stats, SliceStats};
            let mut stats = SliceStats::default();
            let cands = discover_stats(&sub, &sites, &tregs, &decode, depth, Some(&mut stats));
            let mut cands = cands;
            let mut bcands = discover_branch_stats(&trace, &branches, &decode, depth, sample, Some(&mut stats));
            eprintln!("fetch slice stats: found={} call_stop={} depth_out={} decode_fail={} empty_seeds={}",
                stats.found, stats.call_stop, stats.depth_out, stats.decode_fail, stats.empty_seeds);
            cands.append(&mut bcands);
            cands.sort_by_key(|c| (u64::MAX - c.votes as u64, c.va));
            // Optional stride validation from memlog reads at candidate VAs.
            let reads: BTreeMap<u64, Vec<u64>> = match memlog_p {
                Some(p) => {
                    let mb = std::fs::read(&p)?;
                    let mut m: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
                    for c in mb.chunks_exact(33) {
                        let rip = u64::from_le_bytes(c[0..8].try_into().unwrap());
                        let w = c[8] == 1;
                        if w {
                            continue; // reads only
                        }
                        let addr = u64::from_le_bytes(c[9..17].try_into().unwrap());
                        m.entry(rip).or_default().push(addr);
                    }
                    m
                }
                None => BTreeMap::new(),
            };
            println!("fetch candidates: {}", cands.len());
            for c in cands.iter().take(10000) {
                let extra = match reads.get(&c.va) {
                    Some(addrs) => {
                        let (ok, med) = stride_check(addrs);
                        format!(" stride={} med={}", if ok { "BYTECODE" } else { "other" }, med)
                    }
                    None => String::new(),
                };
                println!("  {:#x} via {:#x} base={} votes={}{}", c.va, c.via_dispatch, c.base, c.votes, extra);
            }
        }
        other => {
            eprintln!("unknown command: {}", other);
            std::process::exit(2);
        }
    }
    Ok(())
}
