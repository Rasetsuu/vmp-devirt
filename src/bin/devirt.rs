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
        std::process::exit(2);
    }
    let bin = if ["merge", "map", "sense", "dispatch", "mine-live", "mine-hits", "handlers", "synth"].contains(&args[1].as_str()) {
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
                    for h in f.handler_addrs(&bin, &[]).unwrap_or_default().iter().take(500) {
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
            let movzx = d.decode();
            // movsx accepted too: SMC flips B6<->BE (cf. fetch_finder).
            if movzx.mnemonic() != iced_x86::Mnemonic::Movzx
                && movzx.mnemonic() != iced_x86::Mnemonic::Movsx
            {
                anyhow::bail!("{:#x} is not a movzx/movsx fetch site", va);
            }
            let site = FetchSite {
                va,
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
            // Parse sections a single time; PEBinary::read_bytes re-parses
            // the PE per call (too slow for 90k sites).
            use std::collections::{BTreeSet, HashSet};
            let pe = bin.parse_pe()?;
            let image_base = bin.image_base().unwrap_or(0x140000000);
            let mut sects = Vec::new();
            for s in &pe.sections {
                let start = image_base + s.virtual_address as u64;
                let end = start + s.virtual_size.max(s.size_of_raw_data) as u64;
                sects.push((start, end, s.pointer_to_raw_data as usize, s.virtual_address as usize));
            }
            let read_va = |va: u64, n: usize| -> Option<Vec<u8>> {
                for (start, end, raw, _rva) in &sects {
                    if va >= *start && va + n as u64 <= *end {
                        let off = *raw + (va - *start) as usize;
                        return bin.data.get(off..off + n).map(|b| b.to_vec());
                    }
                }
                None
            };
            let uniq: BTreeSet<u64> = trace.iter().cloned().collect();
            let mut indirect: HashSet<u64> = HashSet::new();
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
                }
            }
            let tables = dispatch_tables(&trace, &|va| indirect.contains(&va));
            println!("indirect dispatch sites: {}", tables.len());
            let mut multi = 0;
            for (va, succ) in tables.iter().take(40) {
                println!("  {:#x}: {} targets {}", va, succ.len(),
                    succ.iter().take(6).map(|s| format!("{:#x}", s)).collect::<Vec<_>>().join(" | "));
            }
            for (_, succ) in tables.iter() {
                if succ.len() > 1 {
                    multi += 1;
                }
            }
            println!("multi-target dispatchers (total): {}", multi);
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
            let fetch = d.decode();
            if fetch.mnemonic() != iced_x86::Mnemonic::Movzx
                && fetch.mnemonic() != iced_x86::Mnemonic::Movsx
            {
                anyhow::bail!("{:#x} is not a movzx/movsx fetch site in overlay", va);
            }
            let site = FetchSite {
                va,
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
                let mut d = iced_x86::Decoder::with_ip(64, code, *va, iced_x86::DecoderOptions::NONE);
                let fetch = d.decode();
                if fetch.mnemonic() != iced_x86::Mnemonic::Movzx
                    && fetch.mnemonic() != iced_x86::Mnemonic::Movsx
                {
                    continue;
                }
                let site = FetchSite {
                    va: *va,
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
            let mut indirect: HashSet<u64> = HashSet::new();
            for va in uniq {
                let bytes = match bin.read_via(&map, va, 6) {
                    Some(b) => b,
                    None => continue,
                };
                let mut d = iced_x86::Decoder::with_ip(64, &bytes, va, iced_x86::DecoderOptions::NONE);
                let ins = d.decode();
                if ins.mnemonic() == iced_x86::Mnemonic::Jmp
                    && matches!(ins.op0_kind(), iced_x86::OpKind::Register)
                {
                    indirect.insert(va);
                }
            }
            let blocks = detect_handlers(&trace, &writes, &|va| indirect.contains(&va));
            println!("writes={} indirect_jmps={} handlers={}", writes.len(), indirect.len(), blocks.len());
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
        other => {
            eprintln!("unknown command: {}", other);
            std::process::exit(2);
        }
    }
    Ok(())
}
