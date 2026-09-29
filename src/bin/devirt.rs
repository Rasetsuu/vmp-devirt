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
        std::process::exit(2);
    }
    let bin = if ["merge", "map", "sense"].contains(&args[1].as_str()) {
        // Merge/sense work on raw files; map needs no binary.
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
            if movzx.mnemonic() != iced_x86::Mnemonic::Movzx {
                anyhow::bail!("{:#x} is not a movzx fetch site", va);
            }
            let site = FetchSite {
                va,
                base: movzx.memory_base(),
                dst: movzx.op0_register(),
                len: movzx.len(),
            };
            let m = mine_cryptor(&site, &bin)?;
            println!("site {:#x} key={} steps={} {:?}", va, m.key_reg, m.steps, m.cryptor.cmds);
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
        other => {
            eprintln!("unknown command: {}", other);
            std::process::exit(2);
        }
    }
    Ok(())
}
