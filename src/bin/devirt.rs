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
        std::process::exit(2);
    }
    let bin = PEBinary::load(&args[2]).with_context(|| format!("load {}", args[2]))?;
    match args[1].as_str() {
        "scan" => {
            for f in frontends() {
                let applies = f.detect(&bin).unwrap_or(false);
                println!("frontend {:<10} applies={}", f.name(), applies);
                if applies {
                    for h in f.handler_addrs(&bin, &[]).unwrap_or_default().iter().take(20) {
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
        other => {
            eprintln!("unknown command: {}", other);
            std::process::exit(2);
        }
    }
    Ok(())
}
