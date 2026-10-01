//! Edge-forcing tracer (idea 2 v1) — dispatcher-directed forced execution.
//!
//! Same Unicorn setup as trace_open_fetch (sections, scratch, IAT stubs,
//! IN hook, GPA trap, RVAFIX), plus one mechanism: when RIP reaches
//! FORCE_SITE, execution continues at FORCE_TARGET instead. Pre-force
//! regs are logged (flip-region validation for learned rules).
//!
//! Usage: force_edge <start> <force_site> <force_target>
//! Env: BIN_PATH, DATA_DIR, EFLAGS, IN_RET, BOUND, FORCES (max forces,
//!   default = every visit), IAT_JSON.
//! Out: <DATA_DIR>/open_trace_forced.bin + forced.json.
//! Guard: KNOWN_BIN (u64LE baseline trace) + DERAIL_MAX (default 128) —
//! halt when execution runs more than DERAIL_MAX consecutive addrs never
//! seen in baseline (derailment into encrypted/garbage regions).

use vmp_devirt::pe_loader::PEBinary;
use unicorn_engine::{Unicorn, unicorn_const::{Arch, Mode, Prot}};
use unicorn_engine_sys::RegisterX86;

fn main() -> anyhow::Result<()> {
    let binpath = std::env::var("BIN_PATH").unwrap_or_else(|_| "./target.exe".to_string());
    let bin = PEBinary::load(&binpath)?;
    let pe = bin.parse_pe()?;
    let base = bin.image_base()?;
    let mut vmp_sections = Vec::new();
    for s in &pe.sections {
        let name = std::str::from_utf8(&s.name).unwrap_or("").trim_end_matches('\0');
        let vsize = std::cmp::max(s.virtual_size, s.size_of_raw_data) as usize;
        if vsize == 0 { continue; }
        vmp_sections.push((base + s.virtual_address as u64, s.pointer_to_raw_data as usize, s.size_of_raw_data as usize, vsize, name.to_string()));
    }
    let start: u64 = std::env::args().nth(1).map(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).unwrap()).unwrap_or(0x14077c26d);
    let force_site: u64 = std::env::args().nth(2).map(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).unwrap()).unwrap();
    let force_target: u64 = std::env::args().nth(3).map(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).unwrap()).unwrap();
    let eflags: u64 = std::env::var("EFLAGS").map(|v| u64::from_str_radix(v.trim().trim_start_matches("0x"), 16).unwrap_or(0x202)).unwrap_or(0x202);
    let bound: u64 = std::env::var("BOUND").map(|v| v.parse().unwrap_or(30000000)).unwrap_or(30000000);
    let max_forces: usize = std::env::var("FORCES").map(|v| v.parse().unwrap_or(usize::MAX)).unwrap_or(usize::MAX);
    // State perturbation (idea 4): PERTURB="rsi=0x10,rbp=0x20" writes regs
    // when force_site hits, *before* any RIP override. PERTURB_ONLY=1
    // skips the override (pure perturbation run).
    fn reg_by_name(n: &str) -> Option<RegisterX86> {
        Some(match n {
            "rax" => RegisterX86::RAX, "rbx" => RegisterX86::RBX,
            "rcx" => RegisterX86::RCX, "rdx" => RegisterX86::RDX,
            "rsi" => RegisterX86::RSI, "rdi" => RegisterX86::RDI,
            "rbp" => RegisterX86::RBP, "rsp" => RegisterX86::RSP,
            "r8" => RegisterX86::R8, "r9" => RegisterX86::R9,
            "r10" => RegisterX86::R10, "r11" => RegisterX86::R11,
            "r12" => RegisterX86::R12, "r13" => RegisterX86::R13,
            "r14" => RegisterX86::R14, "r15" => RegisterX86::R15,
            _ => return None,
        })
    }
    let perturb: Vec<(RegisterX86, u64)> = std::env::var("PERTURB").ok()
        .map(|s| {
            s.split(',').filter_map(|kv| {
                let mut it = kv.split('=');
                let r = reg_by_name(it.next()?.trim())?;
                let v = u64::from_str_radix(it.next()?.trim().trim_start_matches("0x"), 16).ok()?;
                Some((r, v))
            }).collect()
        })
        .unwrap_or_default();
    let perturb_only = std::env::var("PERTURB_ONLY").is_ok();
    // Perturbation fires at PERTURB_SITE (default: force_site). It must
    // predate the flag-writing instruction: by branch time the flags
    // are latched and reg writes no longer matter.
    let perturb_site: u64 = std::env::var("PERTURB_SITE")
        .map(|v| u64::from_str_radix(v.trim().trim_start_matches("0x"), 16).unwrap_or(force_site))
        .unwrap_or(force_site);
    if !perturb.is_empty() {
        eprintln!("perturb on {:#x}: {} regs{}", force_site, perturb.len(), if perturb_only { " (no rip override)" } else { "" });
    }
    let dir = std::env::var("DATA_DIR").unwrap_or_else(|_| "./data".to_string());
    // Derailment guard: baseline-known address set + consecutive-unknown budget.
    let known: std::collections::HashSet<u64> = std::env::var("KNOWN_BIN").ok()
        .and_then(|p| std::fs::read(p).ok())
        .map(|b| b.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect())
        .unwrap_or_default();
    let derail_max: usize = std::env::var("DERAIL_MAX").map(|v| v.parse().unwrap_or(128)).unwrap_or(128);
    eprintln!("known={} derail_max={}", known.len(), if known.is_empty() { 0 } else { derail_max });

    let mut emu = Unicorn::new(Arch::X86, Mode::MODE_64).unwrap();
    for (va, off, rawsz, vsize, _n) in &vmp_sections {
        let mapped = ((vsize + 0xfff) & !0xfff) as u64;
        let _ = emu.mem_map(*va, mapped, Prot::ALL);
        if *rawsz > 0 {
            let end = (*off + *rawsz).min(bin.data.len());
            if *off < end { let _ = emu.mem_write(*va, &bin.data[*off..end]); }
        }
    }
    let sparse_hi: u64 = std::env::var("SPARSE_HI").map(|v| u64::from_str_radix(v.trim().trim_start_matches("0x"), 16).unwrap_or(0x80000000)).unwrap_or(0x80000000);
            for b in (0x100000u64..sparse_hi).step_by(0x100000) { let _ = emu.mem_map(b, 0x100000, Prot::ALL); }
    let _ = emu.mem_map(0, 0x1000, Prot::ALL);
    let _ = emu.mem_write(0, &[0xC3u8]);
    // Import stubs (same as tracer; Open.exe slots harmless elsewhere).
    let stub_heap = 0x70000000u64;
    let stub_zero = 0x70000010u64;
    let heap_base = 0x71000000u64;
    let _ = emu.mem_write(stub_heap, &[0x48u8, 0xB8, 0,0,0,0,0,0,0,0, 0xC3]);
    let _ = emu.mem_write(stub_heap + 2, &heap_base.to_le_bytes());
    let _ = emu.mem_write(stub_zero, &[0x31u8, 0xC0, 0xC3]);
    let _ = emu.mem_map(heap_base, 0x100000, Prot::ALL);
    let stub_time = 0x70000020u64;
    let _ = emu.mem_write(stub_time, &[0x48u8, 0xC7, 0x01, 0x00, 0x40, 0x4B, 0x4C, 0xC3]);
    for (slot, tgt) in [(0x14042d0e0u64, stub_heap), (0x14042d128u64, stub_zero),
                        (0x14042d138u64, 0xDEAD0000u64), (0x14042d110u64, stub_zero),
                        (0x14042d0c0u64, stub_time)] {
        let _ = emu.mem_write(slot, &tgt.to_le_bytes());
    }
    if let Ok(txt) = std::fs::read_to_string(std::env::var("IAT_JSON").unwrap_or_default()) {
        if let Ok(map) = serde_json::from_str::<std::collections::HashMap<String, String>>(&txt) {
            let get = |n: &str| map.get(n).and_then(|v| u64::from_str_radix(v.trim().trim_start_matches("0x"), 16).ok());
            for (name, tgt) in [("LocalAlloc", stub_heap), ("GetProcAddress", 0xDEAD0000u64),
                                ("LoadLibraryA", stub_zero), ("Sleep", stub_zero),
                                ("GetSystemTimeAsFileTime", stub_time), ("VirtualAlloc", stub_heap)] {
                if let Some(slot) = get(name) { let _ = emu.mem_write(slot, &tgt.to_le_bytes()); }
            }
        }
    }
    let pool_va = vmp_sections[0].0 + 0x1000;
    let key = 0x42u64;
    for (r, v) in [(RegisterX86::RAX, pool_va), (RegisterX86::RBX, pool_va),
                   (RegisterX86::RCX, 0), (RegisterX86::RDX, 0),
                   (RegisterX86::RSI, pool_va), (RegisterX86::RDI, pool_va),
                   (RegisterX86::RBP, key), (RegisterX86::R8, pool_va),
                   (RegisterX86::R9, pool_va), (RegisterX86::R10, pool_va),
                   (RegisterX86::R11, key), (RegisterX86::RSP, 0x7ffe0000),
                   (RegisterX86::R12, 0), (RegisterX86::R13, 0),
                   (RegisterX86::RIP, start), (RegisterX86::EFLAGS, eflags)] {
        emu.reg_write(r, v).unwrap();
    }
    let in_ret: u32 = std::env::var("IN_RET").map(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).unwrap_or(0)).unwrap_or(0);
    let _in_hook = emu.add_insn_in_hook(move |_emu, _port, _size| in_ret).unwrap();
    let _mem_hook = emu.add_mem_hook(unicorn_engine::unicorn_const::HookType::MEM_UNMAPPED, 0, 0xffffffffffffffff, move |emu, _mtype, addr, _size, _val| {
        if addr < 0x1000000 {
            let cand = base + addr;
            let mut pb = [0u8; 16];
            if emu.mem_read(cand, &mut pb).is_ok() {
                use iced_x86::{Decoder, DecoderOptions, Mnemonic};
                let mut d = Decoder::with_ip(64, &pb, cand, DecoderOptions::NONE);
                let mut ok = 0;
                let mut bad = false;
                for _ in 0..4 {
                    if !d.can_decode() { bad = true; break; }
                    let ins = d.decode();
                    match ins.mnemonic() {
                        Mnemonic::In | Mnemonic::Out | Mnemonic::Insd | Mnemonic::Outsd
                        | Mnemonic::Insb | Mnemonic::Outsb | Mnemonic::Hlt => { bad = true; break; }
                        _ => {}
                    }
                    if ins.is_invalid() { bad = true; break; }
                    ok += 1;
                }
                if ok >= 2 && !bad {
                    let _ = emu.reg_write(RegisterX86::RIP, cand);
                    return true;
                }
            }
        }
        if addr == 0xDEAD0000 {
            let rsp: u64 = emu.reg_read(RegisterX86::RSP).unwrap_or(0);
            let mut rb = [0u8; 8];
            let ret = emu.mem_read(rsp, &mut rb).map(|_| u64::from_le_bytes(rb)).unwrap_or(0);
            let _ = emu.reg_write(RegisterX86::RSP, rsp + 8);
            let _ = emu.reg_write(RegisterX86::RIP, ret);
            let _ = emu.reg_write(RegisterX86::RAX, 0);
            return true;
        }
        false
    }).unwrap();

    let trace = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let t = trace.clone();
    // Pre-force reg snapshots (flip-region validation): rsi/rbp + code.
    // Plus 256B live bytes at the force target: promotion input for
    // mine-hits (final dumps are SMC re-encrypted; hit-time is truth).
    let pre = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let p = pre.clone();
    let forces = std::sync::Arc::new(std::sync::Mutex::new(0usize));
    let f = forces.clone();
    // Derailment state shared out of the hook.
    let unknown_run = std::sync::Arc::new(std::sync::Mutex::new(0usize));
    let u = unknown_run.clone();
    let derailed = std::sync::Arc::new(std::sync::Mutex::new(false));
    let d = derailed.clone();
    let pert = perturb.clone();
    let pert_only = perturb_only;
    let pert_site = perturb_site;
    let mut count = 0u64;
    let hook = emu.add_code_hook(1, 0, move |emu, addr, _size| {
        count += 1;
        t.lock().unwrap().push(addr);
        if !known.is_empty() {
            let mut r = u.lock().unwrap();
            if known.contains(&addr) {
                *r = 0;
            } else {
                *r += 1;
                if *r > derail_max {
                    *d.lock().unwrap() = true;
                    emu.emu_stop().ok();
                    return;
                }
            }
        }
        // State perturbation at PERTURB_SITE (must predate the
        // flag-writer; by branch time flags are latched).
        if addr == pert_site && !pert.is_empty() {
            let n = *f.lock().unwrap();
            if n < max_forces {
                for (r, v) in &pert {
                    let _ = emu.reg_write(*r, *v);
                }
                *f.lock().unwrap() += 1;
                if pert_only {
                    return;
                }
            }
        }
        if addr == force_site {
            let n = *f.lock().unwrap();
            if n < max_forces {
                let rsi = emu.reg_read(RegisterX86::RSI).unwrap_or(0);
                let rbp = emu.reg_read(RegisterX86::RBP).unwrap_or(0);
                if p.lock().unwrap().len() < 8 {
                    let mut cb = [0u8; 256];
                    let code_hex = emu.mem_read(force_target, &mut cb).ok()
                        .map(|_| cb.iter().map(|x| format!("{:02x}", x)).collect::<String>())
                        .unwrap_or_default();
                    p.lock().unwrap().push((rsi, rbp, code_hex));
                }
                *f.lock().unwrap() += 1;
                if !pert_only {
                    let _ = emu.reg_write(RegisterX86::RIP, force_target);
                    return;
                }
            }
        }
        if count > bound {
            emu.emu_stop().ok();
        }
    }).unwrap();
    let res = emu.emu_start(start, u64::MAX, 0, (bound + 1000) as usize);
    emu.remove_hook(hook)?;
    let trace = trace.lock().unwrap().clone();
    let pre = pre.lock().unwrap().clone();
    let nforces = *forces.lock().unwrap();
    let was_derailed = *derailed.lock().unwrap();
    let end_rip = emu.reg_read(RegisterX86::RIP).unwrap_or(0);
    // Persist trace + summary.
    let mut buf = Vec::with_capacity(trace.len() * 8);
    for a in &trace { buf.extend_from_slice(&a.to_le_bytes()); }
    std::fs::create_dir_all(&dir)?;
    std::fs::write(format!("{}/open_trace_forced.bin", dir), &buf)?;
    let res_str = match &res { Ok(_) => "Ok", Err(_) => "Err" };
    let mut js = format!("{{\"site\": \"{:#x}\", \"target\": \"{:#x}\", \"forces\": {}, \"steps\": {}, \"end_rip\": \"{:#x}\", \"derailed\": {}, \"res\": \"{}\", \"pre\": [",
        force_site, force_target, nforces, trace.len(), end_rip, was_derailed, res_str);
    for (i, (rsi, rbp, code)) in pre.iter().enumerate() {
        if i > 0 { js.push(','); }
        js.push_str(&format!("{{\"rsi\": {}, \"rbp\": {}, \"site\": \"{:#x}\", \"code\": \"{}\"}}", rsi, rbp, force_target, code));
    }
    js.push_str("]}");
    std::fs::write(format!("{}/forced.json", dir), &js)?;
    let uniq: std::collections::BTreeSet<u64> = trace.iter().cloned()
        .filter(|a| (0x140000000u64..0x143000000u64).contains(a)).collect();
    println!("forced {}x {:#x} -> {:#x}: steps={} uniq={} end={:#x} derailed={} res={}{}",
        nforces, force_site, force_target, trace.len(), uniq.len(), end_rip, was_derailed, res_str,
        if perturb_only { " [perturb-only, no rip override]" } else { "" });
    Ok(())
}
