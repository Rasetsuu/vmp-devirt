//! Open.exe fetch tracer — Unicorn snapshot starting AT the fetch site.
//! Maps image + scratch, IN-hook returns 0, 500-step bound, logs every
//! fetch hit (regs + raw byte). Driver never executes.
use vmp_devirt::pe_loader::PEBinary;
use unicorn_engine::{Unicorn, unicorn_const::{Arch, Mode, Prot}};
use unicorn_engine_sys::RegisterX86;

fn main() -> anyhow::Result<()> {
    let binpath = std::env::var("BIN_PATH").unwrap_or_else(|_| "./target.exe".to_string());
    let bin = PEBinary::load(&binpath)?;
    let base = bin.image_base()?;
    // Map ALL sections (not just .vmp) so entry stub code/data resolve.
    // Format-agnostic via map_sections (PE RVAs / ELF absolute addrs).
    let mut vmp_sections = Vec::new();
    for (name, va, off, rawsz, vsize) in bin.map_sections()? {
        vmp_sections.push((va, off, rawsz, vsize, name));
    }
    println!("Sections: {:?}", vmp_sections.iter().map(|(va,_,rawsz,vsize,n)| format!("{} {:#x} virt{}KB raw{}KB", n, va, vsize/1024, rawsz/1024)).collect::<Vec<_>>());
    let start: u64 = std::env::args().nth(1).map(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).unwrap()).unwrap_or(0x140588eda);
    let watch_arg: u64 = std::env::args().nth(2).map(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).unwrap()).unwrap_or(start);
    let entry_mode = std::env::args().len() > 2;
    // Watch set: requested VA + (entry mode) executed-movzx file or strict scan.
    let mut watches = std::collections::BTreeSet::new();
    watches.insert(watch_arg);
    if entry_mode {
        let secname = std::env::var("SECNAME").unwrap_or_else(|_| ".vmp1".to_string());
        if let Ok(txt) = std::fs::read_to_string(std::env::var("WATCH_FILE").unwrap_or_else(|_| format!("{}/watch.txt", std::env::var("DATA_DIR").unwrap_or_else(|_| "./data".to_string())))) {
            for l in txt.lines() {
                if let Ok(v) = u64::from_str_radix(l.trim().trim_start_matches("0x"), 16) { watches.insert(v); }
            }
        } else {
            use vmp_devirt::frontend::fetch_finder::scan_fetch_sites_strict;
            if let Ok(pe2) = bin.parse_pe() {
                if let Ok(base2) = bin.image_base() {
                    for s in &pe2.sections {
                        let name = std::str::from_utf8(&s.name).unwrap_or("").trim_end_matches('\0');
                        if name == secname {
                            let va = base2 + s.virtual_address as u64;
                            let off = s.pointer_to_raw_data as usize;
                            let data = &bin.data[off..off + s.size_of_raw_data as usize];
                            for fs in scan_fetch_sites_strict(data, va) { watches.insert(fs.va); }
                        }
                    }
                }
            }
        }
    }
    eprintln!("watching {} addrs", watches.len());
    // Per-site base register: decode movzx at each watch VA (file bytes; all in .vmp1).
    let mut sitemap = std::collections::HashMap::new();
    {
        use iced_x86::{Decoder, DecoderOptions, Mnemonic};
        use iced_x86::Register as IR;
        for va in watches.iter() {
            if let Ok(b) = bin.read_bytes(*va, 8) {
                let mut d = Decoder::with_ip(64, &b, *va, DecoderOptions::NONE);
                let ins = d.decode();
                // Any byte-load feeds the watch map, not just movzx:
                // the sensor proposes shapes, the tracer must not
                // re-narrow them (architectural seam fix).
                let is_byte_load = matches!(
                    ins.mnemonic(),
                    Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Mov
                ) && ins.memory_base() != IR::None;
                if is_byte_load {
                    let xr = match ins.memory_base() {
                        IR::RAX => RegisterX86::RAX, IR::RBX => RegisterX86::RBX,
                        IR::RCX => RegisterX86::RCX, IR::RDX => RegisterX86::RDX,
                        IR::RSI => RegisterX86::RSI, IR::RDI => RegisterX86::RDI,
                        IR::RBP => RegisterX86::RBP, IR::R8 => RegisterX86::R8,
                        IR::R9 => RegisterX86::R9, IR::R10 => RegisterX86::R10,
                        IR::R11 => RegisterX86::R11, _ => RegisterX86::RAX,
                    };
                    sitemap.insert(*va, (ins.memory_base(), xr, ins.op0_register()));
                }
            }
        }
    }
    {
        // Legacy strict-scan entries only fill gaps (2-tuple + dummy dst).
        use vmp_devirt::frontend::fetch_finder::scan_fetch_sites_strict;
        use iced_x86::Register as IR;
        if let Ok(pe2) = bin.parse_pe() {
            if let Ok(base2) = bin.image_base() {
                for s in &pe2.sections {
                    let name = std::str::from_utf8(&s.name).unwrap_or("").trim_end_matches('\0');
                    if name == ".vmp1" {
                        let va = base2 + s.virtual_address as u64;
                        let off = s.pointer_to_raw_data as usize;
                        let data = &bin.data[off..off + s.size_of_raw_data as usize];
                        for fs in scan_fetch_sites_strict(data, va) {
                            if sitemap.contains_key(&fs.va) { continue; }
                            let xr = match fs.base {
                                IR::RAX => RegisterX86::RAX, IR::RBX => RegisterX86::RBX,
                                IR::RCX => RegisterX86::RCX, IR::RDX => RegisterX86::RDX,
                                IR::RSI => RegisterX86::RSI, IR::RDI => RegisterX86::RDI,
                                IR::RBP => RegisterX86::RBP, IR::R8 => RegisterX86::R8,
                                IR::R9 => RegisterX86::R9, IR::R10 => RegisterX86::R10,
                                IR::R11 => RegisterX86::R11, _ => RegisterX86::RAX,
                            };
                            sitemap.insert(fs.va, (fs.base, xr, fs.dst));
                        }
                    }
                }
            }
        }
    }
    // ELF PLT stub table (PLT_STUBS=1): plt_va -> libc name, from
    // .rela.plt order (push-imm index) + dynsym/dynstr. Manual section
    // parsing (no dynamic-API dependence).
    let mut plt_stubs = std::collections::HashMap::new();
    if std::env::var("PLT_STUBS").is_ok() {
        if let Ok(elf) = bin.parse_elf() {
            if let (Ok(plt), Ok(rela)) = (bin.get_section(".plt"), bin.get_section(".rela.plt")) {
                // plt base VA
                let plt_va = bin.map_sections().ok().and_then(|m| {
                    m.into_iter().find(|(n, _, _, _, _)| n == ".plt").map(|(_, va, _, _, _)| va)
                }).unwrap_or(0);
                // rela entries: (r_offset:64, r_info:64, addend:64); sym = r_info >> 32
                let mut names: Vec<String> = Vec::new();
                for c in rela.chunks_exact(24) {
                    let info = u64::from_le_bytes(c[8..16].try_into().unwrap_or([0; 8]));
                    let sym = (info >> 32) as usize;
                    let nm = elf.dynsyms.to_vec().get(sym)
                        .and_then(|s| elf.dynstrtab.get_at(s.st_name))
                        .unwrap_or("").to_string();
                    names.push(nm);
                }
                // entries start after the 16-byte resolver slot, 16 bytes each
                for (i, nm) in names.iter().enumerate() {
                    if ["memcpy", "memset", "memmove"].contains(&nm.as_str()) {
                        plt_stubs.insert(plt_va + 16 + i as u64 * 16, nm.clone());
                    }
                }
            }
        }
        eprintln!("  PLT stubs: {} ({:?})", plt_stubs.len(),
            plt_stubs.values().collect::<Vec<_>>());
    }
    let sites = [start];
    // EFLAGS variants to force jle taken (ZF=1) / not-taken, etc.
    // Entry mode: EFLAGS env override (multi-state coverage runs).
    let eflags_def = std::env::var("EFLAGS").map(|v| u64::from_str_radix(v.trim().trim_start_matches("0x"), 16).unwrap_or(0x202)).unwrap_or(0x202);
    let eflags_entry = [eflags_def];
    let eflags_snap = [0x46u64, 0x202u64];
    // With explicit start+watch (entry mode), single neutral run.
    for &site in &sites {
        for &eflags in if entry_mode { &eflags_entry[..] } else { &eflags_snap[..] } {
            for &key in &[0x42u64] {
            let mut emu = Unicorn::new(Arch::X86, Mode::MODE_64).unwrap();
            // Page-align section maps (ELF sections are not page-aligned;
            // Unicorn mem_map fails silently on unaligned bases).
            let align_map = |va: u64, vsize: usize| -> (u64, u64) {
                let start = va & !0xfff;
                (((vsize as u64 + (va - start) + 0xfff) & !0xfff), start)
            };
            // Gap-filling mapper: overlapping aligned ranges map once;
            // writes are CHUNKED per mapped page (a single overhanging
            // write fails whole (flatvirt .text lost 4KB to 0x44 bytes)).
            let mut done: Vec<(u64, u64)> = Vec::new();
            for (va, off, rawsz, vsize, _n) in &vmp_sections {
                let (mapped, start) = align_map(*va, *vsize);
                let end = start + mapped;
                // subtract coverage, map gaps
                let mut gaps = vec![(start, end)];
                for d in &done {
                    let mut next = Vec::new();
                    for g in gaps {
                        if g.1 <= d.0 || g.0 >= d.1 {
                            next.push(g);
                            continue;
                        }
                        if g.0 < d.0 {
                            next.push((g.0, d.0));
                        }
                        if g.1 > d.1 {
                            next.push((d.1, g.1));
                        }
                    }
                    gaps = next;
                }
                for g in gaps {
                    if emu.mem_map(g.0, g.1 - g.0, Prot::ALL).is_ok() {
                        done.push((g.0, g.1));
                    }
                }
                if *rawsz > 0 {
                    // chunked write: page-granular so partial coverage sticks.
                    // (pg must ADVANCE past cur: (cur+0xfff)&~0xfff stalls
                    // when cur is already aligned — flatvirt lost 0x84 bytes
                    // of .text to exactly this.)
                    let mut cur = *va;
                    let fend = (*off + *rawsz).min(bin.data.len());
                    let mut foff = *off;
                    while foff < fend {
                        let pg = (cur | 0xfff) + 1;
                        let n = (pg - cur).min((fend - foff) as u64) as usize;
                        if n == 0 {
                            break;
                        }
                        let _ = emu.mem_write(cur, &bin.data[foff..foff + n]);
                        cur += n as u64;
                        foff += n;
                    }
                }
            }
            // RVA alias mapping (ALIAS_RVA=1): some protectors (3.8.1)
            // dispatch by RVA (image-base independent). Aliasing lets
            // raw-RVA jumps land in real code. Overlaps fail silently.
            if std::env::var("ALIAS_RVA").is_ok() {
                for (va, off, rawsz, vsize, _n) in &vmp_sections {
                    let rva = va.wrapping_sub(base);
                    if rva == *va { continue; }
                    let rstart = rva & !0xfff;
                    let rsize = ((vsize + (rva - rstart) as usize + 0xfff) & !0xfff) as u64;
                    if emu.mem_map(rstart, rsize, Prot::ALL).is_ok() && *rawsz > 0 {
                        let end = (*off + *rawsz).min(bin.data.len());
                        if *off < end { let _ = emu.mem_write(rva, &bin.data[*off..end]); }
                    }
                }
                eprintln!("  RVA alias mapping on");
            }
            let sparse_hi: u64 = std::env::var("SPARSE_HI").map(|v| u64::from_str_radix(v.trim().trim_start_matches("0x"), 16).unwrap_or(0x80000000)).unwrap_or(0x80000000);
            for b in (0x100000u64..sparse_hi).step_by(0x100000) { let _ = emu.mem_map(b, 0x100000, Prot::ALL); }
            // Zero page with `ret`: unbound IAT calls (target 0) return cleanly.
            let _ = emu.mem_map(0, 0x1000, Prot::ALL);
            let _ = emu.mem_write(0, &[0xC3u8]);
            // Minimal TEB/PEB (TEB_INIT=1): some protectors (3.8.1) read
            // the image base from PEB (fs:[0x60] -> PEB+0x10) for RVA
            // dispatch; under emulation fs reads 0 without this.
            // Layout: TEB at 0x7FFF0000, PEB at 0x7FFF1000 (both inside
            // the sparse range); FS_BASE set, GS_BASE zeroed.
            if std::env::var("TEB_INIT").is_ok() {
                let teb = 0x7FFF0000u64;
                let peb = 0x7FFF1000u64;
                let _ = emu.mem_write(teb + 0x08, &0x7ffe0000u64.to_le_bytes()); // StackBase
                let _ = emu.mem_write(teb + 0x10, &0x7ff00000u64.to_le_bytes()); // StackLimit
                let _ = emu.mem_write(teb + 0x60, &peb.to_le_bytes()); // ProcessEnvironmentBlock
                let _ = emu.mem_write(peb + 0x02, &[0u8]); // BeingDebugged = 0
                let _ = emu.mem_write(peb + 0x10, &base.to_le_bytes()); // ImageBaseAddress
                let _ = emu.reg_write(RegisterX86::FS_BASE, teb);
                let _ = emu.reg_write(RegisterX86::GS_BASE, 0);
                eprintln!("  TEB/PEB stubbed: teb={:#x} peb={:#x} base={:#x}", teb, peb, base);
            }
            if entry_mode {
                // Determinize: nop the single rdtsc (anti-debug timing gate post-fetch).
                if let Ok(b) = bin.read_bytes(0x14084952bu64, 2) {
                    if b == [0x0Fu8, 0x31] {
                        let _ = emu.mem_write(0x14084952bu64, &[0x66u8, 0x90]);
                        eprintln!("  patched rdtsc @ 0x14084952b");
                    }
                }
                // Synthetic import stubs in scratch + IAT poke (.vmp0 IAT is zero on disk).
                // stub_heap: bump allocator — rax=cur; cur+=(rdx+15)&~15; ret.
                // (Constant-heap aliases every allocation; bump keeps them distinct.)
                // stub_zero: xor eax,eax; ret — LoadLibraryA/GetProcAddress/Sleep.
                let stub_heap = 0x70000000u64;
                let stub_zero = 0x70000040u64;
                let heap_base = 0x71000000u64;
                {
                    // mov rax,[rel cur]; lea rcx,[rdx+15]; and rcx,-16; add [rel cur],rcx; ret; cur: dq base
                    let cur = stub_heap + 32;
                    let mut c = vec![0x48u8, 0x8B, 0x05];
                    c.extend_from_slice(&((cur - (stub_heap + 7)) as u32).to_le_bytes());
                    c.extend_from_slice(&[0x48, 0x8D, 0x4A, 0x0F, 0x48, 0x83, 0xE1, 0xF0]);
                    c.extend_from_slice(&[0x48, 0x01, 0x0D]);
                    c.extend_from_slice(&((cur - (stub_heap + 22)) as u32).to_le_bytes());
                    c.push(0xC3);
                    while c.len() < 32 { c.push(0x90); }
                    let _ = emu.mem_write(stub_heap, &c);
                    let _ = emu.mem_write(cur, &heap_base.to_le_bytes());
                }
                let _ = emu.mem_write(stub_zero, &[0x31u8, 0xC0, 0xC3]);
                let _ = emu.mem_map(heap_base, 0x100000, Prot::ALL);
                // stub_time: mov qword [rcx], FIXED; ret (GetSystemTimeAsFileTime).
                let stub_time = 0x70000050u64;
                let _ = emu.mem_write(stub_time, &[0x48u8, 0xC7, 0x01, 0x00, 0x40, 0x4B, 0x4C, 0xC3]);
                // Const stubs: mov rax, imm64; ret (11 bytes each).
                let mut stub_cur = 0x70000080u64;
                let mut const_jobs: Vec<(String, u64, u64)> = Vec::new();
                for (name, val) in [("GetCurrentProcess", 0xFFFFFFFFFFFFFFFFu64),
                                    ("GetCurrentThread", 0xFFFFFFFFFFFFFFFEu64),
                                    ("GetCurrentThreadId", 0x1001u64),
                                    ("GetCurrentProcessId", 0x1000u64),
                                    ("GetModuleHandleW", base)] {
                    let a = stub_cur;
                    stub_cur += 16;
                    const_jobs.push((name.to_string(), val, a));
                }
                // (writes happen below, no closure borrows emu)
                for (slot, tgt) in [(0x14042d0e0u64, stub_heap), (0x14042d128u64, stub_zero),
                                    (0x14042d138u64, 0xDEAD0000u64), (0x14042d110u64, stub_zero),
                                    (0x14042d0c0u64, stub_time)] {
                    let _ = emu.mem_write(slot, &tgt.to_le_bytes());
                }
                // Generic IAT stubbing from JSON map (other binaries; overrides above).
                if let Ok(txt) = std::fs::read_to_string(std::env::var("IAT_JSON").unwrap_or_default()) {
                    if let Ok(map) = serde_json::from_str::<std::collections::HashMap<String, String>>(&txt) {
                        let get = |n: &str| map.get(n).and_then(|v| u64::from_str_radix(v.trim().trim_start_matches("0x"), 16).ok());
                        let rules = [("LocalAlloc", stub_heap), ("GetProcAddress", 0xDEAD0000u64),
                                     ("LoadLibraryA", stub_zero), ("Sleep", stub_zero),
                                     ("GetSystemTimeAsFileTime", stub_time), ("VirtualAlloc", stub_heap)];
                        for (name, tgt) in rules {
                            if let Some(slot) = get(name) {
                                let _ = emu.mem_write(slot, &tgt.to_le_bytes());
                                eprintln!("  IAT {} -> {:#x}", name, tgt);
                            }
                        }
                        for (name, val, a) in &const_jobs {
                            let mut code = vec![0x48u8, 0xB8];
                            code.extend_from_slice(&val.to_le_bytes());
                            code.push(0xC3);
                            let _ = emu.mem_write(*a, &code);
                            if let Some(slot) = get(name) {
                                let _ = emu.mem_write(slot, &a.to_le_bytes());
                                eprintln!("  IAT {} -> const {:#x}", name, val);
                            }
                        }
                        // Fallback: every other known slot returns 0 (documented
                        // harness lie; beats call-into-void). Heap-ish names get
                        // heap so callers can dereference the result.
                        let mut nfb = 0;
                        for (name, vs) in map.iter() {
                            let handled = rules.iter().any(|(r, _)| r == name)
                                || const_jobs.iter().any(|(n, _, _)| n == name);
                            if handled { continue; }
                            if let Ok(slot) = u64::from_str_radix(vs.trim().trim_start_matches("0x"), 16) {
                                let heapish = ["Alloc", "Heap", "Virtual", "malloc", "Global", "Local", "MapView"].iter().any(|k| name.contains(k));
                                let _ = emu.mem_write(slot, &(if heapish { stub_heap } else { stub_zero }).to_le_bytes());
                                nfb += 1;
                            }
                        }
                        if nfb > 0 { eprintln!("  IAT fallback zero/heap: {} slots", nfb); }
                    }
                }
                eprintln!("  IAT stubbed: LocalAlloc->heap {:#x}", heap_base);
            }
            let pool_va = vmp_sections[0].0 + 0x1000;
            // DLL mode: proper DllMain(hinst, DLL_PROCESS_ATTACH, 0) args.
            let dll_mode = std::env::var("DLL_MAIN").is_ok();
            let (a_rcx, a_rdx, a_r8) = if dll_mode { (base, 1u64, 0u64) } else { (0, 0, pool_va) };
            // Forged injector context: magic "csm\xe0" at [rbp] (stager checks it).
            // RBP/R12/R13 carry injector state; point them at scratch struct.
            let ctx = 0x72000000u64;
            if dll_mode {
                let _ = emu.mem_map(ctx, 0x10000, Prot::ALL);
                let _ = emu.mem_write(ctx, &0xe06d7363u32.to_le_bytes());
            }
            // FRAME_INIT=1: real stack frame for frame-based VMs (ELF/Tigress).
            // RBP=RSP=stack top so rbp-relative locals address real memory;
            // RDI/RSI/... from ARGS="rdi=0x1,rsi=0x2" (function arguments).
            // Default (unset) keeps the VMP forged-injector context.
            let frame = std::env::var("FRAME_INIT").is_ok();
            let mut argmap = std::collections::HashMap::new();
            if let Ok(a) = std::env::var("ARGS") {
                for kv in a.split(',') {
                    let mut it = kv.split('=');
                    if let (Some(k), Some(v)) = (it.next(), it.next()) {
                        if let Ok(n) = u64::from_str_radix(v.trim().trim_start_matches("0x"), 16) {
                            argmap.insert(k.trim().to_lowercase(), n);
                        }
                    }
                }
            }
            let arg = |r: &str, dflt: u64| *argmap.get(r).unwrap_or(&dflt);
            for (r, v) in [(RegisterX86::RAX, pool_va), (RegisterX86::RBX, pool_va),
                           (RegisterX86::RCX, a_rcx), (RegisterX86::RDX, a_rdx),
                           (RegisterX86::RSI, if frame { arg("rsi", 0) } else { pool_va }),
                           (RegisterX86::RDI, if frame { arg("rdi", 0) } else { pool_va }),
                           (RegisterX86::RBP, if dll_mode { 0x72000000u64 } else if frame { 0x7ffe0000u64 } else { key }),
                           (RegisterX86::R8, if frame { arg("r8", 0) } else { a_r8 }),
                           (RegisterX86::R9, if frame { arg("r9", 0) } else { pool_va }),
                           (RegisterX86::R10, pool_va),
                           (RegisterX86::R11, key), (RegisterX86::RSP, 0x7ffe0000),
                           (RegisterX86::R12, if dll_mode { 0x72000000u64 } else { 0 }),
                           (RegisterX86::R13, if dll_mode { 0x72000000u64 } else { 0 }),
                           (RegisterX86::RIP, site), (RegisterX86::EFLAGS, eflags)] {
                emu.reg_write(r, v).unwrap();
            }
            // IN trap -> canned value (env IN_RET, default 0). Variants route VM to other functions.
            let in_ret: u32 = std::env::var("IN_RET").map(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).unwrap_or(0)).unwrap_or(0);
            let _in_hook = emu.add_insn_in_hook(move |_emu, _port, _size| in_ret).unwrap();
            // Log unmapped accesses with faulting RIP.
            // RVA fixup is PE/VMP-only: on ELF (zero-filled BSS, libc-style
            // tables) it hijacks execution into zero pages. PE-gated.
            let rvafix_on = bin.fmt() == vmp_devirt::pe_loader::BinFmt::Pe;
            // Special: GetProcAddress slot points at 0xDEAD0000 -> log (module,name), emulate ret.
            let _mem_hook = emu.add_mem_hook(unicorn_engine::unicorn_const::HookType::MEM_UNMAPPED, 0, 0xffffffffffffffff, move |emu, _mtype, addr, _size, _val| {
                // RVA fixup: small absolute targets are unrebased RVAs (custom tables).
                // Redirect only if bytes decode sanely (valid, no privileged/data soup).
                if rvafix_on && addr < 0x1000000 {
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
                            eprintln!("    RVAFIX {:#x} -> {:#x}", addr, cand);
                            let _ = emu.reg_write(RegisterX86::RIP, cand);
                            return true;
                        }
                    }
                }
                if addr == 0xDEAD0000 {
                    let hmod: u64 = emu.reg_read(RegisterX86::RCX).unwrap_or(0);
                    let nm: u64 = emu.reg_read(RegisterX86::RDX).unwrap_or(0);
                    let rsp: u64 = emu.reg_read(RegisterX86::RSP).unwrap_or(0);
                    let mut nb = [0u8; 64];
                    let name = if nm < 0x10000 { format!("#{}", nm) } else {
                        emu.mem_read(nm, &mut nb).map(|_| {
                            let l = nb.iter().position(|b| *b == 0).unwrap_or(64);
                            String::from_utf8_lossy(&nb[..l]).into_owned()
                        }).unwrap_or("?".into())
                    };
                    let mut rb = [0u8; 8];
                    let ret = emu.mem_read(rsp, &mut rb).map(|_| u64::from_le_bytes(rb)).unwrap_or(0);
                    eprintln!("    GPA hmod={:#x} name={} ret={:#x}", hmod, name, ret);
                    let _ = emu.reg_write(RegisterX86::RSP, rsp + 8);
                    let _ = emu.reg_write(RegisterX86::RIP, ret);
                    let _ = emu.reg_write(RegisterX86::RAX, 0);
                    return true;
                }
                eprintln!("    MEMFAULT addr={:#x}", addr);
                false
            }).unwrap();
            let hits = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let h = hits.clone();
            let memlog = std::env::var("MEMLOG").is_ok();
            let mlog = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let ml = mlog.clone();
            let h2 = hits.clone();
            if memlog {
                // Log (rip, rw, addr, size, val) for accesses between 1st and 40th fetch hit.
                let _rw = emu.add_mem_hook(unicorn_engine::unicorn_const::HookType::MEM_READ | unicorn_engine::unicorn_const::HookType::MEM_WRITE, 0, 0xffffffffffffffff, move |emu, mtype, addr, size, _val| {
                    let n = h2.lock().unwrap().len();
                    if n >= 1 {
                        let rip: u64 = emu.reg_read(RegisterX86::RIP).unwrap_or(0);
                        let w = format!("{:?}", mtype).contains("WRITE");
                        let mut bb = [0u8; 16];
                        let val: u64 = if w { _val as u64 } else {
                            let s = size.min(8);
                            emu.mem_read(addr, &mut bb[..s]).map(|_| u64::from_le_bytes(bb[..8].try_into().unwrap())).unwrap_or(0xdead)
                        };
                        ml.lock().unwrap().push((rip, w, addr, size, val));
                    }
                    true
                }).unwrap();
            }
            let trace = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let t = trace.clone();
            let mut count = 0u64;
            let dump_trace = std::env::var("TRACE_DUMP").is_ok();
            let full = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let f = full.clone();
            let mut staged_dumped = false;
            let bound: u64 = std::env::var("BOUND").map(|v| v.parse().unwrap_or(3000000)).unwrap_or(if entry_mode { 3000000 } else { 500 });
            let w = watches.clone();
            let sm = sitemap.clone();
            // Full-range hook: image + heap/stubs (VM stages code in heap).
            // ELF PLT semantic stubs (PLT_STUBS=1): libc calls through the
            // PLT (memcpy/memset/memmove for VM table init) would otherwise
            // "return" via the zero-page ret stub without doing anything.
            // Emulate semantics host-side, then skip past the call.
            let plt = plt_stubs.clone();
            let hook_all = emu.add_code_hook(1, 0, move |emu, addr, _size| {
                if let Some(name) = plt.get(&addr) {
                    let g = |r: RegisterX86| -> u64 { emu.reg_read(r).unwrap_or(0) };
                    let (dst, src, len) = (g(RegisterX86::RDI), g(RegisterX86::RSI), g(RegisterX86::RDX));
                    let rsp: u64 = g(RegisterX86::RSP);
                    let mut rb = [0u8; 8];
                    let ret = emu.mem_read(rsp, &mut rb).map(|_| u64::from_le_bytes(rb)).unwrap_or(0);
                    let ok = (len as usize) < 0x1000000 && match name.as_str() {
                        "memcpy" | "memmove" => {
                            let mut b = vec![0u8; len as usize];
                            emu.mem_read(src, &mut b).is_ok() && emu.mem_write(dst, &b).is_ok()
                        }
                        "memset" => {
                            let b = vec![(src & 0xFF) as u8; len as usize];
                            emu.mem_write(dst, &b).is_ok()
                        }
                        _ => false,
                    };
                    if ok {
                        let _ = emu.reg_write(RegisterX86::RAX, dst);
                        let _ = emu.reg_write(RegisterX86::RSP, rsp + 8);
                        let _ = emu.reg_write(RegisterX86::RIP, ret);
                    }
                    return;
                }
                // NOTE: single count per traced insn (was double-counted
                // with the increment below; bounds/steps were 2x real).
                // Slide fast-forward: zero padding executes as `add [rax],al` slides.
                // Skip exactly: iters=len/2, cell+=iters*al, flags from last add.
                if entry_mode && (0x300000u64..0x900000u64).contains(&addr) {
                    let mut probe = [0u8; 16];
                    if emu.mem_read(addr, &mut probe).is_ok() && probe.iter().all(|b| *b == 0) {
                        // Scan slide end (chunked, cap 8MB).
                        let mut end = addr;
                        let mut chunk = [0u8; 0x10000];
                        'scan: for off in (0..0x800000u64).step_by(0x10000) {
                            let base = addr + off;
                            if emu.mem_read(base, &mut chunk).is_err() { end = base; break 'scan; }
                            if let Some(i) = chunk.iter().position(|b| *b != 0) { end = base + i as u64; break 'scan; }
                            end = base + 0x10000;
                        }
                        if end > addr + 1 {
                            let iters = (end - addr) / 2;
                            let rax: u64 = emu.reg_read(RegisterX86::RAX).unwrap_or(0);
                            let al = rax & 0xFF;
                            let mut cb = [0u8; 1];
                            let cell0 = emu.mem_read(rax, &mut cb).map(|_| cb[0] as u64).unwrap_or(0);
                            let last_a = (cell0 + (iters - 1) * al) & 0xFF;
                            let res = (last_a + al) & 0xFF;
                            // x86 8-bit add flags for last_a + al = res.
                            let cf = (last_a + al) > 0xFF;
                            let zf = res == 0;
                            let sf = res & 0x80 != 0;
                            let of = ((!(last_a ^ al)) & (last_a ^ res) & 0x80) != 0;
                            let af = ((last_a ^ al ^ res) & 0x10) != 0;
                            let pf = (res.count_ones() % 2) == 0;
                            let flags: u64 = 0x202 | ((cf as u64)) | ((pf as u64) << 2) | ((af as u64) << 4)
                                | ((zf as u64) << 6) | ((sf as u64) << 7) | ((of as u64) << 11);
                            let _ = emu.reg_write(RegisterX86::EFLAGS, flags);
                            let _ = emu.mem_write(rax, &[((cell0 + iters * al) & 0xFF) as u8]);
                            let _ = emu.reg_write(RegisterX86::RIP, end);
                            eprintln!("  SLIDESKIP {:#x}->{:#x} iters={} cell {:#x}->{:#x}", addr, end, iters, cell0, (cell0 + iters * al) & 0xFF);
                            return;
                        }
                    }
                }
                count += 1;
                { let mut t = t.lock().unwrap(); t.push(addr); if t.len() > 200 { let l = t.len(); t.drain(..l-200); } }
                if dump_trace { f.lock().unwrap().push(addr); }
                // Mid-run snapshot: first time execution leaves the staged sweep area.
                if dump_trace && !staged_dumped && addr >= 0x900000 && count > 100000 {
                    staged_dumped = true;
                    let dir = std::env::var("DATA_DIR").unwrap_or_else(|_| "./data".to_string());
                    for (va, sz, tag) in [(0x300000u64, 0x600000usize, "staged_mid"), (0x71000000u64, 0x100000usize, "heap_mid")] {
                        let mut mb = vec![0u8; sz];
                        if emu.mem_read(va, &mut mb).is_ok() {
                            let nz = mb.iter().filter(|b| **b != 0).count();
                            let _ = std::fs::write(format!("{}/open_mem_{}.bin", dir, tag), &mb);
                            eprintln!("  MID wrote open_mem_{}.bin ({} nonzero)", tag, nz);
                        }
                    }
                }
                if w.contains(&addr) {
                    let g = |r: RegisterX86| -> u64 { emu.reg_read(r).unwrap_or(0xdead) };
                    let g = |r: RegisterX86| -> u64 { emu.reg_read(r).unwrap_or(0xdead) };
                    let rax: u64 = g(RegisterX86::RAX);
                    let rsi: u64 = g(RegisterX86::RSI);
                    let rdx: u64 = g(RegisterX86::RDX);
                    let rbx: u64 = g(RegisterX86::RBX);
                    let rbp: u64 = g(RegisterX86::RBP);
                    let r10: u64 = g(RegisterX86::R10);
                    let rcx: u64 = g(RegisterX86::RCX);
                    let rdi: u64 = g(RegisterX86::RDI);
                    let r8: u64 = g(RegisterX86::R8);
                    let r9: u64 = g(RegisterX86::R9);
                    let r11: u64 = g(RegisterX86::R11);
                    let r12: u64 = g(RegisterX86::R12);
                    let r13: u64 = g(RegisterX86::R13);
                    let r14: u64 = g(RegisterX86::R14);
                    let r15: u64 = g(RegisterX86::R15);
                    let rsp: u64 = g(RegisterX86::RSP);
                    let mut b = [0u8; 1];
                    let raw = emu.mem_read(rax, &mut b).map(|_| b[0]);
                    // Per-site base reg + raw at base (key resolved by sweep later).
                    let (base_s, base_raw) = match sm.get(&addr) {
                        Some((bn, xr, _dst)) => {
                            let bv: u64 = g(*xr);
                            let mut bb = [0u8; 1];
                            let br = emu.mem_read(bv, &mut bb).ok().map(|_| bb[0]);
                            (format!("{:?}", bn), br)
                        }
                        None => ("?".to_string(), None),
                    };
                    // Live code bytes at hit time (defeats re-encrypting SMC).
                    let mut cb = [0u8; 256];
                    let code_hex = emu.mem_read(addr, &mut cb).ok()
                        .map(|_| cb.iter().map(|x| format!("{:02x}", x)).collect::<String>())
                        .unwrap_or_default();
                    h.lock().unwrap().push((addr, rax, rsi, rdx, rbx, rbp, r10, raw, rcx, rdi, r8, r9, r11, base_raw, code_hex));
                    eprintln!("  WATCH {:#x} base={} braw={:?} rax={:#x} rcx={:#x} rdx={:#x} rbx={:#x} rsp={:#x} rbp={:#x} rsi={:#x} rdi={:#x} r8={:#x} r9={:#x} r10={:#x} r11={:#x} r12={:#x} r13={:#x} r14={:#x} r15={:#x}", addr, base_s, base_raw.map(|x| format!("{:#x}", x)), rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15);
                    if h.lock().unwrap().len() >= std::env::var("HITS").map(|v| v.parse().unwrap_or(1000)).unwrap_or(1000) { emu.emu_stop().ok(); }
                }
                if count > bound { emu.emu_stop().ok(); }
            }).unwrap();
            let res = emu.emu_start(site, base + 0x900000, 0, (bound + 100) as usize);
            emu.remove_hook(hook_all).unwrap();
            if memlog {
                let ml = mlog.lock().unwrap();
                let mut buf = Vec::with_capacity(ml.len() * 33);
                for (rip, w, addr, size, val) in ml.iter() {
                    buf.extend_from_slice(&rip.to_le_bytes());
                    buf.push(if *w { 1 } else { 0 });
                    buf.extend_from_slice(&addr.to_le_bytes());
                    buf.extend_from_slice(&(*size as u64).to_le_bytes());
                    buf.extend_from_slice(&val.to_le_bytes());
                }
                let dir = std::env::var("DATA_DIR").unwrap_or_else(|_| "./data".to_string());
                let _ = std::fs::write(format!("{}/open_memlog.bin", dir), &buf);
                eprintln!("  wrote {} mem accesses", ml.len());
            }
            if dump_trace {
                let full = full.lock().unwrap();
                let mut buf = Vec::with_capacity(full.len() * 8);
                for a in full.iter() { buf.extend_from_slice(&a.to_le_bytes()); }
                let dir = std::env::var("DATA_DIR").unwrap_or_else(|_| "./data".to_string());
                std::fs::create_dir_all(&dir).ok();
                let _ = std::fs::write(format!("{}/open_trace.bin", dir), &buf);
                eprintln!("  wrote {} trace addrs", full.len());
                // Section-base manifest (snapshots below keyed by section name).
                {
                    let mut m = String::from("{\n");
                    for (va, _off, _rawsz, _vsize, n) in &vmp_sections {
                        m.push_str(&format!("  \"{}\": \"{:#x}\",\n", n.trim_start_matches('.'), va));
                    }
                    m.push_str("  \"staged\": \"0x300000\",\n  \"heap\": \"0x71000000\"\n}\n");
                    let _ = std::fs::write(format!("{}/open_bases.json", dir), &m);
                }
                // Unpacked memory snapshot: sections as emulated (post-unpack bytes).
                for (va, _off, _rawsz, vsize, n) in &vmp_sections {
                    let sz = (*vsize).min(0x4000000);
                    let mut mb = vec![0u8; sz];
                    if emu.mem_read(*va, &mut mb).is_ok() {
                        let fname = format!("{}/open_mem_{}.bin", dir, n.trim_start_matches('.'));
                        let _ = std::fs::write(&fname, &mb);
                        eprintln!("  wrote {} ({} bytes @ {:#x})", fname, sz, va);
                    }
                }
                // Staged-code scratch (VM copies handlers to 0x300000+).
                for (va, sz, tag) in [(0x300000u64, 0x600000usize, "staged"), (0x71000000u64, 0x100000usize, "heap")] {
                    let mut mb = vec![0u8; sz];
                    if emu.mem_read(va, &mut mb).is_ok() {
                        let nz = mb.iter().filter(|b| **b != 0).count();
                        let fname = format!("{}/open_mem_{}.bin", dir, tag);
                        let _ = std::fs::write(&fname, &mb);
                        eprintln!("  wrote {} ({} bytes, {} nonzero @ {:#x})", fname, sz, nz, va);
                    }
                }
            }
            let hits = hits.lock().unwrap();
            let trace = trace.lock().unwrap();
            println!("site {:#x} eflags {:#x} key {:#x}: res={:?} watch_hits={}", site, eflags, key, res, hits.len());
            let end_rip: u64 = emu.reg_read(RegisterX86::RIP).unwrap_or(0);
            let uniq: std::collections::BTreeSet<u64> = trace.iter().cloned().collect();
            println!("  end_rip={:#x} last200uniq={} tail: {}", end_rip, uniq.len(), trace.iter().rev().take(12).rev().map(|a| format!("{:#x}", a)).collect::<Vec<_>>().join(" "));
            for (a, rax, rsi, rdx, rbx, rbp, r10, raw, _rcx, _rdi, _r8, _r9, _r11, _braw, _code) in hits.iter().take(45) {
                println!("  hit {:#x} rax={:#x} rsi={:#x} rdx={:#x} rbx={:#x} rbp={:#x} r10={:#x} raw={:?}", a, rax, rsi, rdx, rbx, rbp, r10, raw.map(|b| format!("{:#x}", b)));
            }
            // Persist stream for stage-2 decoder (canonical RE data path).
            if entry_mode && !hits.is_empty() {
                let dir = std::env::var("DATA_DIR").unwrap_or_else(|_| "./data".to_string());
                std::fs::create_dir_all(&dir).ok();
                let mut f = String::from("[\n");
                for (i, (a, rax, rsi, rdx, rbx, rbp, r10, raw, rcx, rdi, r8, r9, r11, braw, code)) in hits.iter().enumerate() {
                    f.push_str(&format!("  {{\"n\":{},\"site\":\"{:#x}\",\"rax\":{},\"rsi\":{},\"rdx\":{},\"rbx\":{},\"rbp\":{},\"r10\":{},\"rcx\":{},\"rdi\":{},\"r8\":{},\"r9\":{},\"r11\":{},\"raw\":{},\"braw\":{},\"code\":\"{}\"}}",
                        i, a, rax, rsi, rdx, rbx, rbp, r10, rcx, rdi, r8, r9, r11, raw.map(|b| b.to_string()).unwrap_or("null".into()), braw.map(|b| b.to_string()).unwrap_or("null".into()), code));
                    if i + 1 < hits.len() { f.push(','); }
                    f.push('\n');
                }
                f.push_str("]\n");
                let _ = std::fs::write(format!("{}/open_hits.json", dir), &f);
                eprintln!("  wrote {} hits", hits.len());
            }
            }
        }
    }
    Ok(())
}
