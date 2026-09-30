//! Execution snapshot: instrumented Unicorn run producing a rich trace.
//!
//! Caller configures: start address, register init, I/O trap values,
//! import stubs (slot VA -> action), watch addresses, step bound,
//! memory-access logging window. No binary-specific defaults.

use anyhow::Result;
use std::collections::{BTreeSet, HashMap};
use unicorn_engine::{Unicorn, unicorn_const::{Arch, Mode, Prot}};
use unicorn_engine_sys::RegisterX86;

/// One watch hit with full register file + fetched byte (if readable).
#[derive(Debug, Clone, Default)]
pub struct RegHit {
    pub site_va: u64,
    pub regs: HashMap<String, u64>,
    pub raw: Option<u8>,
}

/// Rich execution trace.
#[derive(Debug, Clone, Default)]
pub struct Trace {
    pub addrs: Vec<u64>,
    pub hits: Vec<RegHit>,
    pub end_rip: u64,
    pub steps: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StubAction {
    /// Return zero (xor eax,eax; ret).
    Zero,
    /// Return a heap pointer (mov rax,heap; ret).
    Heap,
    /// Trap for GetProcAddress-style logging (handled by harness).
    TrapLog,
    /// Return constant in rax.
    Const(u64),
    /// Write fixed u64 to [rcx], return void (time-style APIs).
    WriteRcX(u64),
}

/// Import stub: IAT slot VA -> action.
#[derive(Debug, Clone)]
pub struct ImportStub {
    pub slot_va: u64,
    pub action: StubAction,
}

#[derive(Debug, Clone, Default)]
pub struct SnapshotConfig {
    pub start_va: u64,
    pub entry_mode: bool,
    pub eflags: u64,
    pub init_regs: HashMap<RegisterX86, u64>,
    pub in_ret: u32,
    pub stubs: Vec<ImportStub>,
    pub watch: BTreeSet<u64>,
    pub bound: u64,
    pub log_mem: bool,
    /// Skip zero-slide delay loops with exact cell+flag reconstruction.
    pub skip_zero_slides: bool,
    /// Slide address range to consider (default: 0x300000..0x900000).
    pub slide_range: Option<(u64, u64)>,
}

pub const REG_NAMES: &[(&str, RegisterX86)] = &[
    ("rax", RegisterX86::RAX), ("rbx", RegisterX86::RBX),
    ("rcx", RegisterX86::RCX), ("rdx", RegisterX86::RDX),
    ("rsi", RegisterX86::RSI), ("rdi", RegisterX86::RDI),
    ("r8", RegisterX86::R8), ("r9", RegisterX86::R9),
    ("r10", RegisterX86::R10), ("r11", RegisterX86::R11),
    ("r12", RegisterX86::R12), ("r13", RegisterX86::R13),
    ("r14", RegisterX86::R14), ("r15", RegisterX86::R15),
    ("rbp", RegisterX86::RBP), ("rsp", RegisterX86::RSP),
];

/// Map image sections (+scratch + zero page) and run. Returns trace.
/// Logs mem accesses when `log_mem` and at least one hit seen.
pub fn capture(
    image: &[(u64, Vec<u8>)],
    cfg: &SnapshotConfig,
) -> Result<(Trace, Vec<(u64, bool, u64, u64, u64)>, Vec<(u64, String, u64)>)> {
    let mut emu = Unicorn::new(Arch::X86, Mode::MODE_64)?;
    for (va, data) in image {
        let mapped = ((data.len() + 0xfff) & !0xfff) as u64;
        let _ = emu.mem_map(*va, mapped.max(0x1000), Prot::ALL);
        let _ = emu.mem_write(*va, data);
    }
    for b in (0x100000u64..0x80000000u64).step_by(0x100000) {
        let _ = emu.mem_map(b, 0x100000, Prot::ALL);
    }
    let _ = emu.mem_map(0, 0x1000, Prot::ALL);
    let _ = emu.mem_write(0, &[0xC3u8]);
    // Materialize stubs in scratch.
    let mut stub_cur = 0x70000000u64;
    let heap_base = 0x71000000u64;
    let _ = emu.mem_map(heap_base, 0x100000, Prot::ALL);
    let mut trap_addrs: Vec<u64> = Vec::new();
    for stub in &cfg.stubs {
        let bytes: Vec<u8> = match stub.action {
            StubAction::Zero => vec![0x31, 0xC0, 0xC3],
            StubAction::Heap => {
                let mut c = vec![0x48, 0xB8];
                c.extend_from_slice(&heap_base.to_le_bytes());
                c.push(0xC3);
                c
            }
            StubAction::TrapLog => {
                trap_addrs.push(stub.slot_va);
                continue;
            }
            StubAction::Const(v) => {
                let mut c = vec![0x48, 0xB8];
                c.extend_from_slice(&v.to_le_bytes());
                c.push(0xC3);
                c
            }
            StubAction::WriteRcX(v) => {
                // mov qword [rcx], imm32; ret  (v must fit u32)
                let mut c = vec![0x48, 0xC7, 0x01];
                c.extend_from_slice(&(v as u32).to_le_bytes());
                c.push(0xC3);
                c
            }
        };
        let a = stub_cur;
        stub_cur += 32;
        let _ = emu.mem_write(a, &bytes);
        // Patch slot to point at the stub (slots map to *addresses*; the
        // caller pre-resolves slot VAs; we write the stub addr there).
        let _ = emu.mem_write(stub.slot_va, &a.to_le_bytes());
    }
    for (r, v) in &cfg.init_regs {
        emu.reg_write(*r, *v)?;
    }
    emu.reg_write(RegisterX86::RIP, cfg.start_va)?;
    emu.reg_write(RegisterX86::EFLAGS, cfg.eflags)?;
    let in_ret = cfg.in_ret;
    let _ = emu.add_insn_in_hook(move |_emu, _port, _size| in_ret);
    // TrapLog slots: point at unmapped sentinel; the mem hook below logs
    // (module, name) like a GetProcAddress call and emulates return.
    const TRAP_SENTINEL: u64 = 0xDEAD0000;
    for stub in &cfg.stubs {
        if stub.action == StubAction::TrapLog {
            let _ = emu.mem_write(stub.slot_va, &TRAP_SENTINEL.to_le_bytes());
        }
    }
    use unicorn_engine::unicorn_const::HookType;
    let gpa_log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let gl = gpa_log.clone();
    let _ = emu.add_mem_hook(HookType::MEM_UNMAPPED, 0, 0xFFFFFFFFFFFFFFFF, move |emu, _mtype, addr, _size, _val| {
        if addr == TRAP_SENTINEL {
            let hmod: u64 = emu.reg_read(RegisterX86::RCX).unwrap_or(0);
            let nm: u64 = emu.reg_read(RegisterX86::RDX).unwrap_or(0);
            let rsp: u64 = emu.reg_read(RegisterX86::RSP).unwrap_or(0);
            let mut nb = [0u8; 64];
            let name = if nm < 0x10000 {
                format!("#{}", nm)
            } else {
                emu.mem_read(nm, &mut nb).map(|_| {
                    let l = nb.iter().position(|b| *b == 0).unwrap_or(64);
                    String::from_utf8_lossy(&nb[..l]).into_owned()
                }).unwrap_or("?".into())
            };
            let mut rb = [0u8; 8];
            let ret = emu.mem_read(rsp, &mut rb).map(|_| u64::from_le_bytes(rb)).unwrap_or(0);
            gl.lock().unwrap().push((hmod, name, ret));
            let _ = emu.reg_write(RegisterX86::RSP, rsp + 8);
            let _ = emu.reg_write(RegisterX86::RIP, ret);
            let _ = emu.reg_write(RegisterX86::RAX, 0);
            return true;
        }
        false
    });
    let hits = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let h = hits.clone();
    let trace = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let t = trace.clone();
    let w = cfg.watch.clone();
    let bound = cfg.bound;
    let mut count = 0u64;
    let do_skip = cfg.skip_zero_slides;
    let (slide_lo, slide_hi) = cfg.slide_range.unwrap_or((0x300000, 0x900000));
    let hook = emu.add_code_hook(1, 0, move |emu, addr, _size| {
        // NOTE: single count per traced insn (was double-counted with the
        // increment at the hook top; bounds/steps were 2x real).
        // Zero-slide fast-forward: `add [rax],al` over zero padding.
        // Exact: iters=len/2, cell+=iters*al, flags from last add.
        if do_skip && slide_lo <= addr && addr < slide_hi {
            let mut probe = [0u8; 16];
            if emu.mem_read(addr, &mut probe).is_ok() && probe.iter().all(|b| *b == 0) {
                let mut end = addr;
                let mut chunk = [0u8; 0x10000];
                for off in (0..0x800000u64).step_by(0x10000) {
                    let baddr = addr + off;
                    if emu.mem_read(baddr, &mut chunk).is_err() {
                        end = baddr;
                        break;
                    }
                    match chunk.iter().position(|bb| *bb != 0) {
                        Some(i) => { end = baddr + i as u64; break; }
                        None => end = baddr + 0x10000,
                    }
                }
                if end > addr + 1 {
                    let iters = (end - addr) / 2;
                    let rax: u64 = emu.reg_read(RegisterX86::RAX).unwrap_or(0);
                    let al = rax & 0xFF;
                    let mut cb = [0u8; 1];
                    let cell0 = emu.mem_read(rax, &mut cb).map(|_| cb[0] as u64).unwrap_or(0);
                    let last_a = (cell0 + (iters - 1) * al) & 0xFF;
                    let res = (last_a + al) & 0xFF;
                    let cf = (last_a + al) > 0xFF;
                    let zf = res == 0;
                    let sf = res & 0x80 != 0;
                    let of = ((!(last_a ^ al)) & (last_a ^ res) & 0x80) != 0;
                    let af = ((last_a ^ al ^ res) & 0x10) != 0;
                    let pf = (res.count_ones() % 2) == 0;
                    let flags: u64 = 0x202 | (cf as u64) | ((pf as u64) << 2)
                        | ((af as u64) << 4) | ((zf as u64) << 6)
                        | ((sf as u64) << 7) | ((of as u64) << 11);
                    let _ = emu.reg_write(RegisterX86::EFLAGS, flags);
                    let _ = emu.mem_write(rax, &[((cell0 + iters * al) & 0xFF) as u8]);
                    let _ = emu.reg_write(RegisterX86::RIP, end);
                    return;
                }
            }
        }
        count += 1;
        t.lock().unwrap().push(addr);
        if w.contains(&addr) {
            let mut regs = HashMap::new();
            for (n, r) in REG_NAMES {
                regs.insert(n.to_string(), emu.reg_read(*r).unwrap_or(0));
            }
            let rax = regs["rax"];
            let mut b = [0u8; 1];
            let raw = emu.mem_read(rax, &mut b).ok().map(|_| b[0]);
            h.lock().unwrap().push(RegHit { site_va: addr, regs, raw });
            if h.lock().unwrap().len() >= 1000 {
                emu.emu_stop().ok();
            }
        }
        if count > bound {
            emu.emu_stop().ok();
        }
    })?;
    let res = emu.emu_start(cfg.start_va, u64::MAX, 0, (bound + 1000) as usize);
    emu.remove_hook(hook)?;
    let _ = res;
    let hits = hits.lock().unwrap().clone();
    let trace = trace.lock().unwrap().clone();
    let end_rip = emu.reg_read(RegisterX86::RIP).unwrap_or(0);
    let gpa = gpa_log.lock().unwrap().clone();
    let _ = trap_addrs;
    Ok((Trace { addrs: trace, hits, end_rip, steps: count }, Vec::new(), gpa))
}
