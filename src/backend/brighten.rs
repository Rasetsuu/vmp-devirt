//! Saturn-subset brightening: constant-pool folding + RSP-concretized
//! stack-slot recovery over Remill-lifted LLVM IR text.
//!
//! Saturn (deobfuscation via LLVM, 2019) brightens lifted code in two
//! moves we port here in per-BB, trace-assisted form:
//! 1. **constantPool**: loads from constant data ranges (Saturn stresses
//!    RW sections too, not just .rdata) become integer constants, so
//!    downstream `opt` folds the obfuscation that fed on them.
//! 2. **stack concretization**: with a concrete RSP (from a trace visit),
//!    RSP-derived addresses resolve to stack slots; reads with known
//!    contents fold, the rest inventory as `(offset, width, op)`.
//! Saturn's full loop (CFG-shell inline, global→alloca promotion until
//! fixpoint) needs a whole-function shell our per-BB pipeline has not
//! got yet — queued; this module is the applicable subset, and it is
//! measured (folds + slots per file).
//!
//! Inputs are deliberately file-shaped (no binaries in repo): IR text,
//! concrete regs as JSON, pool ranges as JSON, image bytes + base.
//! Unit tests use inline IR strings only.

use std::collections::HashMap;

/// GPR index (State GEP `i32 6, i32 N`) to canonical reg name.
/// Harvested from lifted names (`%RSI = getelementptr ... i32 6, i32 9`).
fn idx_reg(n: u64) -> Option<&'static str> {
    match n {
        1 => Some("rax"),
        3 => Some("rbx"),
        5 => Some("rcx"),
        7 => Some("rdx"),
        9 => Some("rsi"),
        11 => Some("rdi"),
        13 => Some("rsp"),
        15 => Some("rbp"),
        17 => Some("r8"),
        19 => Some("r9"),
        21 => Some("r10"),
        23 => Some("r11"),
        25 => Some("r12"),
        27 => Some("r13"),
        29 => Some("r14"),
        31 => Some("r15"),
        33 => Some("rip"),
        _ => None,
    }
}

/// One recovered stack slot: RSP-relative offset, access width, read/write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackSlot {
    pub offset: i64,
    pub width: u8,
    pub is_write: bool,
}

/// Brightening outcome: rewritten IR, fold count, slot inventory.
#[derive(Debug, Default)]
pub struct BrightenOut {
    pub ir: String,
    pub folds: usize,
    pub slots: Vec<StackSlot>,
}

/// Parse `i64` SSA constant operand: `i64 123` / `i64 noundef -5`.
fn parse_i64_operand(s: &str) -> Option<u64> {
    let s = s.trim();
    let s = s.strip_prefix("i64")?.trim();
    let s = s.strip_prefix("noundef").map(str::trim).unwrap_or(s);
    s.split([',', ' ', ')']).next()?.trim().parse::<i64>().ok().map(|v| v as u64)
}

/// Intrinsic width from `@__remill_read_memory_N` / write name.
fn mem_width(line: &str) -> Option<u8> {
    let p = line.find("__remill_")?;
    let tail = &line[p..];
    let n: String = tail.chars().skip_while(|c| !c.is_ascii_digit()).take_while(|c| c.is_ascii_digit()).collect();
    match n.as_str() {
        "8" => Some(1),
        "16" => Some(2),
        "32" => Some(4),
        "64" => Some(8),
        _ => None,
    }
}

fn llvm_int_ty(width: u8) -> &'static str {
    match width {
        1 => "i8",
        2 => "i16",
        4 => "i32",
        _ => "i64",
    }
}

/// Read little-endian integer of `width` bytes from image at `addr`.
fn image_read(image: &[u8], img_base: u64, addr: u64, width: u8) -> Option<u64> {
    let off = addr.checked_sub(img_base)? as usize;
    let b = image.get(off..off + width as usize)?;
    let mut v = 0u64;
    for (i, by) in b.iter().enumerate() {
        v |= (*by as u64) << (8 * i);
    }
    Some(v)
}

/// Brighten Remill IR text.
///
/// `regs`: concrete register values (lowercase names) from a trace visit.
/// `pools`: `(start, len)` constant ranges (all readable sections, RW incl).
/// `image`/`img_base`: backing bytes for pool reads.
/// `stack_window`: bytes below RSP counted as stack (default 1MB).
pub fn brighten(
    ir: &str,
    regs: &HashMap<String, u64>,
    pools: &[(u64, u64)],
    image: &[u8],
    img_base: u64,
    stack_window: u64,
) -> BrightenOut {
    // Pass 1: State-GEP names -> regs; loads of those -> concrete values.
    let mut gep_reg: HashMap<String, String> = HashMap::new();
    for line in ir.lines() {
        let t = line.trim();
        if !(t.starts_with('%') && t.contains("getelementptr") && t.contains("%struct.State, ptr %state")) {
            continue;
        }
        let name_end = t.find(' ').unwrap_or(t.len());
        let name = t[1..name_end].trim_end_matches('=').trim().to_string();
        // GPR slot = index right after `i32 6,` (trailing indices address bytes/fields)
        if let Some(n) = t.find("i32 6, i32 ").and_then(|p| {
            t[p + "i32 6, i32 ".len()..].split([',', ' ', ')']).next()?.parse::<u64>().ok()
        }) {
            if let Some(r) = idx_reg(n) {
                gep_reg.insert(name, r.to_string());
            }
        }
    }
    // SSA value map: %name -> concrete u64. Seed from reg loads + const defs.
    let mut vals: HashMap<String, u64> = HashMap::new();
    // Symbolic companion: %name -> (base reg, offset) for RSP-relative
    // chains. Needs no concrete RSP: `load RSP; sub 8` IS slot -8 by
    // construction. Concrete window check stays for absolute addrs.
    let mut syms: HashMap<String, (String, i64)> = HashMap::new();
    // fixed-point over simple ALU (text order needs repeats for fwd refs)
    for _ in 0..8 {
        let mut grew = false;
        for line in ir.lines() {
            let t = line.trim();
            if !t.starts_with('%') || !t.contains('=') {
                continue;
            }
            let eq = t.find('=').unwrap();
            let dst = t[1..eq].trim().to_string();
            if vals.contains_key(&dst) {
                continue;
            }
            let rhs = t[eq + 1..].trim();
            // load of a State-reg GEP
            if rhs.starts_with("load i64, ptr %") {
                let src = rhs["load i64, ptr %".len()..].split([',', ' ', ')']).next().unwrap_or("").to_string();
                if let Some(r) = gep_reg.get(&src) {
                    if let Some(v) = regs.get(r) {
                        vals.insert(dst.clone(), *v);
                        grew = true;
                    }
                    // symbolic even without concrete regs
                    if syms.insert(dst.clone(), (r.clone(), 0)).is_none() {
                        grew = true;
                    }
                }
                continue;
            }
            // pure constant def: `i64 123` style appears via `add i64 0, C`? handle add/sub of knowns
            let parts: Vec<&str> = rhs.split_whitespace().collect();
            if parts.len() >= 4 && (parts[0] == "add" || parts[0] == "sub" || parts[0] == "xor" || parts[0] == "and" || parts[0] == "or")
                && (parts[1] == "i64" || parts[1] == "noundef" || parts[2] == "i64")
            {
                // operands: last two comma-separated tokens, each %ssa or constant
                let ops: Vec<&str> = rhs.split(',').collect();
                if ops.len() >= 2 {
                    // resolve one operand text -> (sym-part, const-part), owned
                    let resolve = |s: &str,
                                   syms: &HashMap<String, (String, i64)>,
                                   vals: &HashMap<String, u64>|
                     -> Option<(Option<(String, i64)>, Option<i64>)> {
                        let w = s.split_whitespace().last()?.trim().trim_start_matches("noundef ").trim();
                        let w = w.strip_prefix("i64 noundef").or_else(|| w.strip_prefix("i64")).unwrap_or(w).trim();
                        if let Some(ssa) = w.strip_prefix('%') {
                            let key = ssa.split([',', ')']).next().unwrap_or("");
                            Some((syms.get(key).cloned(), vals.get(key).copied().map(|v| v as i64)))
                        } else {
                            Some((None, w.split([',', ')']).next()?.parse::<i64>().ok()))
                        }
                    };
                    let val_of = |s: &str| -> Option<u64> {
                        // operand token = last whitespace word (`add i64 %v0` -> `%v0`)
                        let w = s.split_whitespace().last()?.trim().trim_start_matches("noundef ").trim();
                        let w = w.strip_prefix("i64 noundef").or_else(|| w.strip_prefix("i64")).unwrap_or(w).trim();
                        if let Some(ssa) = w.strip_prefix('%') {
                            vals.get(ssa).copied()
                        } else {
                            w.split([',', ')']).next()?.parse::<i64>().ok().map(|v| v as u64)
                        }
                    };
                    if let (Some(a), Some(b)) = (val_of(ops[ops.len() - 2]), val_of(ops[ops.len() - 1])) {
                        let r = match parts[0] {
                            "add" => a.wrapping_add(b),
                            "sub" => a.wrapping_sub(b),
                            "xor" => a ^ b,
                            "and" => a & b,
                            _ => a | b,
                        };
                        vals.insert(dst.clone(), r);
                        grew = true;
                    }
                    // symbolic add/sub over (base,off): one side symbolic, other const
                    if parts[0] == "add" || parts[0] == "sub" {
                        let ra = resolve(ops[ops.len() - 2], &syms, &vals);
                        let rb = resolve(ops[ops.len() - 1], &syms, &vals);
                        if let (Some(a), Some(b)) = (ra, rb) {
                            // a/b = (sym-part, const-part); const-part valid only if no sym-part
                            let kc = |p: &(Option<(String, i64)>, Option<i64>)| -> Option<i64> {
                                if p.0.is_none() { p.1 } else { None }
                            };
                            match (&a.0, kc(&a), &b.0, kc(&b)) {
                                (Some((rg, o)), _, None, Some(k)) if parts[0] == "add" => {
                                    if syms.insert(dst.clone(), (rg.clone(), o.wrapping_add(k))).is_none() { grew = true; }
                                }
                                (Some((rg, o)), _, None, Some(k)) => {
                                    if syms.insert(dst.clone(), (rg.clone(), o.wrapping_sub(k))).is_none() { grew = true; }
                                }
                                (None, Some(k), Some((rg, o)), _) if parts[0] == "add" => {
                                    if syms.insert(dst.clone(), (rg.clone(), o.wrapping_add(k))).is_none() { grew = true; }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
        if !grew {
            break;
        }
    }
    let in_pool = |a: u64| pools.iter().any(|(s, l)| a >= *s && a < s + l);
    let rsp = regs.get("rsp").copied().unwrap_or(0);
    let window = if stack_window == 0 { 1 << 20 } else { stack_window };
    let is_stack = |a: u64| rsp != 0 && a <= rsp && rsp - a < window;

    // Pass 2: rewrite + inventory.
    let mut out_lines: Vec<String> = Vec::new();
    let mut folds = 0usize;
    let mut slots: Vec<StackSlot> = Vec::new();
    for line in ir.lines() {
        let t = line.trim();
        let is_mem = t.contains("@__remill_read_memory_") || t.contains("@__remill_write_memory_");
        if !is_mem {
            out_lines.push(line.to_string());
            continue;
        }
        let is_write = t.contains("write_memory_");
        let width = mem_width(t).unwrap_or(8);
        // address operand: read(mem, addr) -> the i64 operand;
        // write(mem, addr, val) -> the FIRST i64 operand (last is the value)
        let mut i64_ops: Vec<&str> = Vec::new();
        let mut rest = t;
        while let Some((_, s)) = rest.split_once("i64") {
            rest = s;
            i64_ops.push(s);
        }
        let addr_tok = if is_write { i64_ops.first() } else { i64_ops.last() };
        // resolve: concrete SSA -> sym (base+off) -> literal
        enum Addr {
            Abs(u64),
            Sym(String, i64),
        }
        let addr_val: Option<Addr> = addr_tok.and_then(|s| {
            let s = s.trim().trim_start_matches("noundef ").trim();
            if let Some(ssa) = s.strip_prefix('%') {
                let key = ssa.split([',', ' ', ')']).next().unwrap_or("");
                if let Some(v) = vals.get(key) {
                    Some(Addr::Abs(*v))
                } else if let Some((b, o)) = syms.get(key) {
                    // concretize against known base reg when possible
                    match regs.get(b.as_str()) {
                        Some(rv) => Some(Addr::Abs(rv.wrapping_add(*o as u64))),
                        None => Some(Addr::Sym(b.clone(), *o)),
                    }
                } else {
                    None
                }
            } else {
                s.split([',', ' ', ')']).next()?.parse::<i64>().ok().map(|v| Addr::Abs(v as u64))
            }
        });
        // symbolic RSP-relative: slot by construction, no RSP value needed.
        // Bounded by window: RSP + huge offset is a dynamic index
        // (VM-context addressing), not a frame slot.
        if let Some(Addr::Sym(b, o)) = &addr_val {
            if b == "rsp" {
                if o.unsigned_abs() < window {
                    slots.push(StackSlot { offset: *o, width, is_write });
                }
                out_lines.push(line.to_string());
                continue;
            }
        }
        let addr = match addr_val {
            Some(Addr::Abs(a)) => a,
            _ => {
                out_lines.push(line.to_string());
                continue;
            }
        };
        if is_stack(addr) {
            slots.push(StackSlot { offset: addr.wrapping_sub(rsp) as i64, width, is_write });
        }
        if !is_write && in_pool(addr) {
            if let Some(v) = image_read(image, img_base, addr, width) {
                // fold: `%r = call ...` -> `%r = add iN 0, C`
                if let Some(eq) = line.find('=') {
                    let dst = line[..eq].trim();
                    folds += 1;
                    out_lines.push(format!("{} = add {} 0, {}", dst, llvm_int_ty(width), v));
                    continue;
                }
            }
        }
        out_lines.push(line.to_string());
    }
    slots.sort_by_key(|s| (s.offset, s.width, s.is_write));
    slots.dedup();
    BrightenOut { ir: out_lines.join("\n"), folds, slots }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn regs(pairs: &[(&str, u64)]) -> HashMap<String, u64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    const TINY: &str = r#"
define ptr @sub_1(ptr noalias %state, i64 %program_counter, ptr noalias %memory) {
  %RSI = getelementptr inbounds %struct.State, ptr %state, i32 0, i32 0, i32 6, i32 9, i32 0, i32 0
  %RSPb = getelementptr inbounds %struct.State, ptr %state, i32 0, i32 0, i32 6, i32 13, i32 0, i32 0
  %v0 = load i64, ptr %RSI, align 8
  %sp = load i64, ptr %RSPb, align 8
  %a1 = add i64 %v0, 16
  %c = call noundef zeroext i8 @__remill_read_memory_8(ptr noundef %memory, i64 noundef %a1) #3
  %s = sub i64 %sp, 8
  %w = call noundef ptr @__remill_write_memory_64(ptr noundef %memory, i64 noundef %s, i64 noundef %v0) #4
  %t = add i64 %c, %c
  ret ptr %memory
}"#;

    #[test]
    fn pool_fold_and_stack_slot() {
        // RSI=0x140000000, pool covers image; read at RSI+16 folds to image bytes.
        let r = regs(&[("rsi", 0x1400_00000), ("rsp", 0x7ffe_0000)]);
        let mut image = vec![0u8; 0x100];
        image[0x10] = 0x42;
        let pools = [(0x1400_00000u64, 0x1000u64)];
        let o = brighten(TINY, &r, &pools, &image, 0x1400_00000, 0);
        assert_eq!(o.folds, 1, "pool read should fold");
        assert!(o.ir.contains("= add i8 0, 66"), "folded const in IR:\n{}", o.ir);
        assert!(!o.ir.contains("__remill_read_memory_8"), "call gone");
        // write to RSP-8 inventories as slot offset -8 width 8
        assert!(o.slots.contains(&StackSlot { offset: -8, width: 8, is_write: true }),
            "slots={:?}", o.slots);
    }

    #[test]
    fn symbolic_slot_without_rsp() {
        // no regs at all: RSP-relative write still inventories via symbolics
        let o = brighten(TINY, &regs(&[]), &[], &[], 0x1400_00000, 0);
        assert!(o.slots.contains(&StackSlot { offset: -8, width: 8, is_write: true }),
            "slots={:?}", o.slots);
    }

    #[test]
    fn no_regs_no_crash() {
        let o = brighten(TINY, &regs(&[]), &[], &[], 0, 0);
        assert_eq!(o.folds, 0);
        assert!(o.ir.contains("__remill_read_memory_8"));
    }

    #[test]
    fn addr_outside_pool_kept() {
        let r = regs(&[("rsi", 0x1400_00000), ("rsp", 0x7ffe_0000)]);
        let o = brighten(TINY, &r, &[], &[0u8; 0x100], 0x1400_00000, 0);
        assert_eq!(o.folds, 0, "no pools -> no folds");
        assert!(o.slots.contains(&StackSlot { offset: -8, width: 8, is_write: true }));
    }
}
