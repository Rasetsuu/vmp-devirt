/// Canonical VMP opcode→handler type mapping.
///
/// Generated from VMP 3.5.1 source `intel.h` InitCommands registration order.
/// This is STATIC — identical for all VMP 1.0-3.6.0.
/// Opcode = sequential index in source enum registration order.

use serde::{Serialize, Deserialize};

/// Handler type enum — mirrors VMP source IntelCommandType
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandlerType {
    Nop,
    PushReg, PopReg,
    PushVal, PushWord, PushByte,
    PushMem, PopMem,
    PushSeg, PopSeg,
    PushDbg, PopDbg,
    PushCtrl, PopCtrl,
    Add, Sub, Mul, Imul, Div, Idiv,
    And, Or, Xor, Not, Neg,
    Nor, Nand,
    Shl, Shr,
    Rcl, Rcr,
    Shld, Shrd,
    // FPU (33 arithmetic)
    Fild, Fld, Fadd, Fsub, Fsubr,
    Fstp, Fst, Fist, Fistp,
    Fisub, Fdiv, Fmul, Fcomp,
    Fstcw, Fldcw, Fstsw,
    // FPU misc (23)
    Wait, Fchs, Fsqrt, F2xm1, Fabs,
    Fclex, Fcos, Fdecstp, Fincstp, Finit,
    Fldln2, Fldz, Fld1, Fldpi,
    Fpatan, Fprem, Fprem1, Fptan,
    Frndint, Fsin, Ftst, Fyl2x, Fldlg2,
    Ret, Iret,
    Jmp, Call,
    Rdtsc, Cpuid, Syscall,
    PushEsp, PopEsp,
    Unknown,
}

/// Canonical opcode entry
#[derive(Debug, Clone, Copy)]
pub struct OpcodeEntry {
    /// Opcode byte (0-255)
    pub opcode: u8,
    /// Handler type
    pub handler_type: HandlerType,
    /// Human-readable semantic
    pub semantic: &'static str,
    /// Size of data payload (0 = stack-based)
    pub data_size: u8,
    /// Stack effect (−1 = push, +1 = pop, 0 = stack-neutral)
    pub stack_effect: i8,
    /// Description
    pub description: &'static str,
}

/// Canonical 256-entry opcode map
pub struct CanonicalOpcodeMap;

impl CanonicalOpcodeMap {
    /// Get reference to canonical 256-entry table
    pub fn entries() -> &'static [OpcodeEntry; 256] {
        static MAP: [OpcodeEntry; 256] = generate();
        &MAP
    }

    /// Lookup opcode entry
    pub fn lookup(opcode: u8) -> &'static OpcodeEntry {
        &Self::entries()[opcode as usize]
    }
}

/// Build canonical 256-entry opcode map matching VMP 3.5.1 InitCommands order
const fn generate() -> [OpcodeEntry; 256] {
    // Manual construction to match source enum order
    // build_opcode_map.py: canonical_handlers() order
    let mut m = [OpcodeEntry {
        opcode: 0, handler_type: HandlerType::Unknown,
        semantic: "", data_size: 0, stack_effect: 0, description: "",
    }; 256];
    let mut i = 0;

    // 0: cmNop
    m[i] = entry(i, HandlerType::Nop, "nop", 0, 0, "no operation");
    i += 1;

    // 1-4: cmPushReg (osByte..osDWord)
    m[i] = entry(i, HandlerType::PushReg, "push_reg", 1, -1, "push register (byte)"); i += 1;
    m[i] = entry(i, HandlerType::PushReg, "push_reg", 2, -1, "push register (word)"); i += 1;
    m[i] = entry(i, HandlerType::PushReg, "push_reg", 4, -1, "push register (dword)"); i += 1;

    // 4-7: cmPopReg (osByte..osDWord)
    m[i] = entry(i, HandlerType::PopReg, "pop_reg", 1, 1, "pop register (byte)"); i += 1;
    m[i] = entry(i, HandlerType::PopReg, "pop_reg", 2, 1, "pop register (word)"); i += 1;
    m[i] = entry(i, HandlerType::PopReg, "pop_reg", 4, 1, "pop register (dword)"); i += 1;

    // 7-10: cmPushVal (osByte..osDWord)
    m[i] = entry(i, HandlerType::PushByte, "push_byte", 1, -1, "push byte immediate"); i += 1;
    m[i] = entry(i, HandlerType::PushWord, "push_word", 2, -1, "push word immediate"); i += 1;
    m[i] = entry(i, HandlerType::PushVal, "push_val", 4, -1, "push dword immediate"); i += 1;

    // 10-17: cmPushMem (osByte..osDWord × DS,SS)
    m[i] = entry_push_mem(i, 1); i += 1;
    m[i] = entry_push_mem(i, 2); i += 1;
    m[i] = entry_push_mem(i, 4); i += 1;
    m[i] = entry_push_mem(i, 8); i += 1; // DS extra
    m[i] = entry_push_mem(i, 1); i += 1; // SS
    m[i] = entry_push_mem(i, 2); i += 1;
    m[i] = entry_push_mem(i, 4); i += 1;
    m[i] = entry_push_mem(i, 8); i += 1;

    // 18-25: cmPopMem (osByte..osDWord × DS,SS)
    m[i] = entry_pop_mem(i, 1); i += 1;
    m[i] = entry_pop_mem(i, 2); i += 1;
    m[i] = entry_pop_mem(i, 4); i += 1;
    m[i] = entry_pop_mem(i, 8); i += 1;
    m[i] = entry_pop_mem(i, 1); i += 1;
    m[i] = entry_pop_mem(i, 2); i += 1;
    m[i] = entry_pop_mem(i, 4); i += 1;
    m[i] = entry_pop_mem(i, 8); i += 1;

    // 26-31: cmPushSeg (ES..GS)
    m[i] = entry_seg(i, HandlerType::PushSeg, "push_seg", -1); i += 1;
    m[i] = entry_seg(i, HandlerType::PushSeg, "push_seg", -1); i += 1;
    m[i] = entry_seg(i, HandlerType::PushSeg, "push_seg", -1); i += 1;
    m[i] = entry_seg(i, HandlerType::PushSeg, "push_seg", -1); i += 1;
    m[i] = entry_seg(i, HandlerType::PushSeg, "push_seg", -1); i += 1;
    m[i] = entry_seg(i, HandlerType::PushSeg, "push_seg", -1); i += 1;

    // 32-36: cmPopSeg (ES..GS, excl CS)
    m[i] = entry_seg(i, HandlerType::PopSeg, "pop_seg", 1); i += 1;
    m[i] = entry_seg(i, HandlerType::PopSeg, "pop_seg", 1); i += 1;
    m[i] = entry_seg(i, HandlerType::PopSeg, "pop_seg", 1); i += 1;
    m[i] = entry_seg(i, HandlerType::PopSeg, "pop_seg", 1); i += 1;
    m[i] = entry_seg(i, HandlerType::PopSeg, "pop_seg", 1); i += 1;

    // 37-44: cmPushDbg / cmPopDbg (DR0..DR7)
    m[i] = entry_dbg(i, HandlerType::PushDbg, "push_dbg", -1); i += 1;
    m[i] = entry_dbg(i, HandlerType::PushDbg, "push_dbg", -1); i += 1;
    m[i] = entry_dbg(i, HandlerType::PushDbg, "push_dbg", -1); i += 1;
    m[i] = entry_dbg(i, HandlerType::PushDbg, "push_dbg", -1); i += 1;
    m[i] = entry_dbg(i, HandlerType::PushDbg, "push_dbg", -1); i += 1;
    m[i] = entry_dbg(i, HandlerType::PushDbg, "push_dbg", -1); i += 1;
    m[i] = entry_dbg(i, HandlerType::PushDbg, "push_dbg", -1); i += 1;
    m[i] = entry_dbg(i, HandlerType::PushDbg, "push_dbg", -1); i += 1;

    m[i] = entry_dbg(i, HandlerType::PopDbg, "pop_dbg", 1); i += 1;
    m[i] = entry_dbg(i, HandlerType::PopDbg, "pop_dbg", 1); i += 1;
    m[i] = entry_dbg(i, HandlerType::PopDbg, "pop_dbg", 1); i += 1;
    m[i] = entry_dbg(i, HandlerType::PopDbg, "pop_dbg", 1); i += 1;
    m[i] = entry_dbg(i, HandlerType::PopDbg, "pop_dbg", 1); i += 1;
    m[i] = entry_dbg(i, HandlerType::PopDbg, "pop_dbg", 1); i += 1;
    m[i] = entry_dbg(i, HandlerType::PopDbg, "pop_dbg", 1); i += 1;
    m[i] = entry_dbg(i, HandlerType::PopDbg, "pop_dbg", 1); i += 1;

    // 45-52: cmPushCtrl / cmPopCtrl (CR0..CR7)
    m[i] = entry_ctrl(i, HandlerType::PushCtrl, "push_ctrl", -1); i += 1;
    m[i] = entry_ctrl(i, HandlerType::PushCtrl, "push_ctrl", -1); i += 1;
    m[i] = entry_ctrl(i, HandlerType::PushCtrl, "push_ctrl", -1); i += 1;
    m[i] = entry_ctrl(i, HandlerType::PushCtrl, "push_ctrl", -1); i += 1;
    m[i] = entry_ctrl(i, HandlerType::PushCtrl, "push_ctrl", -1); i += 1;
    m[i] = entry_ctrl(i, HandlerType::PushCtrl, "push_ctrl", -1); i += 1;
    m[i] = entry_ctrl(i, HandlerType::PushCtrl, "push_ctrl", -1); i += 1;
    m[i] = entry_ctrl(i, HandlerType::PushCtrl, "push_ctrl", -1); i += 1;

    m[i] = entry_ctrl(i, HandlerType::PopCtrl, "pop_ctrl", 1); i += 1;
    m[i] = entry_ctrl(i, HandlerType::PopCtrl, "pop_ctrl", 1); i += 1;
    m[i] = entry_ctrl(i, HandlerType::PopCtrl, "pop_ctrl", 1); i += 1;
    m[i] = entry_ctrl(i, HandlerType::PopCtrl, "pop_ctrl", 1); i += 1;
    m[i] = entry_ctrl(i, HandlerType::PopCtrl, "pop_ctrl", 1); i += 1;
    m[i] = entry_ctrl(i, HandlerType::PopCtrl, "pop_ctrl", 1); i += 1;
    m[i] = entry_ctrl(i, HandlerType::PopCtrl, "pop_ctrl", 1); i += 1;
    m[i] = entry_ctrl(i, HandlerType::PopCtrl, "pop_ctrl", 1); i += 1;

    // 53-56: cmPushReg+ESP (osByte..osDWord)
    m[i] = entry(i, HandlerType::PushEsp, "push_esp", 1, -1, "push register ESP (byte)"); i += 1;
    m[i] = entry(i, HandlerType::PushEsp, "push_esp", 2, -1, "push register ESP (word)"); i += 1;
    m[i] = entry(i, HandlerType::PushEsp, "push_esp", 4, -1, "push register ESP (dword)"); i += 1;

    // 57-59: cmPopReg+ESP (osWord..osDWord)
    m[i] = entry(i, HandlerType::PopEsp, "pop_esp", 2, 1, "pop register ESP (word)"); i += 1;
    m[i] = entry(i, HandlerType::PopEsp, "pop_esp", 4, 1, "pop register ESP (dword)"); i += 1;

    // 60-71: ALU: add/nor/nand (osByte..osDWord × 3)
    let alu_ops = [(HandlerType::Add, "add"), (HandlerType::Nor, "nor"), (HandlerType::Nand, "nand")];
    let sizes = [1u8, 2, 4, 8];
    let mut si = 0;
    while si < 4 {
        let mut oi = 0;
        while oi < 3 {
            let (ht, sem) = alu_ops[oi];
            m[i] = entry(i, ht, sem, sizes[si], 0, "binary ALU operation");
            oi += 1;
            i += 1;
        }
        si += 1;
    }

    // 72-79: Shl/Shr (osByte..osDWord × 2)
    si = 0;
    while si < 4 {
        m[i] = entry(i, HandlerType::Shl, "shl", sizes[si], 0, "shift left"); si += 1; i += 1;
    }
    si = 0;
    while si < 4 {
        m[i] = entry(i, HandlerType::Shr, "shr", sizes[si], 0, "shift right"); si += 1; i += 1;
    }

    // 80-87: Rcl/Rcr (osByte..osDWord × 2)
    si = 0;
    while si < 4 {
        m[i] = entry(i, HandlerType::Rcl, "rcl", sizes[si], 0, "rotate through carry left"); si += 1; i += 1;
    }
    si = 0;
    while si < 4 {
        m[i] = entry(i, HandlerType::Rcr, "rcr", sizes[si], 0, "rotate through carry right"); si += 1; i += 1;
    }

    // 88-91: Shld/Shrd (osDWord..osDWord)
    m[i] = entry(i, HandlerType::Shld, "shld", 4, 0, "double shift left"); i += 1;
    m[i] = entry(i, HandlerType::Shld, "shld", 8, 0, "double shift left (qword)"); i += 1;
    m[i] = entry(i, HandlerType::Shrd, "shrd", 4, 0, "double shift right"); i += 1;
    m[i] = entry(i, HandlerType::Shrd, "shrd", 8, 0, "double shift right (qword)"); i += 1;

    // 92-99: Div/Idiv/Mul/Imul (osByte..osDWord)
    let size4 = [1u8, 2, 4, 8];
    si = 0;
    while si < 4 {
        m[i] = entry(i, HandlerType::Div, "div", size4[si], 0, "unsigned divide"); si += 1; i += 1;
    }
    si = 0;
    while si < 4 {
        m[i] = entry(i, HandlerType::Idiv, "idiv", size4[si], 0, "signed divide"); si += 1; i += 1;
    }
    si = 0;
    while si < 4 {
        m[i] = entry(i, HandlerType::Mul, "mul", size4[si], 0, "unsigned multiply"); si += 1; i += 1;
    }
    si = 0;
    while si < 4 {
        m[i] = entry(i, HandlerType::Imul, "imul", size4[si], 0, "signed multiply"); si += 1; i += 1;
    }

    // 108-140: FPU ops (33)
    let fpu_ops: &[(HandlerType, &str, u8)] = &[
        (HandlerType::Fild, "fild", 2), (HandlerType::Fild, "fild", 4), (HandlerType::Fild, "fild", 8),
        (HandlerType::Fld, "fld", 4), (HandlerType::Fld, "fld", 8), (HandlerType::Fld, "fld", 10),
        (HandlerType::Fadd, "fadd", 4), (HandlerType::Fadd, "fadd", 8),
        (HandlerType::Fsub, "fsub", 4), (HandlerType::Fsub, "fsub", 8),
        (HandlerType::Fsubr, "fsubr", 4), (HandlerType::Fsubr, "fsubr", 8),
        (HandlerType::Fstp, "fstp", 4), (HandlerType::Fstp, "fstp", 8), (HandlerType::Fstp, "fstp", 10),
        (HandlerType::Fst, "fst", 4), (HandlerType::Fst, "fst", 8),
        (HandlerType::Fist, "fist", 2), (HandlerType::Fist, "fist", 4),
        (HandlerType::Fistp, "fistp", 2), (HandlerType::Fistp, "fistp", 4), (HandlerType::Fistp, "fistp", 8),
        (HandlerType::Fisub, "fisub", 2), (HandlerType::Fisub, "fisub", 4),
        (HandlerType::Fdiv, "fdiv", 4), (HandlerType::Fdiv, "fdiv", 8),
        (HandlerType::Fmul, "fmul", 4), (HandlerType::Fmul, "fmul", 8),
        (HandlerType::Fcomp, "fcomp", 4), (HandlerType::Fcomp, "fcomp", 8),
        (HandlerType::Fstcw, "fstcw", 2),
        (HandlerType::Fldcw, "fldcw", 2),
        (HandlerType::Fstsw, "fstsw", 2),
    ];
    let mut fi = 0;
    while fi < fpu_ops.len() {
        let (ht, sem, sz) = fpu_ops[fi];
        m[i] = entry(i, ht, sem, sz, 0, "FPU operation");
        fi += 1;
        i += 1;
    }

    // 141-163: FPU misc (23)
    let fpu_misc: &[(HandlerType, &str)] = &[
        (HandlerType::Wait, "wait"), (HandlerType::Fchs, "fchs"),
        (HandlerType::Fsqrt, "fsqrt"), (HandlerType::F2xm1, "f2xm1"),
        (HandlerType::Fabs, "fabs"), (HandlerType::Fclex, "fclex"),
        (HandlerType::Fcos, "fcos"), (HandlerType::Fdecstp, "fdecstp"),
        (HandlerType::Fincstp, "fincstp"), (HandlerType::Finit, "finit"),
        (HandlerType::Fldln2, "fldln2"), (HandlerType::Fldz, "fldz"),
        (HandlerType::Fld1, "fld1"), (HandlerType::Fldpi, "fldpi"),
        (HandlerType::Fpatan, "fpatan"), (HandlerType::Fprem, "fprem"),
        (HandlerType::Fprem1, "fprem1"), (HandlerType::Fptan, "fptan"),
        (HandlerType::Frndint, "frndint"), (HandlerType::Fsin, "fsin"),
        (HandlerType::Ftst, "ftst"), (HandlerType::Fyl2x, "fyl2x"),
        (HandlerType::Fldlg2, "fldlg2"),
    ];
    let mut mi = 0;
    while mi < fpu_misc.len() {
        let (ht, sem) = fpu_misc[mi];
        m[i] = entry(i, ht, sem, 4, 0, "FPU misc operation");
        mi += 1;
        i += 1;
    }

    // 164-166: Ret/Iret/Ret(far)
    m[i] = entry(i, HandlerType::Ret, "ret", 4, 0, "return"); i += 1;
    m[i] = entry(i, HandlerType::Iret, "iret", 4, 0, "interrupt return"); i += 1;
    m[i] = entry(i, HandlerType::Ret, "ret_far", 4, 0, "far return"); i += 1;

    // Remaining slots: Unknown (will be filled from per-sample discovery)
    while i < 256 {
        match m[i].handler_type {
            HandlerType::Unknown => {
                m[i] = entry(i, HandlerType::Unknown, "unknown", 0, 0, "unregistered");
            }
            _ => {}
        }
        i += 1;
    }

    m
}

const fn entry(
    opcode: usize, handler_type: HandlerType, semantic: &'static str,
    data_size: u8, stack_effect: i8, description: &'static str,
) -> OpcodeEntry {
    OpcodeEntry { opcode: opcode as u8, handler_type, semantic, data_size, stack_effect, description }
}

const fn entry_push_mem(opcode: usize, _size: u8) -> OpcodeEntry {
    entry(opcode, HandlerType::PushMem, "push_mem", 4, 0, "push memory")
}

const fn entry_pop_mem(opcode: usize, _size: u8) -> OpcodeEntry {
    entry(opcode, HandlerType::PopMem, "pop_mem", 4, 0, "pop memory")
}

const fn entry_seg(opcode: usize, ht: HandlerType, sem: &'static str, _se: i8) -> OpcodeEntry {
    entry(opcode, ht, sem, 2, _se, "segment register")
}

const fn entry_dbg(opcode: usize, ht: HandlerType, sem: &'static str, _se: i8) -> OpcodeEntry {
    entry(opcode, ht, sem, 8, _se, "debug register")
}

const fn entry_ctrl(opcode: usize, ht: HandlerType, sem: &'static str, _se: i8) -> OpcodeEntry {
    entry(opcode, ht, sem, 8, _se, "control register")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_map_256() {
        let map = CanonicalOpcodeMap::entries();
        assert_eq!(map.len(), 256);
    }

    #[test]
    fn test_opcode_0_is_nop() {
        assert_eq!(CanonicalOpcodeMap::lookup(0).handler_type, HandlerType::Nop);
    }

    #[test]
    fn test_opcode_1_is_push_reg() {
        assert_eq!(CanonicalOpcodeMap::lookup(1).handler_type, HandlerType::PushReg);
    }

    #[test]
    fn test_opcode_4_is_pop_reg() {
        assert_eq!(CanonicalOpcodeMap::lookup(4).handler_type, HandlerType::PopReg);
    }

    #[test]
    fn test_opcode_7_is_push_byte() {
        assert_eq!(CanonicalOpcodeMap::lookup(7).handler_type, HandlerType::PushByte);
    }

    #[test]
    fn test_opcode_9_is_push_val() {
        assert_eq!(CanonicalOpcodeMap::lookup(9).handler_type, HandlerType::PushVal);
    }

    #[test]
    fn test_all_entries_have_unique_opcodes() {
        let map = CanonicalOpcodeMap::entries();
        let mut seen = [false; 256];
        for e in map.iter() {
            assert!(!seen[e.opcode as usize], "duplicate opcode {}", e.opcode);
            seen[e.opcode as usize] = true;
        }
    }

    #[test]
    fn test_lookup_is_consistent_with_entries() {
        let entries = CanonicalOpcodeMap::entries();
        for (idx, entry) in entries.iter().enumerate() {
            let lookup = CanonicalOpcodeMap::lookup(idx as u8);
            assert_eq!(lookup.handler_type, entry.handler_type);
        }
    }
}
