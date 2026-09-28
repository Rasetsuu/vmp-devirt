//! ValueCryptor port from VMP 3.5.1 leak `core/processors.cc`
//!
//! `ValueCommand` = one transform (ADD/SUB/XOR/ROL/ROR/NOT/NEG/BSWAP/INC/DEC)
//! `ValueCryptor` = ordered chain; `Encrypt` applies forward, `Decrypt` applies
//! inverse in reverse order (ADD<->SUB, INC<->DEC, ROL<->ROR).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptOp {
    Add,
    Sub,
    Xor,
    Inc,
    Dec,
    Bswap,
    Rol,
    Ror,
    Not,
    Neg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptSize {
    Byte,
    Word,
    DWord,
    QWord,
}

impl CryptSize {
    fn mask(self) -> u64 {
        match self {
            CryptSize::Byte => 0xFF,
            CryptSize::Word => 0xFFFF,
            CryptSize::DWord => 0xFFFF_FFFF,
            CryptSize::QWord => 0xFFFF_FFFF_FFFF_FFFF,
        }
    }
    fn bits(self) -> u32 {
        match self {
            CryptSize::Byte => 8,
            CryptSize::Word => 16,
            CryptSize::DWord => 32,
            CryptSize::QWord => 64,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ValueCommand {
    pub op: CryptOp,
    pub size: CryptSize,
    /// For Rol/Ror this is rotate amount (byte), for Add/Sub/Xor the immediate.
    /// Inc/Dec/Not/Neg/Bswap ignore it (0).
    pub value: u64,
}

impl ValueCommand {
    /// Inverse op used during Decrypt (leak `ValueCommand::type(true)`).
    fn inverse(&self) -> CryptOp {
        match self.op {
            CryptOp::Add => CryptOp::Sub,
            CryptOp::Sub => CryptOp::Add,
            CryptOp::Inc => CryptOp::Dec,
            CryptOp::Dec => CryptOp::Inc,
            CryptOp::Rol => CryptOp::Ror,
            CryptOp::Ror => CryptOp::Rol,
            o => o,
        }
    }

    fn apply(&self, mut v: u64, decrypt: bool) -> u64 {
        let op = if decrypt { self.inverse() } else { self.op };
        let mask = self.size.mask();
        let bits = self.size.bits();
        // keep only size-relevant bits for the value operand where needed
        let imm = self.value & mask;
        v &= mask;
        let res = match op {
            CryptOp::Add | CryptOp::Inc => {
                let add = if op == CryptOp::Inc { 1 } else { imm };
                v.wrapping_add(add) & mask
            }
            CryptOp::Sub | CryptOp::Dec => {
                let sub = if op == CryptOp::Dec { 1 } else { imm };
                v.wrapping_sub(sub) & mask
            }
            CryptOp::Xor => (v ^ imm) & mask,
            CryptOp::Not => (!v) & mask,
            CryptOp::Neg => (0u64.wrapping_sub(v)) & mask,
            CryptOp::Bswap => match self.size {
                CryptSize::Word => (v as u16).swap_bytes() as u64,
                CryptSize::DWord => (v as u32).swap_bytes() as u64,
                CryptSize::QWord => v.swap_bytes(),
                CryptSize::Byte => v & mask,
            },
            CryptOp::Rol => {
                let r = (imm as u32) % bits;
                if r == 0 { v } else { ((v << r) | (v >> (bits - r))) & mask }
            }
            CryptOp::Ror => {
                let r = (imm as u32) % bits;
                if r == 0 { v } else { ((v >> r) | (v << (bits - r))) & mask }
            }
        };
        // preserve upper bits of original for QWord? For smaller sizes we already masked.
        res & mask
    }

    pub fn encrypt(&self, v: u64) -> u64 {
        self.apply(v, false)
    }
    pub fn decrypt(&self, v: u64) -> u64 {
        self.apply(v, true)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValueCryptor {
    pub size: CryptSize,
    pub cmds: Vec<ValueCommand>,
}

impl Default for CryptSize {
    fn default() -> Self { CryptSize::Byte }
}

impl ValueCryptor {
    pub fn new(size: CryptSize) -> Self {
        Self { size, cmds: Vec::new() }
    }
    pub fn add(&mut self, op: CryptOp, value: u64) {
        // Keep size of command consistent with cryptor size, but
        // Rol/Ror immediate is always byte-sized in the leak.
        let sz = match op {
            CryptOp::Rol | CryptOp::Ror => CryptSize::Byte,
            _ => self.size,
        };
        // Store value truncated to size (except Rol/Ror where value is rotate amount)
        let v = match op {
            CryptOp::Rol | CryptOp::Ror => value & 0xFF,
            CryptOp::Add | CryptOp::Sub | CryptOp::Xor => value & self.size.mask(),
            _ => 0,
        };
        self.cmds.push(ValueCommand { op, size: sz, value: v });
    }

    pub fn encrypt(&self, mut v: u64) -> u64 {
        for c in &self.cmds {
            v = c.encrypt(v);
            // keep truncated to cryptor size after each step (leak does)
            v &= self.size.mask();
        }
        v
    }
    pub fn decrypt(&self, mut v: u64) -> u64 {
        for c in self.cmds.iter().rev() {
            v = c.decrypt(v);
            v &= self.size.mask();
        }
        v
    }

    /// Build from the per-site chain we observed via Unicorn.
    /// Example: `xor al,bpl; add al,0xa1; neg al; inc al; xor al,1` -> sequence
    /// of ValueCommands that reproduces the same transform.
    pub fn from_ops(size: CryptSize, ops: &[(CryptOp, u64)]) -> Self {
        let mut c = Self::new(size);
        for (op, v) in ops {
            c.add(*op, *v);
        }
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_byte() {
        let mut cr = ValueCryptor::new(CryptSize::Byte);
        cr.add(CryptOp::Xor, 0x42);
        cr.add(CryptOp::Rol, 1);
        cr.add(CryptOp::Add, 0x0f);
        for b in 0..=255u64 {
            let e = cr.encrypt(b);
            let d = cr.decrypt(e);
            assert_eq!(d, b, "b={b:#x} e={e:#x} d={d:#x}");
        }
    }

    #[test]
    fn rbx_family_chain() {
        // Verified 0x1401989e9: xor cl,r11b; inc cl; xor cl,6; rol cl,1; inc cl
        // as ValueCryptor Byte: Xor(key), Inc, Xor(6), Rol(1), Inc
        // We test the fixed part without key (key is separate xor)
        let mut cr = ValueCryptor::new(CryptSize::Byte);
        cr.add(CryptOp::Inc, 0);
        cr.add(CryptOp::Xor, 6);
        cr.add(CryptOp::Rol, 1);
        cr.add(CryptOp::Inc, 0);
        // raw=0x3e key=0xf6 => byte ^ key = 0xc8
        let raw = 0x3eu64;
        let key = 0xf6u64;
        let x = raw ^ key;
        let enc = cr.encrypt(x);
        assert_eq!(enc, 0xa0);
        assert_eq!(cr.decrypt(enc), x);
    }

    #[test]
    fn bswap_vectors() {
        let mut cr = ValueCryptor::new(CryptSize::DWord);
        cr.add(CryptOp::Bswap, 0);
        assert_eq!(cr.encrypt(0x11223344), 0x44332211);
        assert_eq!(cr.decrypt(0x44332211), 0x11223344);
    }
}
