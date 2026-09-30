//! Bytecode value chains: ordered ALU transforms over a fetch byte.
//!
//! Derived from observation, not from any protector source: the miner
//! (`frontend::cryptor_miner`) recovers chains like
//! `Neg -> Not -> Neg -> Ror(1)` live from executed fetch sites, and
//! this module is the executable form of exactly those chains —
//! `encrypt` replays a chain, `decrypt` replays its inverse.
//! Chain alphabet matches x86 byte-ALU semantics (wrapping add/sub,
//! xor, rotates, not/neg, bswap, inc/dec), verified against traced
//! fetch bytes (`mine-hits` cross-checks).

use serde::{Deserialize, Serialize};

/// One chain operation. Semantics follow the x86 instruction of the
/// same name at the chain's operand width.
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

/// Operand width a chain operates at (3.x fetch chains are bytes;
/// wider widths exist in other VM shapes).
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

/// One step of a chain: operation plus operand.
/// Rotates take a rotation amount (byte range, applied mod width);
/// Add/Sub/Xor take an immediate of operand width; the rest ignore it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ValueCommand {
    pub op: CryptOp,
    pub size: CryptSize,
    pub value: u64,
}

impl ValueCommand {
    /// Decryption runs every step's inverse in reverse order.
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
        let imm = self.value & mask;
        v &= mask;
        let res = match op {
            CryptOp::Add | CryptOp::Inc => {
                v.wrapping_add(if op == CryptOp::Inc { 1 } else { imm }) & mask
            }
            CryptOp::Sub | CryptOp::Dec => {
                v.wrapping_sub(if op == CryptOp::Dec { 1 } else { imm }) & mask
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
        res & mask
    }

    pub fn encrypt(&self, v: u64) -> u64 {
        self.apply(v, false)
    }
    pub fn decrypt(&self, v: u64) -> u64 {
        self.apply(v, true)
    }
}

/// An ordered chain; `encrypt` replays forward, `decrypt` replays the
/// inverse chain backward.
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
        // Rotation applies at the operand width; only the *amount* is a
        // byte (x86 semantics: amount mod width).
        let v = match op {
            CryptOp::Rol | CryptOp::Ror => value & 0xFF,
            CryptOp::Add | CryptOp::Sub | CryptOp::Xor => value & self.size.mask(),
            _ => 0,
        };
        self.cmds.push(ValueCommand { op, size: self.size, value: v });
    }
    pub fn encrypt(&self, mut v: u64) -> u64 {
        for c in &self.cmds {
            v = c.apply(v, false);
        }
        v & self.size.mask()
    }
    pub fn decrypt(&self, mut v: u64) -> u64 {
        for c in self.cmds.iter().rev() {
            v = c.apply(v, true);
        }
        v & self.size.mask()
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
        // Mined live: Inc, Xor(6), Rol(1), Inc on the key-mixed byte.
        // raw=0x3e key=0xf6 => byte ^ key = 0xc8
        let mut cr = ValueCryptor::new(CryptSize::Byte);
        cr.add(CryptOp::Inc, 0);
        cr.add(CryptOp::Xor, 6);
        cr.add(CryptOp::Rol, 1);
        cr.add(CryptOp::Inc, 0);
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

    #[test]
    fn rol_ror_wide_widths() {
        // Rotation applies at operand width (amount stays a byte).
        let mut cr32 = ValueCryptor::new(CryptSize::DWord);
        cr32.add(CryptOp::Rol, 8);
        assert_eq!(cr32.cmds[0].apply(0x11223344, false), 0x22334411);
        let mut cr64 = ValueCryptor::new(CryptSize::QWord);
        cr64.add(CryptOp::Ror, 8);
        assert_eq!(cr64.cmds[0].apply(0x1122334455667788, false), 0x8811223344556677);
        let mut cr16 = ValueCryptor::new(CryptSize::Word);
        cr16.add(CryptOp::Rol, 4);
        assert_eq!(cr16.cmds[0].apply(0x1234, false), 0x2341);
        // roundtrips at every width (byte-facing entry points)
        for (sz, v) in [(CryptSize::Byte, 0xabu64),
                        (CryptSize::Word, 0xabcd),
                        (CryptSize::DWord, 0xabcdef01),
                        (CryptSize::QWord, 0xabcdef0123456789)] {
            let mut c = ValueCryptor::new(sz);
            c.add(CryptOp::Rol, 3);
            c.add(CryptOp::Xor, 0x5a);
            let e = c.cmds.iter().fold(v & sz.mask(), |a, x| x.apply(a, false));
            let d = c.cmds.iter().rev().fold(e, |a, x| x.apply(a, true));
            assert_eq!(d & sz.mask(), v & sz.mask());
        }
    }
}
