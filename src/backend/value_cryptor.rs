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

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// One chain operation. Semantics follow the x86 instruction of the
/// same name at the chain's operand width. And is one-way for
/// key-mixes (e.g. NOR schedules `~B0 & ~B1` need both bytes to
/// invert); chains containing it report shape, not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptOp {
    Add,
    Sub,
    Xor,
    And,
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
    /// And has no inverse (one-way mix); decrypting an And-chain
    /// is an error the caller must handle (needs the co-byte).
    fn inverse(&self) -> Option<CryptOp> {
        match self.op {
            CryptOp::Add => Some(CryptOp::Sub),
            CryptOp::Sub => Some(CryptOp::Add),
            CryptOp::Inc => Some(CryptOp::Dec),
            CryptOp::Dec => Some(CryptOp::Inc),
            CryptOp::Rol => Some(CryptOp::Ror),
            CryptOp::Ror => Some(CryptOp::Rol),
            CryptOp::And => None,
            o => Some(o),
        }
    }

    fn apply(&self, mut v: u64, decrypt: bool) -> Result<u64> {
        let op = if decrypt {
            self.inverse().ok_or_else(|| {
                anyhow::anyhow!("And-chain has no inverse (needs co-byte)")
            })?
        } else {
            self.op
        };
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
            CryptOp::And => (v & imm) & mask,
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
        Ok(res & mask)
    }

    pub fn encrypt(&self, v: u64) -> u64 {
        // Forward application is infallible (inverse() only runs on decrypt).
        self.apply(v, false).unwrap_or(v & self.size.mask())
    }
    pub fn decrypt(&self, v: u64) -> Result<u64> {
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
            CryptOp::Add | CryptOp::Sub | CryptOp::Xor | CryptOp::And => {
                value & self.size.mask()
            }
            _ => 0,
        };
        self.cmds.push(ValueCommand { op, size: self.size, value: v });
    }
    pub fn encrypt(&self, mut v: u64) -> u64 {
        for c in &self.cmds {
            v = c.apply(v, false).unwrap_or(v & self.size.mask());
        }
        v & self.size.mask()
    }
    /// Inverse chain; errors on one-way mixes (And needs the co-byte).
    pub fn decrypt(&self, mut v: u64) -> Result<u64> {
        for c in self.cmds.iter().rev() {
            v = c.apply(v, true)?;
        }
        Ok(v & self.size.mask())
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
            let d = cr.decrypt(e).unwrap();
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
        assert_eq!(cr.decrypt(enc).unwrap(), x);
    }

    #[test]
    fn bswap_vectors() {
        let mut cr = ValueCryptor::new(CryptSize::DWord);
        cr.add(CryptOp::Bswap, 0);
        assert_eq!(cr.encrypt(0x11223344), 0x44332211);
        assert_eq!(cr.decrypt(0x44332211).unwrap(), 0x11223344);
    }

    #[test]
    fn rol_ror_wide_widths() {
        // Rotation applies at operand width (amount stays a byte).
        let mut cr32 = ValueCryptor::new(CryptSize::DWord);
        cr32.add(CryptOp::Rol, 8);
        assert_eq!(cr32.cmds[0].apply(0x11223344, false).unwrap(), 0x22334411);
        let mut cr64 = ValueCryptor::new(CryptSize::QWord);
        cr64.add(CryptOp::Ror, 8);
        assert_eq!(cr64.cmds[0].apply(0x1122334455667788, false).unwrap(), 0x8811223344556677);
        let mut cr16 = ValueCryptor::new(CryptSize::Word);
        cr16.add(CryptOp::Rol, 4);
        assert_eq!(cr16.cmds[0].apply(0x1234, false).unwrap(), 0x2341);
        // roundtrips at every width (byte-facing entry points)
        for (sz, v) in [(CryptSize::Byte, 0xabu64),
                        (CryptSize::Word, 0xabcd),
                        (CryptSize::DWord, 0xabcdef01),
                        (CryptSize::QWord, 0xabcdef0123456789)] {
            let mut c = ValueCryptor::new(sz);
            c.add(CryptOp::Rol, 3);
            c.add(CryptOp::Xor, 0x5a);
            let e = c.cmds.iter().fold(v & sz.mask(), |a, x| x.apply(a, false).unwrap());
            let d = c.cmds.iter().rev().try_fold(e, |a, x| x.apply(a, true)).unwrap();
            assert_eq!(d & sz.mask(), v & sz.mask());
        }
    }

    #[test]
    fn and_mix_shape() {
        // NOR schedule shape: Not, Not, And — forward works, inverse
        // honestly errors (needs the co-byte).
        let mut cr = ValueCryptor::new(CryptSize::Byte);
        cr.add(CryptOp::Not, 0);
        cr.add(CryptOp::Not, 0);
        cr.add(CryptOp::And, 0xFF);
        assert_eq!(cr.encrypt(0x3c), 0x3c & 0xFF);
        assert!(cr.decrypt(0x3c).is_err());
    }
}
